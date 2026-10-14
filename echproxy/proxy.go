package echproxy

import (
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

// Debug 控制是否输出逐请求的详细调试日志（通过 CLI -v 开启）。
var Debug bool

func debugLogf(format string, args ...any) {
	if Debug {
		log.Printf(format, args...)
	}
}

const writeTimeout = 30 * time.Minute

// roundTripFn 供单元测试注入自定义传输层使用，生产环境默认调用 cloudflare_ech.RoundTrip。
var roundTripFn = cloudflare_ech.RoundTrip

// ModeName 返回传输模式的可读名称。
func ModeName(mode string) string {
	switch mode {
	case "sni":
		return "SNI Camouflage"
	case "direct":
		return "Direct"
	default:
		return "Cloudflare ECH"
	}
}

// ProxyHandler 核心反向代理处理器，统一承载：
//   - 功能一（8443 门户反代模式）：将 *.l.moonchan.xyz 映射至真实上游并执行域名重写、SW 注入与 Cookie 转换
//   - 功能二（443 本地透明反代模式）：将原域名（如 pixiv.net / *.pixiv.net）直接通过 ECH/SNI 隧道转发
func ProxyHandler(upstreams config.UpstreamMap, blockedHosts []string) gin.HandlerFunc {
	blocked := append([]string(nil), blockedHosts...)

	return func(c *gin.Context) {
		start := time.Now()
		clientIP := c.ClientIP()
		host := stripPort(c.Request.Host)

		// 1. 匹配上游路由规则（精确匹配或泛子域名匹配）
		uc, ok := config.Resolve(upstreams, host)
		if !ok {
			log.Printf("[%s] Upstream config not found: %s", clientIP, host)
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusBadGateway, "no upstream for host: %s", host)
			return
		}

		ucForRewrite := uc
		if ucForRewrite.Wildcard == nil {
			ucForRewrite.Wildcard = config.InheritWildcard(upstreams, host)
		}
		rewriter := rewrite.BuildEntryRewriter(ucForRewrite, blocked)

		// 2. 构造发往真实上游的 HTTP 请求
		outReq, err := buildUpstreamRequest(c, uc)
		if err != nil {
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		// 3. 通过 ECH / SNI / Direct 隧道发送请求
		resp, err := roundTripFn(outReq, uc.Mode, uc.IPMode)
		if err != nil {
			log.Printf("[%s] Upstream request failed (%s): %v", clientIP, uc.Host, err)
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer resp.Body.Close()

		cookie.DefaultJar.SaveResponseCookies(uc.Host, resp)
		debugLogf("[%s] %s %s -> %s (%s, %v)", clientIP, c.Request.Method, c.Request.URL.Path, uc.Host, resp.Status, time.Since(start))

		// 4. 处理响应头（剔除逐跳头、改写 Set-Cookie Domain、重写 Location 重定向、注入 CORS）
		port := extractPort(c.Request.Host)
		cookieDomain := uc.CookieDomain
		if cookieDomain == "" {
			cookieDomain = host
		}
		prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, rewriter, port)

		// 防止上游 Canonical 重定向（如 iwara.tv -> www.iwara.tv）被 rewriter 改写回自身导致 301 死循环
		if resp.StatusCode/100 == 3 {
			if loc := c.Writer.Header().Get("Location"); loc != "" && isSelfRedirect(loc, c.Request) {
				if nextResp, ok := followSelfRedirect(c, outReq, resp, uc); ok {
					resp.Body.Close()
					resp = nextResp
					defer resp.Body.Close()
					cookie.DefaultJar.SaveResponseCookies(resp.Request.Host, resp)
					clearHeaders(c.Writer.Header())
					prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, rewriter, port)
				}
			}
		}

		// 5. 若开启了 sw_inject 且请求 /sw.js（而上游未返回 JS），则自动返回生成的 Service Worker 脚本
		if uc.SWInject && c.Request.URL.Path == "/sw.js" && !rewrite.IsJavascriptResponse(resp) {
			c.Writer.Header().Del("Content-Length")
			c.Writer.Header().Set("Content-Type", "application/javascript")
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte(rewrite.GenerateServiceWorkerJS(upstreams, indexHost, port, blocked)))
			return
		}

		// 6. 写回响应状态码并传输/重写响应体
		c.Status(resp.StatusCode)
		sendResponseBody(c, uc, resp, rewriter, port)
	}
}

func buildUpstreamRequest(c *gin.Context, uc config.UpstreamConfig) (*http.Request, error) {
	reqURI := c.Request.RequestURI
	if reqURI == "" {
		reqURI = c.Request.URL.RequestURI()
	} else if strings.HasPrefix(reqURI, "http://") || strings.HasPrefix(reqURI, "https://") {
		if u, err := url.ParseRequestURI(reqURI); err == nil {
			reqURI = u.RequestURI()
		}
	}
	if !strings.HasPrefix(reqURI, "/") {
		reqURI = "/" + reqURI
	}

	outReq, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, "https://"+uc.Host+reqURI, c.Request.Body)
	if err != nil {
		return nil, err
	}

	cookie.DefaultJar.SaveClientCookies(uc.Host, c.Request)
	rewrite.CopyHeaders(outReq.Header, c.Request.Header)

	if _, ok := uc.Headers["X-Forwarded-For"]; !ok {
		outReq.Header.Del("X-Forwarded-For")
	}
	if _, ok := uc.Headers["X-Forwarded-Proto"]; !ok {
		outReq.Header.Del("X-Forwarded-Proto")
	}
	if uc.Referer != "" {
		outReq.Header.Set("Referer", uc.Referer)
	}
	rewrite.ApplyHeaderRules(outReq.Header, uc.Headers, true, c.Request)

	outReq.Host = uc.Host
	outReq.ContentLength = c.Request.ContentLength

	fixedCookie := cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile)
	if fixedCookie != "" {
		cookie.DefaultJar.Seed(uc.Host, fixedCookie)
	}
	cookie.DefaultJar.ApplyToRequest(uc.Host, outReq, fixedCookie)
	return outReq, nil
}

func prepareResponseHeaders(dst, src http.Header, uc config.UpstreamConfig, cookieDomain string, req *http.Request, rewriter func([]byte, string) []byte, port string) {
	rewrite.CopyHeaders(dst, src)
	cookie.RewriteSetCookieHeaders(dst, cookieDomain, req.TLS == nil)
	rewrite.ApplyHeaderRules(dst, uc.ResponseHeaders, false, nil)
	rewrite.RewriteRedirectHeaders(dst, rewriter, port)
	rewrite.ApplyCORSHeaders(dst, req)
}

func isSelfRedirect(rewrittenLoc string, clientReq *http.Request) bool {
	u, err := url.Parse(rewrittenLoc)
	if err != nil {
		return false
	}
	reqPath := clientReq.URL.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}
	locPath := u.RequestURI()
	if locPath == "" {
		locPath = "/"
	}
	return (u.Host == "" || strings.EqualFold(u.Host, clientReq.Host)) && locPath == reqPath
}

func followSelfRedirect(c *gin.Context, outReq *http.Request, resp *http.Response, uc config.UpstreamConfig) (*http.Response, bool) {
	rawTarget, err := outReq.URL.Parse(resp.Header.Get("Location"))
	if err != nil || rawTarget.Host == "" {
		return nil, false
	}
	if rawTarget.Scheme == "http" {
		rawTarget.Scheme = "https"
	}
	nextReq, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, rawTarget.String(), nil)
	if err != nil {
		return nil, false
	}
	rewrite.CopyHeaders(nextReq.Header, outReq.Header)
	nextReq.Host = rawTarget.Host
	cookie.DefaultJar.ApplyToRequest(rawTarget.Host, nextReq, cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile))
	nextResp, err := roundTripFn(nextReq, uc.Mode, uc.IPMode)
	if err != nil {
		return nil, false
	}
	nextResp.Request = nextReq
	return nextResp, true
}

func clearHeaders(h http.Header) {
	for k := range h {
		delete(h, k)
	}
}

func sendResponseBody(c *gin.Context, uc config.UpstreamConfig, resp *http.Response, rewriter func([]byte, string) []byte, port string) {
	rc := http.NewResponseController(c.Writer)

	// 文本类且不超过 8MB：解压 -> 重写域名与内容 -> 注入 SW -> 重新压缩并发送
	if rewriter != nil && rewrite.IsTextContent(resp.Header.Get("Content-Type")) &&
		(resp.ContentLength <= 0 || resp.ContentLength <= rewrite.MaxRewriteSize) {

		body, err := io.ReadAll(io.LimitReader(resp.Body, rewrite.MaxRewriteSize+1))
		if err != nil || len(body) > rewrite.MaxRewriteSize {
			if len(body) > 0 {
				_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
				_, _ = c.Writer.Write(body)
			}
			return
		}

		origEnc := resp.Header.Get("Content-Encoding")
		plain, derr := rewrite.DecompressBody(body, origEnc)
		if derr != nil {
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = c.Writer.Write(body)
			return
		}

		plain = rewriter(plain, port)

		if uc.SWInject && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
			!bytes.Contains(plain, []byte("serviceWorker")) {
			reg := []byte(`<script>navigator.serviceWorker.register('/sw.js').catch(function(){})</script>`)
			if idx := bytes.Index(plain, []byte("</head>")); idx >= 0 {
				plain = append(plain[:idx], append(reg, plain[idx:]...)...)
			} else {
				plain = append(plain, reg...)
			}
		}

		c.Writer.Header().Del("Content-Encoding")
		if compressed, enc := rewrite.CompressBody(plain, origEnc, c.Request.Header.Get("Accept-Encoding")); enc != "" {
			plain = compressed
			c.Writer.Header().Set("Content-Encoding", enc)
		}
		c.Writer.Header().Set("Content-Length", strconv.Itoa(len(plain)))
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = c.Writer.Write(plain)
		return
	}

	// 二进制流或大文件（图片、视频等）：32KB 分块直接流式转发
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, werr := c.Writer.Write(buf[:n]); werr != nil {
				break
			}
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
}

func extractPort(hostport string) string {
	if _, p, err := net.SplitHostPort(hostport); err == nil {
		return p
	}
	return ""
}
