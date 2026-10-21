package echproxy

import (
	"bytes"
	"errors"
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
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
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

const (
	writeTimeout        = 30 * time.Minute
	maxSelfRedirectHops = 3
	maxBufferedReqBody  = 1 << 20 // 1 MB 请求体缓冲上限（供明文 HTTP 自动升降级重试使用）

	// forceCertQueryParam 是证书警告页「强行访问」按钮的覆盖参数名。
	// 命中有效一次性 token 时跳过上游证书校验继续连接（用户在看到过期/不一致警告后明确选择继续）。
	forceCertQueryParam = "__ech_proxy_force_cert__"
)

// roundTripFn 供单元测试注入自定义传输层使用，生产环境默认调用 cloudflare_ech.RoundTrip。
var roundTripFn = cloudflare_ech.RoundTrip

// ModeName 返回传输模式的可读名称。
func ModeName(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "sni":
		return "SNI Camouflage (DoH + Fake SNI + Cert Check)"
	case "fragment", "bypass", "gfw":
		return "GFW Bypass (DoH + TLS ClientHello Fragment + Cert Check)"
	case "direct":
		return "Direct (TLS Cert Check)"
	case "auto":
		return "Auto (DoH + SNI / ECH / Fragment + Cert Check)"
	default:
		return "Cloudflare ECH (DoH + ECH + Cert Check)"
	}
}

// ProxyHandler 核心反向代理处理器（无鉴权包装，保持向后兼容）。
func ProxyHandler(upstreams config.UpstreamMap, blockedHosts []string) gin.HandlerFunc {
	return ProxyHandlerWithOptions(upstreams, blockedHosts, nil, nil)
}

// ProxyHandlerWithAuth 核心反向代理处理器（带鉴权，保持向后兼容）。
func ProxyHandlerWithAuth(upstreams config.UpstreamMap, blockedHosts []string, auth *AuthConfig) gin.HandlerFunc {
	return ProxyHandlerWithOptions(upstreams, blockedHosts, auth, nil)
}

// ProxyHandlerWithOptions 核心反向代理处理器，统一承载：
//   - PAC 白名单劫持（同时支持 HTTPS CONNECT MITM 与明文 HTTP 正向代理）；
//   - 三种上游请求方式（1. DoH + SNI 伪装，2. DoH + ECH，3. DoH + TLS 分片绕过 GFW），以及对纯 HTTP 站点的自动回退；
//   - 上游证书核对（比较 truedomain.com 与服务端回传证书是否一致、是否过期，异常时提示并提供「强行访问」按钮）；
//   - 远程广告处理（拦截并删除源站广告 [--skip-ad-block 可跳过]，插入 https://4545810.xyz/ads.js 广告商 <script> 标签 [--skip-ad-script 可跳过]）。
func ProxyHandlerWithOptions(upstreams config.UpstreamMap, blockedHosts []string, auth *AuthConfig, adScript *rewrite.AdScriptManager) gin.HandlerFunc {
	blocked := append([]string(nil), blockedHosts...)

	return func(c *gin.Context) {
		defer logger.RecoverAndLog("ProxyHandler", func(r any, _ []byte) {
			if !c.Writer.Written() {
				c.String(http.StatusInternalServerError, "internal proxy error")
			}
		})

		start := time.Now()
		clientIP := c.ClientIP()
		host := stripPort(c.Request.Host)
		reqPort := extractPort(c.Request.Host)

		// 若启用了认证，对反代流量执行鉴权校验
		if auth != nil && auth.Enabled() {
			ok, err := auth.Check(c.Request, clientIP)
			if errors.Is(err, ErrAuthRateLimited) {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
				c.String(http.StatusTooManyRequests, "too many authentication failures")
				return
			}
			if !ok {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
				c.Header("WWW-Authenticate", `Basic realm="ech-proxy"`)
				c.String(http.StatusUnauthorized, "authentication required")
				return
			}
		}

		// 1. 匹配上游路由规则（精确匹配、泛子域名匹配或非门户原域名自动透传）
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
		activeBlocked := blocked
		if adScript != nil && adScript.SkipAdBlock() {
			activeBlocked = nil
		}
		rewriter := rewrite.BuildEntryRewriterForHost(host, ucForRewrite, activeBlocked)

		// 判断客户端请求是否为明文 HTTP 正向代理请求（如 GET http://site.com/path HTTP/1.1）
		isPlainClientHTTP := c.Request.TLS == nil && !config.IsPortalDomain(host) &&
			(strings.HasPrefix(strings.ToLower(c.Request.RequestURI), "http://") || strings.EqualFold(c.Request.URL.Scheme, "http"))
		isExplicitCustomHTTPPort := isPlainClientHTTP && reqPort != "" && reqPort != "80" && reqPort != "443" && reqPort != "8443"

		// 为支持明文 HTTP 请求在 HTTPS 尝试失败（如目标仅开放 80 端口）时无缝回退到 HTTP，缓冲小体积请求体
		var bodySnapshot []byte
		canReplayBody := c.Request.Body == nil || c.Request.Body == http.NoBody
		if !canReplayBody && isPlainClientHTTP && c.Request.ContentLength >= 0 && c.Request.ContentLength <= maxBufferedReqBody {
			if b, berr := io.ReadAll(io.LimitReader(c.Request.Body, maxBufferedReqBody+1)); berr == nil && len(b) <= maxBufferedReqBody {
				bodySnapshot = b
				canReplayBody = true
				c.Request.Body = io.NopCloser(bytes.NewReader(bodySnapshot))
			}
		}

		// 2. 构造发往真实上游的请求：
		//    - 若是自定义非 80/443 的明文 HTTP 端口（如 http://example.com:8080/），直接走明文 HTTP；
		//    - 否则优先构造 HTTPS 请求走三种绕过方式（1. DoH+SNI，2. DoH+ECH，3. DoH+TLS分片）。
		scheme := "https"
		targetHostPort := uc.Host
		if isExplicitCustomHTTPPort {
			scheme = "http"
			targetHostPort = net.JoinHostPort(uc.Host, reqPort)
		}
		outReq, err := buildUpstreamRequestWithScheme(c, uc, scheme, targetHostPort)
		if err != nil {
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		// 3. 发送上游请求并核对证书；若客户端原本发起的是明文 http:// 请求且目标站点不支持 HTTPS（非证书错误），自动回退明文 HTTP
		resp, err := roundTripFn(outReq, uc.Mode, uc.IPMode)
		if err != nil && isPlainClientHTTP && scheme == "https" && !cloudflare_ech.IsCertError(err) && canReplayBody {
			if bodySnapshot != nil {
				c.Request.Body = io.NopCloser(bytes.NewReader(bodySnapshot))
			} else {
				c.Request.Body = http.NoBody
			}
			if httpReq, herr := buildUpstreamRequestWithScheme(c, uc, "http", uc.Host); herr == nil {
				if httpResp, herr2 := roundTripFn(httpReq, uc.Mode, uc.IPMode); herr2 == nil {
					resp = httpResp
					err = nil
					outReq = httpReq
				}
			}
		}

		if err != nil {
			// 上游证书校验失败（过期 / 域名不一致 / 不可信）：渲染区分类型的中文警告页（含「强行访问」按钮）
			if kind, certHost, detail, ok := cloudflare_ech.ClassifyCertError(err); ok {
				serveCertWarningPage(c, err, kind, certHost, detail, host, uc.Host)
				return
			}
			log.Printf("[%s] Upstream request failed (%s): %v", clientIP, uc.Host, err)
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()

		cookie.DefaultJar.SaveResponseCookies(uc.Host, resp)
		debugLogf("[%s] %s %s -> %s (%s, %v)", clientIP, c.Request.Method, c.Request.URL.Path, uc.Host, resp.Status, time.Since(start))

		// 4. 处理响应头（剔除逐跳头、改写 Set-Cookie Domain、重写 Location 重定向、注入 CORS）
		port := reqPort
		cookieDomain := uc.CookieDomain
		if cookieDomain == "" {
			cookieDomain = host
		}
		prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, rewriter, port)

		// 防止上游 Canonical 重定向（如 http -> https 或 iwara.tv -> www.iwara.tv）导致死循环（支持多跳防护）
		for hop := 0; hop < maxSelfRedirectHops && resp.StatusCode/100 == 3; hop++ {
			loc := c.Writer.Header().Get("Location")
			if loc == "" || !isSelfRedirect(loc, c.Request) {
				break
			}
			nextResp, ok := followSelfRedirect(c, outReq, resp, uc)
			if !ok {
				break
			}
			_ = resp.Body.Close()
			resp = nextResp
			outReq = nextResp.Request
			cookie.DefaultJar.SaveResponseCookies(resp.Request.Host, resp)
			clearHeaders(c.Writer.Header())
			prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, rewriter, port)
		}

		// 5. 若处于门户模式且开启了 sw_inject、请求 /sw.js（而上游未返回 JS），则自动返回生成的 Service Worker 脚本
		if uc.SWInject && config.IsPortalDomain(host) && c.Request.URL.Path == "/sw.js" && !rewrite.IsJavascriptResponse(resp) {
			c.Writer.Header().Del("Content-Length")
			c.Writer.Header().Set("Content-Type", "application/javascript")
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte(rewrite.GenerateServiceWorkerJS(upstreams, indexHost, port, activeBlocked)))
			return
		}

		// 若对 HTML 页面启用了广告脚本注入或 ServiceWorker，移除上游严格的 CSP 头以确保插入的 <script> 广告商代码可执行
		if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
			((adScript != nil && (adScript.Enabled() || !adScript.SkipAdBlock()) && (adScript.IsWhitelisted(host, uc.Host) || adScript.AllMode())) || uc.SWInject) {
			c.Writer.Header().Del("Content-Security-Policy")
			c.Writer.Header().Del("Content-Security-Policy-Report-Only")
		}

		// 6. 写回响应状态码并传输/重写响应体（删除源站广告 + 插入广告商 <script> 标签）
		c.Status(resp.StatusCode)
		sendResponseBody(c, host, uc, resp, rewriter, adScript, port)
	}
}

func buildUpstreamRequest(c *gin.Context, uc config.UpstreamConfig) (*http.Request, error) {
	return buildUpstreamRequestWithScheme(c, uc, "https", uc.Host)
}

func buildUpstreamRequestWithScheme(c *gin.Context, uc config.UpstreamConfig, scheme, targetHostPort string) (*http.Request, error) {
	if scheme == "" {
		scheme = "https"
	}
	if targetHostPort == "" {
		targetHostPort = uc.Host
	}
	reqURI := c.Request.RequestURI
	if reqURI == "" {
		reqURI = c.Request.URL.RequestURI()
	} else if strings.HasPrefix(strings.ToLower(reqURI), "http://") || strings.HasPrefix(strings.ToLower(reqURI), "https://") {
		if u, err := url.ParseRequestURI(reqURI); err == nil {
			reqURI = u.RequestURI()
		}
	}
	if !strings.HasPrefix(reqURI, "/") {
		reqURI = "/" + reqURI
	}

	// 「强行访问」覆盖（会话级记忆 + 一次性 token）：
	forceToken := c.Query(forceCertQueryParam)
	forceApproved := forceCerts.isForceApproved(uc.Host)
	if forceToken != "" && !forceApproved {
		if forceCerts.consumeForceToken(uc.Host, forceToken) {
			forceApproved = true
		}
	}
	reqCtx := cloudflare_ech.WithSNIServerName(c.Request.Context(), uc.SNIServerName)
	if forceApproved {
		reqCtx = cloudflare_ech.WithAllowBadCert(reqCtx)
		if u, perr := url.Parse(reqURI); perr == nil {
			q := u.Query()
			q.Del(forceCertQueryParam)
			u.RawQuery = q.Encode()
			reqURI = u.RequestURI()
		}
	}

	outReq, err := http.NewRequestWithContext(reqCtx, c.Request.Method, scheme+"://"+targetHostPort+reqURI, c.Request.Body)
	if err != nil {
		return nil, err
	}

	cookie.DefaultJar.SaveClientCookies(uc.Host, c.Request)
	rewrite.CopyHeaders(outReq.Header, c.Request.Header)

	// 剥离正向代理专用逐跳头，防止泄露给上游服务器
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

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

	outReq.Host = targetHostPort
	outReq.ContentLength = c.Request.ContentLength

	fixedCookie := cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile)
	if fixedCookie != "" {
		cookie.DefaultJar.Seed(uc.Host, fixedCookie)
	}
	cookie.DefaultJar.ApplyToRequestWithPriority(uc.Host, outReq, fixedCookie, uc.CookiePriority)
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
	method := c.Request.Method
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		if method != http.MethodGet && method != http.MethodHead {
			method = http.MethodGet
		}
	}
	// 继承 outReq.Context()（保留 WithAllowBadCert 等标记）
	reqCtx := cloudflare_ech.WithSNIServerName(outReq.Context(), uc.SNIServerName)
	if forceCerts.isForceApproved(rawTarget.Host) {
		reqCtx = cloudflare_ech.WithAllowBadCert(reqCtx)
	}
	nextReq, err := http.NewRequestWithContext(reqCtx, method, rawTarget.String(), nil)
	if err != nil {
		return nil, false
	}
	rewrite.CopyHeaders(nextReq.Header, outReq.Header)
	nextReq.Host = rawTarget.Host
	cookie.DefaultJar.ApplyToRequestWithPriority(rawTarget.Host, nextReq, cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile), uc.CookiePriority)
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

func sendResponseBody(c *gin.Context, requestHost string, uc config.UpstreamConfig, resp *http.Response, rewriter func([]byte, string) []byte, adScript *rewrite.AdScriptManager, port string) {
	rc := http.NewResponseController(c.Writer)

	// 文本类且不超过 8MB：解压 -> 重写域名与内容 -> 拦截源站广告 + 插入广告商 <script> 标签 -> 注入 SW -> 重新压缩并发送
	if rewriter != nil && rewrite.IsTextContent(resp.Header.Get("Content-Type")) &&
		(resp.ContentLength <= 0 || resp.ContentLength <= rewrite.MaxRewriteSize) {

		body, err := io.ReadAll(io.LimitReader(resp.Body, rewrite.MaxRewriteSize+1))
		if err != nil || len(body) > rewrite.MaxRewriteSize {
			if len(body) > 0 {
				_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
				if _, werr := c.Writer.Write(body); werr != nil {
					return
				}
			}
			if err == nil {
				streamRemainingBody(c, rc, resp.Body)
			}
			return
		}

		origEnc := resp.Header.Get("Content-Encoding")
		plain, derr := rewrite.DecompressBody(body, origEnc)
		if derr != nil {
			c.Writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = c.Writer.Write(body)
			return
		}

		plain = rewriter(plain, port)

		lowerCT := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(lowerCT, "text/html") {
			if adScript != nil && (adScript.Enabled() || !adScript.SkipAdBlock()) {
				plain = adScript.InjectIntoHTMLForHost(plain, requestHost, uc.Host)
			}
			if uc.SWInject && config.IsPortalDomain(requestHost) && !bytes.Contains(plain, []byte("serviceWorker")) {
				reg := []byte(`<script>navigator.serviceWorker.register('/sw.js').catch(function(){})</script>`)
				if idx := bytes.Index(plain, []byte("</head>")); idx >= 0 {
					plain = append(plain[:idx], append(reg, plain[idx:]...)...)
				} else {
					plain = append(plain, reg...)
				}
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
	streamRemainingBody(c, rc, resp.Body)
}

func streamRemainingBody(c *gin.Context, rc *http.ResponseController, body io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := body.Read(buf)
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