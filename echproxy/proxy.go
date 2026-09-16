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

	cloudflare_ech "github.com/Hana-ame/ech-proxy/ech"
	"github.com/Hana-ame/ech-proxy/netdial"
	"github.com/gin-gonic/gin"
)

var Debug bool

func debugLogf(format string, args ...interface{}) {
	if Debug {
		log.Printf(format, args...)
	}
}

const writeTimeout = 30 * time.Minute

func setWriteDeadline(rc *http.ResponseController) {
	rc.SetWriteDeadline(time.Now().Add(writeTimeout))
}

func ModeName(mode string) string {
	switch mode {
	case "sni":
		return "SNI伪装直连"
	case "direct":
		return "普通直连"
	default:
		return "Cloudflare ECH"
	}
}

func proxyRoundTrip(req *http.Request, mode string) (*http.Response, error) {
	switch mode {
	case "direct":
		client := netdial.Client(netdial.OpTimeout)
		return client.Do(req)
	case "sni":
		return sniFrontDo(req)
	default:
		return cloudflare_ech.Do(req)
	}
}

func ProxyHandler(cfg UpstreamMap, blockedHosts []string) gin.HandlerFunc {
	blocked := append([]string(nil), blockedHosts...)
	return func(c *gin.Context) {
		start := time.Now()
		clientIP := c.ClientIP()
		method := c.Request.Method
		rawPath := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		host := c.Request.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		uc, ok := cfg[host]
		if !ok {
			uc, ok = matchWildcard(cfg, host)
		}
		if !ok {
			log.Printf("[%s] 未找到上游配置: %s", clientIP, host)
			c.String(http.StatusBadGateway, "no upstream for host: %s", host)
			return
		}

		ucForRewrite := uc
		if ucForRewrite.Wildcard == nil {
			ucForRewrite.Wildcard = inheritWildcard(cfg, host)
		}
		rewriter := buildEntryRewriter(ucForRewrite, blocked)

		swWant := uc.SWInject && rawPath == "/sw.js"

		targetURL := &url.URL{
			Scheme:   "https",
			Host:     uc.Host,
			Path:     rawPath,
			RawQuery: rawQuery,
		}
		urlStr := targetURL.String()

		debugLogf("[%s] %s %s -> %s", clientIP, method, rawPath, urlStr)

		outReq, err := http.NewRequest(method, urlStr, c.Request.Body)
		if err != nil {
			log.Printf("[%s] 创建请求失败: %v", clientIP, err)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		// 1. 保存客户端请求携带的所有 Cookie (捕获前端 JS document.cookie 写入的新凭证)
		saveClientCookies(uc.Host, c.Request)

		// 2. 拷贝客户端请求头 (剔除 RFC 逐跳头)
		copyHeaders(outReq.Header, c.Request.Header)

		// 3. 默认不伪造/注入 X-Forwarded-For 与 X-Forwarded-Proto，防止暴露反代身份与真实 IP;
		// 客户端自带的代理追踪头默认抹除 (除非在 headers 规则中显式要求保留或配置)
		if _, ok := uc.Headers["X-Forwarded-For"]; !ok {
			outReq.Header.Del("X-Forwarded-For")
		}
		if _, ok := uc.Headers["X-Forwarded-Proto"]; !ok {
			outReq.Header.Del("X-Forwarded-Proto")
		}

		// 4. 应用通用声明式请求头规则 (支持 string 覆盖、{delete:true} 剔除、{replace:[a,b]} 替换)
		ApplyHeaderRules(outReq.Header, uc.Headers, true, c.Request)

		outReq.Host = uc.Host
		outReq.ContentLength = c.Request.ContentLength

		// 5. 应用 Cookie (合并 Jar + 客户端当前请求 Cookie + 本地文件/固定 Cookie)
		fixedCookie := getFixedCookie(uc)
		applyCookies(uc.Host, outReq, fixedCookie)

		resp, err := proxyRoundTrip(outReq, uc.Mode)
		if err != nil {
			log.Printf("[%s] 上游请求失败: %v (耗时: %v)", clientIP, err, time.Since(start))
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer resp.Body.Close()

		saveCookies(uc.Host, resp)

		debugLogf("[%s] <- %s (耗时: %v)", clientIP, resp.Status, time.Since(start))

		copyHeaders(c.Writer.Header(), resp.Header)
		rewriteSetCookieDomains(c.Writer.Header(), host, c.Request.TLS == nil)

		// 6. 应用通用声明式响应头规则 (支持 string 覆盖、{delete:true} 剔除、{replace:[a,b]} 替换)
		ApplyHeaderRules(c.Writer.Header(), uc.ResponseHeaders, false, nil)

		if swWant && !isJavascriptResponse(resp) {
			port := ""
			if _, p, err := net.SplitHostPort(c.Request.Host); err == nil {
				port = p
			}
			swProxyMap := buildSWProxyMap(cfg, port)
			swRules := collectWildcardRules(cfg)
			c.Writer.Header().Del("Content-Length")
			c.Writer.Header().Set("Content-Type", "application/javascript")
			c.Writer.WriteHeader(200)
			c.Writer.Write([]byte(swOverrideJS(swProxyMap, swRules, blocked)))
			debugLogf("[%s] %s %s -> SW 兜底生成 %d 条规则 %d 条通配 %d 条屏蔽", clientIP, method, rawPath, len(swProxyMap), len(swRules), len(blocked))
			return
		}

		c.Status(resp.StatusCode)

		rc := http.NewResponseController(c.Writer)

		if rewriter != nil {
			port := ""
			if _, p, err := net.SplitHostPort(c.Request.Host); err == nil {
				port = p
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				c.Writer.Header().Set("Location", string(rewriter([]byte(loc), port)))
			}
			if refresh := resp.Header.Get("Refresh"); refresh != "" {
				c.Writer.Header().Set("Refresh", string(rewriter([]byte(refresh), port)))
			}

			if isTextContent(resp.Header.Get("Content-Type")) &&
				(resp.ContentLength <= 0 || resp.ContentLength <= maxRewriteSize) {
				body, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteSize+1))
				if err != nil {
					if len(body) > 0 {
						setWriteDeadline(rc)
						c.Writer.Write(body)
					}
					return
				}
				if len(body) > maxRewriteSize {
					if len(body) > 0 {
						setWriteDeadline(rc)
						c.Writer.Write(body)
					}
				} else if body, err = decompressBody(body, resp.Header.Get("Content-Encoding")); err == nil {
					body = rewriter(body, port)
					if uc.SWInject && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
						!bytes.Contains(body, []byte("serviceWorker")) {
						reg := []byte(`<script>navigator.serviceWorker.register('/sw.js').catch(function(){})</script>`)
						if idx := bytes.Index(body, []byte("</head>")); idx >= 0 {
							body = append(body[:idx], append(reg, body[idx:]...)...)
						} else {
							body = append(body, reg...)
						}
						debugLogf("[%s] %s -> HTML 注入 SW 注册", clientIP, rawPath)
					}
					c.Writer.Header().Del("Content-Encoding")
					c.Writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
					setWriteDeadline(rc)
					if _, werr := c.Writer.Write(body); werr == nil {
						return
					}
				} else {
					if len(body) > 0 {
						setWriteDeadline(rc)
						c.Writer.Write(body)
					}
					return
				}
			}
		}

		buf := make([]byte, 32*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				setWriteDeadline(rc)
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
}
