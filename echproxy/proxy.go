package echproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

var Debug bool

var streamBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

func debugLogf(format string, args ...any) {
	if Debug {
		log.Printf(format, args...)
	}
}

const (
	writeTimeout        = 30 * time.Minute
	maxSelfRedirectHops = 3
	maxBufferedReqBody  = 1 << 20
	forceCertQueryParam = "__ech_proxy_force_cert__"
)

var (
	roundTripFn       = cloudflare_ech.RoundTrip
	fallbackProxyMu   sync.RWMutex
	fallbackProxyRaw  string
	fallbackTransport http.RoundTripper
)

// SetFallbackRoundTripper 设置自定义 fallback RoundTripper（供单元测试注入模拟）。
func SetFallbackRoundTripper(rt http.RoundTripper) {
	fallbackProxyMu.Lock()
	defer fallbackProxyMu.Unlock()
	if oldTr, ok := fallbackTransport.(*http.Transport); ok && oldTr != nil {
		oldTr.CloseIdleConnections()
	}
	fallbackTransport = rt
	if rt != nil {
		fallbackProxyRaw = "mock-fallback-proxy"
	} else {
		fallbackProxyRaw = ""
	}
}

// SetFallbackProxy 配置上游备用代理（如本地 v2ray 127.0.0.1:10809），用于在直连分片遭遇 GFW 深度 IP 阻断时无感逃逸。
func SetFallbackProxy(raw string) {
	fallbackProxyMu.Lock()
	defer fallbackProxyMu.Unlock()
	raw = strings.TrimSpace(raw)
	if raw == fallbackProxyRaw {
		return
	}
	fallbackProxyRaw = raw
	u := parseFallbackProxyURL(raw)
	if u == nil {
		if oldTr, ok := fallbackTransport.(*http.Transport); ok && oldTr != nil {
			oldTr.CloseIdleConnections()
		}
		fallbackTransport = nil
		return
	}
	if oldTr, ok := fallbackTransport.(*http.Transport); ok && oldTr != nil {
		oldTr.CloseIdleConnections()
	}
	fallbackTransport = &http.Transport{
		Proxy: http.ProxyURL(u),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// GetFallbackProxy 获取当前生效的上游备用代理原始字符串。
func GetFallbackProxy() string {
	fallbackProxyMu.RLock()
	defer fallbackProxyMu.RUnlock()
	return fallbackProxyRaw
}

func getFallbackTransport() http.RoundTripper {
	fallbackProxyMu.RLock()
	defer fallbackProxyMu.RUnlock()
	return fallbackTransport
}

func parseFallbackProxyURL(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "direct") {
		return nil
	}
	if strings.HasPrefix(strings.ToUpper(raw), "PROXY ") {
		raw = strings.TrimSpace(raw[6:])
		if idx := strings.Index(raw, ";"); idx != -1 {
			raw = strings.TrimSpace(raw[:idx])
		}
	}
	if strings.Contains(raw, "=") {
		for _, tok := range strings.Split(raw, ";") {
			tok = strings.TrimSpace(tok)
			kv := strings.SplitN(tok, "=", 2)
			if len(kv) == 2 && (strings.EqualFold(kv[0], "http") || strings.EqualFold(kv[0], "https")) {
				raw = strings.TrimSpace(kv[1])
				break
			}
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

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

// isDocumentNavigation 判断请求是否为浏览器主文档或 iframe 页面导航请求。
func isDocumentNavigation(req *http.Request) bool {
	if req == nil || req.Method != http.MethodGet {
		return false
	}
	dest := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	mode := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Mode")))
	if dest == "document" || dest == "iframe" || mode == "navigate" {
		return true
	}
	accept := strings.ToLower(req.Header.Get("Accept"))
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

// isClientForceRefresh 判断客户端请求是否显式指示忽略/绕过本地缓存（如 Ctrl+F5 强制刷新）。
func isClientForceRefresh(req *http.Request) bool {
	if req == nil {
		return false
	}
	cc := strings.ToLower(req.Header.Get("Cache-Control"))
	pragma := strings.ToLower(req.Header.Get("Pragma"))
	return strings.Contains(cc, "no-cache") || strings.Contains(pragma, "no-cache") || strings.Contains(cc, "max-age=0")
}

// hasConditionalHeaders 判断客户端原始请求是否携带了条件缓存校验头。
func hasConditionalHeaders(h http.Header) bool {
	return h.Get("If-None-Match") != "" ||
		h.Get("If-Modified-Since") != "" ||
		h.Get("If-Match") != "" ||
		h.Get("If-Unmodified-Since") != "" ||
		h.Get("If-Range") != ""
}

// stripConditionalHeaders 剥离请求中的条件缓存头，强制上游返回完整响应体而非 304。
func stripConditionalHeaders(h http.Header) {
	h.Del("If-None-Match")
	h.Del("If-Modified-Since")
	h.Del("If-Match")
	h.Del("If-Unmodified-Since")
	h.Del("If-Range")
}

func ProxyHandler(upstreams config.UpstreamMap, blockedHosts []string) gin.HandlerFunc {
	return ProxyHandlerWithOptions(upstreams, blockedHosts, nil, nil)
}

func ProxyHandlerWithAuth(upstreams config.UpstreamMap, blockedHosts []string, auth *AuthConfig) gin.HandlerFunc {
	return ProxyHandlerWithOptions(upstreams, blockedHosts, auth, nil)
}

func ProxyHandlerWithOptions(upstreams config.UpstreamMap, blockedHosts []string, auth *AuthConfig, adScript *rewrite.AdScriptManager) gin.HandlerFunc {
	return ProxyHandlerWithConfig(&config.Config{
		Upstreams:    upstreams,
		BlockedHosts: append([]string(nil), blockedHosts...),
	}, auth, adScript)
}

func attachReplayBody(req *http.Request, bodyReplay []byte) {
	if req == nil || bodyReplay == nil {
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyReplay))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodyReplay)), nil
	}
}

func ProxyHandlerWithConfig(cfg *config.Config, auth *AuthConfig, adScript *rewrite.AdScriptManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer logger.RecoverAndLog("ProxyHandler", func(r any, _ []byte) {
			if r == http.ErrAbortHandler {
				panic(http.ErrAbortHandler)
			}
			if !c.Writer.Written() {
				c.String(http.StatusInternalServerError, "internal proxy error")
			}
		})

		start := time.Now()
		clientIP := c.ClientIP()
		host := netdial.CleanHost(c.Request.Host)
		reqPort := netdial.ExtractPort(c.Request.Host)
		origDomainMode := config.IsOriginalDomainMode(host)

		if auth != nil && auth.Enabled() {
			ok, err := auth.Check(c.Request, clientIP)
			if errors.Is(err, ErrAuthRateLimited) {
				if !origDomainMode {
					rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
				}
				c.String(http.StatusTooManyRequests, "too many authentication failures")
				return
			}
			if !ok {
				if !origDomainMode {
					rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
				}
				c.Header("WWW-Authenticate", `Basic realm="ech-proxy"`)
				c.String(http.StatusUnauthorized, "authentication required")
				return
			}
		}

		// upstream.json 严格只与 8443 门户方案有关：
		// 在 PAC 主线方案下（adScript != nil），非 *.l.moonchan.xyz 原域名完全不耦合 upstream.json。
		var upstreams config.UpstreamMap
		var blocked []string
		if adScript == nil || config.IsPortalDomain(host) {
			upstreams, blocked = cfg.Snapshot()
		}

		uc, ok := config.Resolve(upstreams, host)
		if !ok {
			if !origDomainMode {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			}
			c.String(http.StatusBadGateway, "no upstream for host: %s", host)
			return
		}

		// PAC / 443 原域名模式下完全透传，不构建响应重写器（仅 8443 门户域名启用重写器）
		var rewriter func([]byte, string) []byte
		if !origDomainMode && (len(upstreams) > 0 || len(blocked) > 0) {
			ucForRewrite := uc
			if ucForRewrite.Wildcard == nil && len(upstreams) > 0 {
				ucForRewrite.Wildcard = config.InheritWildcard(upstreams, host)
			}
			rewriter = rewrite.BuildEntryRewriterForHost(host, ucForRewrite, blocked)
		}

		clientSentPlainHTTP := c.Request.TLS == nil &&
			(strings.HasPrefix(strings.ToLower(c.Request.RequestURI), "http://") ||
				strings.EqualFold(c.Request.URL.Scheme, "http") ||
				reqPort == "80")

		targetScheme := "https"
		if clientSentPlainHTTP && reqPort != "" && reqPort != "80" && reqPort != "443" && origDomainMode {
			targetScheme = "http"
		}

		var bodyReplay []byte
		if c.Request.Body != nil && c.Request.ContentLength >= 0 && c.Request.ContentLength <= maxBufferedReqBody {
			if b, rerr := io.ReadAll(io.LimitReader(c.Request.Body, maxBufferedReqBody+1)); rerr == nil && len(b) <= maxBufferedReqBody {
				bodyReplay = b
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyReplay))
			}
		}

		outReq, err := buildUpstreamRequestWithScheme(c, uc, targetScheme, reqPort)
		if err != nil {
			if !origDomainMode {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			}
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}
		attachReplayBody(outReq, bodyReplay)

		resp, err := roundTripFn(outReq, uc.Mode, uc.IPMode)
		if err != nil && clientSentPlainHTTP && targetScheme == "https" && !cloudflare_ech.IsCertError(err) && origDomainMode {
			if bodyReplay != nil {
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyReplay))
			}
			if httpReq, herr := buildUpstreamRequestWithScheme(c, uc, "http", reqPort); herr == nil {
				attachReplayBody(httpReq, bodyReplay)
				if httpResp, herr2 := roundTripFn(httpReq, uc.Mode, uc.IPMode); herr2 == nil {
					outReq, resp, err = httpReq, httpResp, nil
					targetScheme = "http"
				}
			}
		}

		if err != nil && !cloudflare_ech.IsCertError(err) && !errors.Is(err, context.Canceled) && (c.Request.Context().Err() == nil) {
			if fbTransport := getFallbackTransport(); fbTransport != nil {
				if bodyReplay != nil {
					c.Request.Body = io.NopCloser(bytes.NewReader(bodyReplay))
				}
				if fbReq, herr := buildUpstreamRequestWithScheme(c, uc, targetScheme, reqPort); herr == nil {
					attachReplayBody(fbReq, bodyReplay)
					if fbResp, fberr := fbTransport.RoundTrip(fbReq); fberr == nil {
						log.Printf("[%s] Direct connection failed for %s (%v), seamlessly fell back to upstream proxy (%s)", clientIP, uc.Host, err, GetFallbackProxy())
						outReq, resp, err = fbReq, fbResp, nil
					}
				}
			}
		}

		reqPath := strings.ToLower(c.Request.URL.Path)
		isSourceMap := strings.HasSuffix(reqPath, ".js.map") || strings.HasSuffix(reqPath, ".css.map") || strings.HasSuffix(reqPath, ".map")
		if isSourceMap && (err != nil || (resp != nil && resp.StatusCode >= 400)) {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			if !origDomainMode {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			}
			c.Header("Content-Type", "application/json; charset=utf-8")
			c.Header("Cache-Control", "public, max-age=86400")
			c.String(http.StatusOK, `{"version":3,"sources":[],"mappings":""}`)
			return
		}

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
				(c.Request.Context().Err() != nil && (errors.Is(c.Request.Context().Err(), context.Canceled) || errors.Is(c.Request.Context().Err(), context.DeadlineExceeded))) ||
				strings.Contains(strings.ToLower(err.Error()), "context canceled") {
				// 客户端主动断开/取消请求（如浏览器切页、图片预取取消或滚动离开可视区），属于正常客户端生命周期，无需向日志刷屏假报警
				debugLogf("[%s] Client canceled request (%s): %v", clientIP, uc.Host, err)
				return
			}
			log.Printf("[%s] Upstream request failed (%s): %v", clientIP, uc.Host, err)
			if !origDomainMode {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			}
			if renderCertWarningIfMatch(c, uc.Host, err) {
				return
			}
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()

		// PAC / 443 原域名模式下不写入内存 CookieJar，完全由浏览器自主存储与管理 Cookie
		if !origDomainMode {
			cookie.DefaultJar.SaveResponseCookies(uc.Host, resp)
		}
		debugLogf("[%s] %s %s -> %s (%s, %v)", clientIP, c.Request.Method, c.Request.URL.Path, uc.Host, resp.Status, time.Since(start))

		port := reqPort
		cookieDomain := uc.CookieDomain
		if cookieDomain == "" {
			cookieDomain = host
		}
		effectiveRewriter := rewriter
		if origDomainMode {
			effectiveRewriter = nil
		}
		prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, effectiveRewriter, port)

		// PAC / 443 原域名模式下完全透传上游 3xx 重定向，仅 8443 门户模式执行内部自我重定向熔断
		if !origDomainMode {
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
				prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, effectiveRewriter, port)
			}
		}

		// 防御「孤儿 304」白屏：
		// 若上游返回 304 Not Modified，但浏览器并未发送任何条件请求头（浏览器本地根本无缓存导致页面全白），
		// 自动剥离条件请求头并附加 Cache-Control: no-cache 向上游重拉一次完整的 200 OK 响应。
		if resp.StatusCode == http.StatusNotModified && !hasConditionalHeaders(c.Request.Header) {
			if retryReq, rerr := buildUpstreamRequestWithScheme(c, uc, targetScheme, reqPort); rerr == nil {
				attachReplayBody(retryReq, bodyReplay)
				stripConditionalHeaders(retryReq.Header)
				retryReq.Header.Set("Cache-Control", "no-cache")
				retryReq.Header.Set("Pragma", "no-cache")
				if retryResp, rerr2 := roundTripFn(retryReq, uc.Mode, uc.IPMode); rerr2 == nil && retryResp != nil {
					_ = resp.Body.Close()
					resp = retryResp
					outReq = retryReq
					if !origDomainMode {
						cookie.DefaultJar.SaveResponseCookies(uc.Host, resp)
					}
					clearHeaders(c.Writer.Header())
					prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, effectiveRewriter, port)
				}
			}
		}

		if uc.SWInject && config.IsPortalDomain(host) && c.Request.URL.Path == "/sw.js" && !rewrite.IsJavascriptResponse(resp) {
			c.Writer.Header().Del("Content-Length")
			c.Writer.Header().Set("Content-Type", "application/javascript")
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte(rewrite.GenerateServiceWorkerJS(upstreams, indexHost, port, blocked)))
			return
		}

		sendResponseBody(c, host, uc, resp, effectiveRewriter, port, adScript)
	}
}

func buildUpstreamRequestWithScheme(c *gin.Context, uc config.UpstreamConfig, scheme, reqPort string) (*http.Request, error) {
	if scheme == "" {
		scheme = "https"
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

	reqCtx := cloudflare_ech.WithSNIServerName(c.Request.Context(), uc.SNIServerName)
	reqURI, forceCert := consumeForceCertParam(reqURI, uc.Host)
	if forceCert {
		reqCtx = cloudflare_ech.WithAllowBadCert(reqCtx)
	}

	targetHost := uc.Host
	if scheme == "http" && reqPort != "" && reqPort != "80" && reqPort != "443" && !strings.Contains(targetHost, ":") {
		targetHost = net.JoinHostPort(targetHost, reqPort)
	}

	outReq, err := http.NewRequestWithContext(reqCtx, c.Request.Method, scheme+"://"+targetHost+reqURI, c.Request.Body)
	if err != nil {
		return nil, err
	}

	origDomainMode := config.IsOriginalDomainMode(c.Request.Host)
	if origDomainMode {
		// PAC / 443 原域名模式：完全透传客户端请求头（含原始 Cookie 头、CORS 预检头、安全头等），不经过内存 CookieJar 拦截重排
		rewrite.CopyRawHeaders(outReq.Header, c.Request.Header)
	} else {
		cookie.DefaultJar.SaveClientCookies(uc.Host, c.Request)
		rewrite.CopyHeaders(outReq.Header, c.Request.Header)
	}
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authenticate")
	outReq.Header.Del("Proxy-Authorization")

	// 仅当客户端主动发起强制刷新（Cache-Control: no-cache / Pragma: no-cache）时，剥离条件缓存头；
	// 正常浏览导航保留 If-None-Match / If-Modified-Since，允许毫秒级 304 命中浏览器本地缓存，大幅提升浏览速度。
	if isClientForceRefresh(c.Request) {
		stripConditionalHeaders(outReq.Header)
	}

	if _, ok := uc.Headers["X-Forwarded-For"]; !ok {
		outReq.Header.Del("X-Forwarded-For")
	}
	if _, ok := uc.Headers["X-Forwarded-Proto"]; !ok {
		outReq.Header.Del("X-Forwarded-Proto")
	}
	if !origDomainMode {
		if uc.Referer != "" {
			outReq.Header.Set("Referer", uc.Referer)
		}
		rewrite.ApplyHeaderRules(outReq.Header, uc.Headers, true, c.Request)
	}

	outReq.Host = targetHost
	outReq.ContentLength = c.Request.ContentLength

	if !origDomainMode {
		fixedCookie := cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile)
		if fixedCookie != "" {
			cookie.DefaultJar.Seed(uc.Host, fixedCookie)
		}
		cookie.DefaultJar.ApplyToRequestWithPriority(uc.Host, outReq, fixedCookie, uc.CookiePriority)
	}
	return outReq, nil
}

func consumeForceCertParam(reqURI, upstreamHost string) (string, bool) {
	approved := forceCerts.isApproved(upstreamHost)
	if !strings.Contains(reqURI, forceCertQueryParam) {
		return reqURI, approved
	}
	u, err := url.ParseRequestURI(reqURI)
	if err != nil {
		return reqURI, approved
	}
	q := u.Query()
	tok := q.Get(forceCertQueryParam)
	if tok == "" {
		return reqURI, approved
	}
	q.Del(forceCertQueryParam)
	u.RawQuery = q.Encode()
	cleaned := u.RequestURI()
	if forceCerts.consume(upstreamHost, tok) {
		return cleaned, true
	}
	return cleaned, approved
}

func prepareResponseHeaders(dst, src http.Header, uc config.UpstreamConfig, cookieDomain string, req *http.Request, rewriter func([]byte, string) []byte, port string) {
	origDomainMode := req != nil && config.IsOriginalDomainMode(req.Host)
	if origDomainMode {
		// PAC / 443 原域名模式：100% 原样透传上游响应头（保留原始 Set-Cookie Domain、Location 重定向、CSP、CORS、ETag、Vary 等）
		rewrite.CopyRawHeaders(dst, src)
		return
	}
	rewrite.CopyHeaders(dst, src)
	httpMode := req.TLS == nil && !strings.EqualFold(req.URL.Scheme, "https")
	cookie.RewriteSetCookieHeaders(dst, cookieDomain, httpMode)
	rewrite.ApplyHeaderRules(dst, uc.ResponseHeaders, false, nil)
	if rewriter != nil {
		rewrite.RewriteRedirectHeaders(dst, rewriter, port)
	}
	ct := strings.ToLower(src.Get("Content-Type"))
	if rewriter != nil && rewrite.IsTextContent(ct) {
		dst.Del("ETag")
		dst.Del("Last-Modified")
	}
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
	reqCtx := cloudflare_ech.WithSNIServerName(c.Request.Context(), uc.SNIServerName)
	nextReq, err := http.NewRequestWithContext(reqCtx, method, rawTarget.String(), nil)
	if err != nil {
		return nil, false
	}
	rewrite.CopyHeaders(nextReq.Header, outReq.Header)
	stripConditionalHeaders(nextReq.Header)
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

func needsBodyRewrite(c *gin.Context, requestHost string, uc config.UpstreamConfig, resp *http.Response, rewriter func([]byte, string) []byte, adScript *rewrite.AdScriptManager) bool {
	// PAC / 443 原域名模式下永不缓冲或改写响应体，一律走流式直传
	if config.IsOriginalDomainMode(requestHost) {
		return false
	}
	if c.Request.Method == http.MethodHead ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200) {
		return false
	}
	if resp.ContentLength > rewrite.MaxRewriteSize {
		return false
	}

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	isHTML := strings.Contains(contentType, "text/html")

	// 1. 显式配置了重写器（如 8443 门户模式下的 URL 映射）且为文本
	if rewriter != nil && rewrite.IsTextContent(contentType) {
		return true
	}

	// 2. 门户域下的 ServiceWorker 注册脚本注入
	if isHTML && uc.SWInject && config.IsPortalDomain(requestHost) {
		return true
	}

	return false
}

func sendResponseBody(c *gin.Context, requestHost string, uc config.UpstreamConfig, resp *http.Response, rewriter func([]byte, string) []byte, port string, adScript *rewrite.AdScriptManager) {
	if c.Request.Method == http.MethodHead ||
		resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200) {
		c.Status(resp.StatusCode)
		c.Writer.WriteHeaderNow()
		return
	}

	rc := http.NewResponseController(c.Writer)

	// PAC / 443 原域名模式及无需改写的请求，一律直接流式传输给客户端（首包预读校验防止 0 字节断流被当成 200 缓存）
	if !needsBodyRewrite(c, requestHost, uc, resp, rewriter, adScript) {
		streamRemainingBody(c, rc, resp)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, rewrite.MaxRewriteSize+1))
	if err != nil && len(body) == 0 {
		clearHeaders(c.Writer.Header())
		rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.String(http.StatusBadGateway, "upstream body read failed: %v", err)
		return
	}
	if err != nil || len(body) > rewrite.MaxRewriteSize {
		c.Status(resp.StatusCode)
		if len(body) > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, werr := c.Writer.Write(body); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
		bufPtr := streamBufPool.Get().(*[]byte)
		defer streamBufPool.Put(bufPtr)
		streamRemainingBodyWithBuf(c, rc, resp.Body, *bufPtr)
		return
	}

	origEnc := resp.Header.Get("Content-Encoding")
	plain, derr := rewrite.DecompressBody(body, origEnc)
	if derr != nil {
		if len(body) == 0 && resp.ContentLength != 0 {
			clearHeaders(c.Writer.Header())
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
			c.String(http.StatusBadGateway, "upstream empty compressed body")
			return
		}
		c.Writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		c.Status(resp.StatusCode)
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = c.Writer.Write(body)
		return
	}

	if rewriter != nil {
		plain = rewriter(plain, port)
	}

	isHTML := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
	if isHTML && uc.SWInject && config.IsPortalDomain(requestHost) && !bytes.Contains(plain, []byte("serviceWorker")) {
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
	c.Status(resp.StatusCode)
	_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = c.Writer.Write(plain)
}

func streamRemainingBody(c *gin.Context, rc *http.ResponseController, resp *http.Response) {
	bufPtr := streamBufPool.Get().(*[]byte)
	defer streamBufPool.Put(bufPtr)
	buf := *bufPtr

	n, rerr := resp.Body.Read(buf)
	if n == 0 && rerr != nil && !errors.Is(rerr, io.EOF) {
		clearHeaders(c.Writer.Header())
		if !config.IsOriginalDomainMode(c.Request.Host) {
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
		}
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.String(http.StatusBadGateway, "upstream stream aborted before first byte: %v", rerr)
		return
	}

	c.Status(resp.StatusCode)
	if n > 0 {
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, werr := c.Writer.Write(buf[:n]); werr != nil {
			return
		}
		if f, ok := c.Writer.(http.Flusher); ok {
			f.Flush()
		}
	}
	if rerr != nil {
		return
	}
	streamRemainingBodyWithBuf(c, rc, resp.Body, buf)
}

func streamRemainingBodyWithBuf(c *gin.Context, rc *http.ResponseController, body io.Reader, buf []byte) {
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
