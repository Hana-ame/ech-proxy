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
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

var Debug bool

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

var roundTripFn = cloudflare_ech.RoundTrip

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

func ProxyHandlerWithConfig(cfg *config.Config, auth *AuthConfig, adScript *rewrite.AdScriptManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer logger.RecoverAndLog("ProxyHandler", func(_ any, _ []byte) {
			if !c.Writer.Written() {
				c.String(http.StatusInternalServerError, "internal proxy error")
			}
		})

		start := time.Now()
		clientIP := c.ClientIP()
		host := netdial.CleanHost(c.Request.Host)
		reqPort := netdial.ExtractPort(c.Request.Host)

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

		// upstream.json 严格只与 8443 门户方案有关：
		// 在 PAC 主线方案下（adScript != nil），非 *.l.moonchan.xyz 原域名完全不耦合 upstream.json。
		var upstreams config.UpstreamMap
		var blocked []string
		if adScript == nil || config.IsPortalDomain(host) {
			upstreams, blocked = cfg.Snapshot()
		}

		uc, ok := config.Resolve(upstreams, host)
		if !ok {
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusBadGateway, "no upstream for host: %s", host)
			return
		}

		ucForRewrite := uc
		if ucForRewrite.Wildcard == nil && len(upstreams) > 0 {
			ucForRewrite.Wildcard = config.InheritWildcard(upstreams, host)
		}
		var rewriter func([]byte, string) []byte
		if len(upstreams) > 0 || len(blocked) > 0 {
			rewriter = rewrite.BuildEntryRewriterForHost(host, ucForRewrite, blocked)
		}

		clientSentPlainHTTP := c.Request.TLS == nil &&
			(strings.HasPrefix(strings.ToLower(c.Request.RequestURI), "http://") ||
				strings.EqualFold(c.Request.URL.Scheme, "http") ||
				reqPort == "80")

		targetScheme := "https"
		if clientSentPlainHTTP && reqPort != "" && reqPort != "80" && reqPort != "443" && config.IsOriginalDomainMode(host) {
			targetScheme = "http"
		}

		var bodyReplay []byte
		if clientSentPlainHTTP && targetScheme == "https" && c.Request.Body != nil && c.Request.ContentLength <= maxBufferedReqBody {
			if b, rerr := io.ReadAll(io.LimitReader(c.Request.Body, maxBufferedReqBody+1)); rerr == nil && len(b) <= maxBufferedReqBody {
				bodyReplay = b
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyReplay))
			}
		}

		outReq, err := buildUpstreamRequestWithScheme(c, uc, targetScheme, reqPort)
		if err != nil {
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		resp, err := roundTripFn(outReq, uc.Mode, uc.IPMode)
		if err != nil && clientSentPlainHTTP && targetScheme == "https" && !cloudflare_ech.IsCertError(err) && config.IsOriginalDomainMode(host) {
			if bodyReplay != nil {
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyReplay))
			}
			if httpReq, herr := buildUpstreamRequestWithScheme(c, uc, "http", reqPort); herr == nil {
				if httpResp, herr2 := roundTripFn(httpReq, uc.Mode, uc.IPMode); herr2 == nil {
					outReq, resp, err = httpReq, httpResp, nil
					targetScheme = "http"
				}
			}
		}

		if err != nil {
			log.Printf("[%s] Upstream request failed (%s): %v", clientIP, uc.Host, err)
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
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

		cookie.DefaultJar.SaveResponseCookies(uc.Host, resp)
		debugLogf("[%s] %s %s -> %s (%s, %v)", clientIP, c.Request.Method, c.Request.URL.Path, uc.Host, resp.Status, time.Since(start))

		port := reqPort
		cookieDomain := uc.CookieDomain
		if cookieDomain == "" {
			cookieDomain = host
		}
		effectiveRewriter := rewriter
		if targetScheme == "http" && config.IsOriginalDomainMode(host) {
			effectiveRewriter = nil
		}
		prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, effectiveRewriter, port)

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

		if uc.SWInject && config.IsPortalDomain(host) && c.Request.URL.Path == "/sw.js" && !rewrite.IsJavascriptResponse(resp) {
			c.Writer.Header().Del("Content-Length")
			c.Writer.Header().Set("Content-Type", "application/javascript")
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte(rewrite.GenerateServiceWorkerJS(upstreams, indexHost, port, blocked)))
			return
		}

		c.Status(resp.StatusCode)
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

	cookie.DefaultJar.SaveClientCookies(uc.Host, c.Request)
	rewrite.CopyHeaders(outReq.Header, c.Request.Header)
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

	outReq.Host = targetHost
	outReq.ContentLength = c.Request.ContentLength

	fixedCookie := cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile)
	if fixedCookie != "" {
		cookie.DefaultJar.Seed(uc.Host, fixedCookie)
	}
	cookie.DefaultJar.ApplyToRequestWithPriority(uc.Host, outReq, fixedCookie, uc.CookiePriority)
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
	rewrite.CopyHeaders(dst, src)
	cookie.RewriteSetCookieHeaders(dst, cookieDomain, req.TLS == nil)
	rewrite.ApplyHeaderRules(dst, uc.ResponseHeaders, false, nil)
	if rewriter != nil {
		rewrite.RewriteRedirectHeaders(dst, rewriter, port)
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

func sendResponseBody(c *gin.Context, requestHost string, uc config.UpstreamConfig, resp *http.Response, rewriter func([]byte, string) []byte, port string, adScript *rewrite.AdScriptManager) {
	rc := http.NewResponseController(c.Writer)

	if (rewriter != nil || adScript != nil) && rewrite.IsTextContent(resp.Header.Get("Content-Type")) &&
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

		if rewriter != nil {
			plain = rewriter(plain, port)
		}

		isHTML := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
		if isHTML && adScript != nil && (!adScript.SkipAdScript() || !adScript.SkipAdBlock()) {
			beforeLen := len(plain)
			plain = adScript.InjectIntoHTMLForHost(plain, requestHost, uc.Host)
			if len(plain) != beforeLen {
				c.Writer.Header().Del("Content-Security-Policy")
				c.Writer.Header().Del("Content-Security-Policy-Report-Only")
			}
		}

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
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = c.Writer.Write(plain)
		return
	}

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