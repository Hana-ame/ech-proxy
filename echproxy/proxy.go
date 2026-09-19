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

	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
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
		return "SNI Camouflage"
	case "direct":
		return "Direct"
	default:
		return "Cloudflare ECH"
	}
}

func proxyRoundTrip(req *http.Request, mode, ipMode string) (*http.Response, error) {
	switch mode {
	case "direct":
		client := netdial.Client(netdial.OpTimeout)
		return client.Do(req)
	case "sni":
		return sniFrontDo(req)
	default:
		return cloudflare_ech.Do(req, ipMode)
	}
}

// buildUpstreamRequest constructs the outgoing upstream HTTP request from the client's gin context:
// copies and filters headers, strips proxy-tracking headers, applies declarative header rules,
// merges cookies (jar + client + fixed), and sets the upstream Host.
func buildUpstreamRequest(c *gin.Context, uc UpstreamConfig, urlStr string, priority ...string) (*http.Request, error) {
	p := getCookiePriority(priority...)
	outReq, err := http.NewRequest(c.Request.Method, urlStr, c.Request.Body)
	if err != nil {
		return nil, err
	}

	// 1. Capture JS-set cookies sent by the browser before overwriting the Cookie header.
	saveClientCookies(uc.Host, c.Request, p)

	// 2. Copy client request headers, stripping RFC 2616 hop-by-hop headers.
	copyHeaders(outReq.Header, c.Request.Header)

	// 3. Strip proxy-identity headers unless explicitly configured via header rules.
	if _, ok := uc.Headers["X-Forwarded-For"]; !ok {
		outReq.Header.Del("X-Forwarded-For")
	}
	if _, ok := uc.Headers["X-Forwarded-Proto"]; !ok {
		outReq.Header.Del("X-Forwarded-Proto")
	}

	// 4. Apply declarative header rules (set/delete/regex-replace).
	ApplyHeaderRules(outReq.Header, uc.Headers, true, c.Request)

	outReq.Host = uc.Host
	outReq.ContentLength = c.Request.ContentLength

	// 5. Merge cookie jar + client cookies + fixed/file cookies into the outgoing Cookie header.
	// If priority is browser, do not inject server's static fixedCookie.
	fixedCookie := ""
	if p != "browser" && !hasJarCookies(uc.Host) {
		fixedCookie = getFixedCookie(uc)
		if fixedCookie != "" {
			seedCookieRaw(uc.Host, fixedCookie)
		}
	}
	applyCookies(uc.Host, outReq, fixedCookie, p)

	return outReq, nil
}


// handleSWFallback serves the generated Service Worker JavaScript when the upstream does not
// return a JavaScript response for /sw.js.
func handleSWFallback(c *gin.Context, cfg UpstreamMap, blocked []string, clientIP, method, rawPath string) {
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
	debugLogf("[%s] %s %s -> SW fallback generated %d rules, %d wildcards, %d blocked",
		clientIP, method, rawPath, len(swProxyMap), len(swRules), len(blocked))
}

// rewriteAndSendBody handles the response body pipeline:
// For text content within the size limit: decompresses, rewrites domains/URLs, optionally
// injects the SW registration snippet, re-compresses (gzip if client accepts it), and
// sets accurate Content-Length.
// For binary or oversized content: streams raw bytes in 32 KB chunks with flushing.
func rewriteAndSendBody(c *gin.Context, uc UpstreamConfig, resp *http.Response,
	rewriter func([]byte, string) []byte, rc *http.ResponseController, clientIP, rawPath string) {

	port := ""
	if _, p, err := net.SplitHostPort(c.Request.Host); err == nil {
		port = p
	}

	// Text body rewriting path (decompress → rewrite → optionally re-compress).
	if rewriter != nil &&
		isTextContent(resp.Header.Get("Content-Type")) &&
		(resp.ContentLength <= 0 || resp.ContentLength <= maxRewriteSize) {

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteSize+1))
		if err != nil {
			log.Printf("[%s] Body read error for %s: %v", clientIP, rawPath, err)
			if len(body) > 0 {
				setWriteDeadline(rc)
				c.Writer.Write(body)
			}
			return
		}
		if len(body) > maxRewriteSize {
			// Exceeds rewrite size limit; stream unmodified.
			if len(body) > 0 {
				setWriteDeadline(rc)
				c.Writer.Write(body)
			}
			return
		}

		origEncoding := resp.Header.Get("Content-Encoding")
		decompressed, derr := decompressBody(body, origEncoding)
		if derr != nil {
			log.Printf("[%s] Decompression error for %s (%s): %v", clientIP, rawPath, origEncoding, derr)
			if len(body) > 0 {
				setWriteDeadline(rc)
				c.Writer.Write(body)
			}
			return
		}

		decompressed = rewriter(decompressed, port)

		// Inject Service Worker registration snippet into HTML pages that don't already have one.
		if uc.SWInject &&
			strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
			!bytes.Contains(decompressed, []byte("serviceWorker")) {
			reg := []byte(`<script>navigator.serviceWorker.register('/sw.js').catch(function(){})</script>`)
			if idx := bytes.Index(decompressed, []byte("</head>")); idx >= 0 {
				decompressed = append(decompressed[:idx], append(reg, decompressed[idx:]...)...)
			} else {
				decompressed = append(decompressed, reg...)
			}
			debugLogf("[%s] %s -> HTML injected SW registration", clientIP, rawPath)
		}

		// Re-compress using gzip if the client accepts it and the original was gzip-encoded.
		c.Writer.Header().Del("Content-Encoding")
		if compressed, enc := compressBody(decompressed, origEncoding, c.Request.Header.Get("Accept-Encoding")); enc != "" {
			decompressed = compressed
			c.Writer.Header().Set("Content-Encoding", enc)
		}
		c.Writer.Header().Set("Content-Length", strconv.Itoa(len(decompressed)))
		setWriteDeadline(rc)
		c.Writer.Write(decompressed)
		return
	}

	// Binary / large body streaming path: copy in 32 KB chunks with per-chunk flush.
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

// ProxyHandler returns a gin.HandlerFunc that resolves the upstream for each request,
// constructs and sends an outgoing request, then writes the (optionally rewritten) response
// back to the client. The pipeline is split across three helpers:
//   - buildUpstreamRequest: header/cookie construction
//   - handleSWFallback:     service worker JS generation
//   - rewriteAndSendBody:   body decompression, rewriting, re-compression, and streaming
func ProxyHandler(cfg UpstreamMap, blockedHosts []string) gin.HandlerFunc {
	blocked := append([]string(nil), blockedHosts...)
	return func(c *gin.Context) {
		start := time.Now()
		clientIP := c.ClientIP()
		method := c.Request.Method
		rawPath := c.Request.URL.Path

		// --- Step 1: Resolve upstream config ---
		host := c.Request.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		uc, ok := cfg[host]
		if !ok {
			uc, ok = matchWildcard(cfg, host)
		}
		if !ok {
			log.Printf("[%s] Upstream config not found: %s", clientIP, host)
			c.String(http.StatusBadGateway, "no upstream for host: %s", host)
			return
		}

		// URL parameter trigger for cookie mode switch (?_cookie_mode=seed or ?_cookie_mode=browser)
		if mode := strings.ToLower(strings.TrimSpace(c.Query("_cookie_mode"))); mode == "seed" || mode == "browser" {
			applyCookieModeSwitch(c, uc, host, mode)
			u := *c.Request.URL
			q := u.Query()
			q.Del("_cookie_mode")
			u.RawQuery = q.Encode()
			target := u.RequestURI()
			if target == "" {
				target = "/"
			}
			c.Redirect(http.StatusFound, target)
			return
		}

		cookiePriority := getEffectiveCookiePriority(c, uc, host)

		ucForRewrite := uc
		if ucForRewrite.Wildcard == nil {
			ucForRewrite.Wildcard = inheritWildcard(cfg, host)
		}
		rewriter := buildEntryRewriter(ucForRewrite, blocked)
		swWant := uc.SWInject && rawPath == "/sw.js"

		// --- Step 2: Build outgoing upstream request ---
		reqURI := c.Request.RequestURI
		if reqURI == "" {
			reqURI = c.Request.URL.EscapedPath()
			if c.Request.URL.RawQuery != "" {
				reqURI += "?" + c.Request.URL.RawQuery
			}
		} else if strings.HasPrefix(reqURI, "http://") || strings.HasPrefix(reqURI, "https://") {
			if u, err := url.ParseRequestURI(reqURI); err == nil {
				reqURI = u.RequestURI()
			}
		}
		if !strings.HasPrefix(reqURI, "/") {
			reqURI = "/" + reqURI
		}
		urlStr := "https://" + uc.Host + reqURI
		debugLogf("[%s] %s %s -> %s", clientIP, method, reqURI, urlStr)

		outReq, err := buildUpstreamRequest(c, uc, urlStr, cookiePriority)
		if err != nil {
			log.Printf("[%s] Failed to create request: %v", clientIP, err)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		// --- Step 3: Round-trip to upstream ---
		resp, err := proxyRoundTrip(outReq, uc.Mode, uc.IPMode)
		if err != nil {
			log.Printf("[%s] Upstream request failed: %v (elapsed: %v)", clientIP, err, time.Since(start))
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer resp.Body.Close()

		saveCookies(uc.Host, resp)
		debugLogf("[%s] <- %s (elapsed: %v)", clientIP, resp.Status, time.Since(start))

		// --- Step 4: Prepare response headers ---
		copyHeaders(c.Writer.Header(), resp.Header)
		cookieDomain := uc.CookieDomain
		if cookieDomain == "" {
			cookieDomain = host
		}
		rewriteSetCookieDomains(c.Writer.Header(), cookieDomain, c.Request.TLS == nil)
		ApplyHeaderRules(c.Writer.Header(), uc.ResponseHeaders, false, nil)
		syncJarCookiesToBrowser(c, uc.Host, cookieDomain, c.Request.TLS == nil, cookiePriority)

		port := ""
		if _, p, err := net.SplitHostPort(c.Request.Host); err == nil {
			port = p
		}
		rewriteRedirectHeaders(c.Writer.Header(), rewriter, port)

		// --- Step 5: SW fallback injection ---
		if swWant && !isJavascriptResponse(resp) {
			handleSWFallback(c, cfg, blocked, clientIP, method, rawPath)
			return
		}

		c.Status(resp.StatusCode)
		rc := http.NewResponseController(c.Writer)

		// --- Step 6: Stream / rewrite response body ---
		rewriteAndSendBody(c, uc, resp, rewriter, rc, clientIP, rawPath)
	}
}

// rewriteRedirectHeaders rewrites redirect headers (Location and Refresh):
// 1. Applies domain and port rewriting through rewriter.
// 2. Automatically upgrades any http:// scheme in redirects to https:// before sending to the client,
//    ensuring clients stay on secure HTTPS and preventing protocol downgrade / mixed content loops.
func rewriteRedirectHeaders(h http.Header, rewriter func([]byte, string) []byte, port string) {
	if loc := h.Get("Location"); loc != "" {
		if rewriter != nil {
			loc = string(rewriter([]byte(loc), port))
		}
		if len(loc) >= 7 && strings.EqualFold(loc[:7], "http://") {
			loc = "https://" + loc[7:]
		}
		h.Set("Location", loc)
	}
	if refresh := h.Get("Refresh"); refresh != "" {
		if rewriter != nil {
			refresh = string(rewriter([]byte(refresh), port))
		}
		if idx := strings.Index(strings.ToLower(refresh), "http://"); idx >= 0 {
			refresh = refresh[:idx] + "https://" + refresh[idx+7:]
		}
		h.Set("Refresh", refresh)
	}
}
