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
			log.Printf("[%s] Upstream config not found: %s", clientIP, host)
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
			log.Printf("[%s] Failed to create request: %v", clientIP, err)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		// 1. Save all cookies carried by client request (capturing new credentials written by frontend JS document.cookie)
		saveClientCookies(uc.Host, c.Request)

		// 2. Copy client request headers (stripping RFC hop-by-hop headers)
		copyHeaders(outReq.Header, c.Request.Header)

		// 3. Do not forge/inject X-Forwarded-For and X-Forwarded-Proto by default to prevent leaking proxy identity and real IP;
		// Client proxy tracking headers are stripped by default (unless explicitly configured in headers rules)
		if _, ok := uc.Headers["X-Forwarded-For"]; !ok {
			outReq.Header.Del("X-Forwarded-For")
		}
		if _, ok := uc.Headers["X-Forwarded-Proto"]; !ok {
			outReq.Header.Del("X-Forwarded-Proto")
		}

		// 4. Apply generic declarative request header rules (supports string override, {delete:true} stripping, {replace:[a,b]} substitution)
		ApplyHeaderRules(outReq.Header, uc.Headers, true, c.Request)

		outReq.Host = uc.Host
		outReq.ContentLength = c.Request.ContentLength

		// 5. Apply cookies (merging Jar + current client request cookies + local file/fixed cookies)
		fixedCookie := getFixedCookie(uc)
		applyCookies(uc.Host, outReq, fixedCookie)

		resp, err := proxyRoundTrip(outReq, uc.Mode)
		if err != nil {
			log.Printf("[%s] Upstream request failed: %v (elapsed: %v)", clientIP, err, time.Since(start))
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer resp.Body.Close()

		saveCookies(uc.Host, resp)

		debugLogf("[%s] <- %s (elapsed: %v)", clientIP, resp.Status, time.Since(start))

		copyHeaders(c.Writer.Header(), resp.Header)
		rewriteSetCookieDomains(c.Writer.Header(), host, c.Request.TLS == nil)

		// 6. Apply generic declarative response header rules (supports string override, {delete:true} stripping, {replace:[a,b]} substitution)
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
			debugLogf("[%s] %s %s -> SW fallback generated %d rules, %d wildcards, %d blocked", clientIP, method, rawPath, len(swProxyMap), len(swRules), len(blocked))
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
						debugLogf("[%s] %s -> HTML injected SW registration", clientIP, rawPath)
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
