package echproxy

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// hopByHopHeaders are headers that must be stripped during proxy forwarding according to RFC 2616.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// isCORSOrSecurityHeader reports whether a header key is CORS or security-related
// and should be defined and managed exclusively by this proxy.
func isCORSOrSecurityHeader(key string) bool {
	l := strings.ToLower(key)
	return strings.HasPrefix(l, "access-control-") ||
		strings.HasPrefix(l, "content-security-policy") ||
		l == "cross-origin-resource-policy" ||
		l == "cross-origin-opener-policy" ||
		l == "cross-origin-embedder-policy" ||
		l == "timing-allow-origin"
}

// copyHeaders copies request/response headers from src to dst, stripping hop-by-hop headers
// and all upstream CORS/security headers so the proxy's full CORS policy always overrides them.
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if isHopByHop(k) || isCORSOrSecurityHeader(k) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ApplyCORSHeaders applies comprehensive CORS headers to dst based on req,
// explicitly overriding any original or conflicting CORS headers.
func ApplyCORSHeaders(dst http.Header, req *http.Request) {
	var origin string
	var reqHeaders string
	if req != nil {
		origin = req.Header.Get("Origin")
		reqHeaders = req.Header.Get("Access-Control-Request-Headers")
	}

	if origin != "" {
		dst.Set("Access-Control-Allow-Origin", origin)
		dst.Set("Access-Control-Allow-Credentials", "true")
		dst.Set("Vary", "Origin")
	} else {
		dst.Set("Access-Control-Allow-Origin", "*")
		dst.Del("Access-Control-Allow-Credentials")
	}

	dst.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")

	if reqHeaders != "" {
		dst.Set("Access-Control-Allow-Headers", reqHeaders)
	} else {
		dst.Set("Access-Control-Allow-Headers", "*")
	}

	dst.Set("Access-Control-Expose-Headers", "*, Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag, Last-Modified, Date, Cache-Control")
	dst.Set("Access-Control-Max-Age", "86400")
	dst.Set("Access-Control-Allow-Private-Network", "true")
	dst.Set("Cross-Origin-Resource-Policy", "cross-origin")
	dst.Set("Timing-Allow-Origin", "*")
}

// CORSMiddleware provides unified CORS handling for all responses served by the proxy:
// Dynamically reflects client Origin or provides wildcard origin, allows media/video streaming
// with range requests and exposes all headers, allowing any website to embed or fetch resources.
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ApplyCORSHeaders(c.Writer.Header(), c.Request)
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
		// Re-apply after handler execution to guarantee full CORS headers override
		// any headers set by downstream handlers before body writing.
		ApplyCORSHeaders(c.Writer.Header(), c.Request)
	}
}

var (
	setCookieHasDomainRE = regexp.MustCompile(`(?i);\s*Domain=`)
	setCookieReplaceRE   = regexp.MustCompile(`(?i);\s*Domain=[^;]*`)
	setCookieSecureRE    = regexp.MustCompile(`(?i);\s*Secure`)
)

// rewriteSetCookieDomains normalizes Set-Cookie headers in the response so browsers store them properly:
//  1. Upstream domain (e.g., Domain=.dlsite.com) -> rewritten to current proxy domain or shared cookie domain
//     (e.g., dlsite.l.moonchan.xyz or l.moonchan.xyz), otherwise the browser rejects cookies due to domain mismatch
//     -> frontend JS cannot read them -> popup loop.
//  2. Secure flag: upstream HTTPS sends Secure cookie, but if proxy runs in HTTP mode,
//     the browser will not store it (Secure cookies can only be sent over HTTPS), so it must be removed.
func rewriteSetCookieDomains(h http.Header, cookieDomain string, httpMode bool) {
	scs := h.Values("Set-Cookie")
	if len(scs) == 0 {
		return
	}
	h.Del("Set-Cookie")
	domain := cookieDomain
	if hh, _, err := net.SplitHostPort(cookieDomain); err == nil {
		domain = hh
	}
	domain = strings.TrimPrefix(domain, ".")
	hasDomain := setCookieHasDomainRE
	replaceDomain := setCookieReplaceRE
	secureRE := setCookieSecureRE
	for _, s := range scs {
		if hasDomain.MatchString(s) {
			s = replaceDomain.ReplaceAllString(s, "; Domain="+domain)
		}
		if httpMode {
			s = secureRE.ReplaceAllString(s, "")
		}
		h.Add("Set-Cookie", s)
	}
}

func isHopByHop(name string) bool {
	return hopByHopHeaders[http.CanonicalHeaderKey(name)]
}
