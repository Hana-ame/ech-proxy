package echproxy

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// hopByHopHeaders are headers that must be stripped during proxy forwarding according to RFC 2616.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// copyHeaders copies request/response headers from src to dst, stripping hop-by-hop headers and upstream CORS headers
// (CORS is defined by this proxy; passing upstream CORS through would cause duplicate conflicting headers with CORSMiddleware).
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		l := strings.ToLower(k)
		if isHopByHop(k) || strings.HasPrefix(l, "access-control-") ||
			strings.HasPrefix(l, "content-security-policy") {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// CORSMiddleware provides unified CORS handling for the reverse proxy:
// Dynamically reflects the client Origin and enables Allow-Credentials (allowing cookies / auth tokens),
// preventing the browser from blocking cross-subdomain API calls (e.g. iwara.l.moonchan.xyz -> iwara-api.l.moonchan.xyz).
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		} else {
			c.Header("Access-Control-Allow-Origin", "*")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
		if h := c.GetHeader("Access-Control-Request-Headers"); h != "" {
			c.Header("Access-Control-Allow-Headers", h)
		} else {
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Origin, X-Requested-With, Cache-Control, User-Agent, X-Site")
		}
		c.Header("Access-Control-Max-Age", "86400")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

var (
	setCookieHasDomainRE = regexp.MustCompile(`(?i);\s*Domain=`)
	setCookieReplaceRE   = regexp.MustCompile(`(?i);\s*Domain=[^;]*`)
	setCookieSecureRE    = regexp.MustCompile(`(?i);\s*Secure`)
)

// rewriteSetCookieDomains normalizes Set-Cookie headers in the response so browsers store them properly:
//  1. Upstream domain (e.g., Domain=.dlsite.com) -> rewritten to current proxy domain (dlsite.l.moonchan.xyz),
//     otherwise the browser rejects cookies due to domain mismatch -> frontend JS cannot read them -> popup loop.
//  2. Secure flag: upstream HTTPS sends Secure cookie, but if proxy runs in HTTP mode,
//     the browser will not store it (Secure cookies can only be sent over HTTPS), so it must be removed.
func rewriteSetCookieDomains(h http.Header, proxyHost string, httpMode bool) {
	scs := h.Values("Set-Cookie")
	if len(scs) == 0 {
		return
	}
	h.Del("Set-Cookie")
	domain := proxyHost
	if hh, _, err := net.SplitHostPort(proxyHost); err == nil {
		domain = hh
	}
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
	for _, h := range hopByHopHeaders {
		if http.CanonicalHeaderKey(name) == h {
			return true
		}
	}
	return false
}
