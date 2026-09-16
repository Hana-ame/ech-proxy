package echproxy

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// hopByHopHeaders 是需要按 RFC 2616 处理的逐跳头，转发时必须剔除。
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

// copyHeaders 复制 src 的请求/响应头到 dst，剔除逐跳头与上游 CORS 头
// （CORS 由本代理自定，透传会与 CORSMiddleware 产生重复冲突头）。
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

// CORSMiddleware 统一为反向代理提供 CORS 处理:
// 动态回显客户端 Origin 并开启 Allow-Credentials (允许携带 Cookie / 认证 Token),
// 避免客户端在子域间 (如 iwara.l.moonchan.xyz -> iwara-api.l.moonchan.xyz) 发起 API 请求时被浏览器 CORS 拦截。
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

// rewriteSetCookieDomains 把响应 Set-Cookie 头规范化, 让浏览器能正常存储:
//  1. Domain=.dlsite.com 等上游域 → 改写为当前代理域 (dlsite.l.moonchan.xyz),
//     否则浏览器因域不匹配拒绝存储 → 前端 JS 读不到 cookie → 弹窗无限循环。
//  2. Secure 标志: 上游 https 下发 Secure cookie, 若代理跑在 http 模式
//     浏览器不会存 (Secure cookie 只能经 https 传输), 需移除。
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
