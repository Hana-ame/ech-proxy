// Package rewrite 负责 HTTP 请求头/响应头规则处理、CORS 跨域头设置、
// 响应体解压/重写/压缩、屏蔽域名剥离以及 Service Worker 动态脚本生成。
package rewrite

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
)

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

var (
	httpSchemePrefixRE  = regexp.MustCompile(`(?i)^http://`)
	refreshHTTPSchemeRE = regexp.MustCompile(`(?i)http://`)
)

func isCORSOrSecurityHeader(key string) bool {
	l := strings.ToLower(key)
	return strings.HasPrefix(l, "access-control-") ||
		strings.HasPrefix(l, "content-security-policy") ||
		l == "cross-origin-resource-policy" ||
		l == "cross-origin-opener-policy" ||
		l == "cross-origin-embedder-policy" ||
		l == "timing-allow-origin"
}

// CopyHeaders 拷贝 HTTP 头，自动剥离 RFC 2616 逐跳头与上游自带的 CORS/CSP 限制头。
func CopyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] || isCORSOrSecurityHeader(k) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ApplyCORSHeaders 为响应注入完整的跨域许可头。
func ApplyCORSHeaders(dst http.Header, req *http.Request) {
	var origin, reqHeaders string
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

// ApplyHeaderRules 将配置中的 HeaderRule（删除、正则替换、覆盖）应用到目标 http.Header。
func ApplyHeaderRules(h http.Header, rules map[string]config.HeaderRule, isRequest bool, clientReq *http.Request) {
	for k, rule := range rules {
		if rule.Delete {
			h.Del(k)
			continue
		}
		if len(rule.Replace) >= 2 {
			if cur := h.Get(k); cur != "" {
				if rule.CompiledReplace != nil {
					h.Set(k, rule.CompiledReplace.ReplaceAllString(cur, rule.Replace[1]))
				} else {
					h.Set(k, strings.ReplaceAll(cur, rule.Replace[0], rule.Replace[1]))
				}
			}
			continue
		}
		if rule.Value == "" {
			h.Del(k)
			continue
		}
		if isRequest && strings.EqualFold(k, "Origin") && clientReq != nil {
			if clientReq.Header.Get("Origin") != "" || (clientReq.Method != http.MethodGet && clientReq.Method != http.MethodHead) {
				h.Set(k, rule.Value)
			}
		} else {
			h.Set(k, rule.Value)
		}
	}
}

// ForceHTTPSURL 将任意以 http:// 开头的 URL 强制升级为 https://（修复 #23 静默降级 HTTP）。
func ForceHTTPSURL(raw string) string {
	return httpSchemePrefixRE.ReplaceAllString(strings.TrimSpace(raw), "https://")
}

// RewriteRedirectHeaders 改写所有 Location 和 Refresh 重定向头中的域名，并无条件将 http:// 升级为 https://（#23）。
func RewriteRedirectHeaders(h http.Header, rewriter func([]byte, string) []byte, port string) {
	if locs := h.Values("Location"); len(locs) > 0 {
		h.Del("Location")
		for _, loc := range locs {
			loc = ForceHTTPSURL(loc)
			if rewriter != nil {
				loc = string(rewriter([]byte(loc), port))
			}
			loc = ForceHTTPSURL(loc)
			h.Add("Location", loc)
		}
	}
	if refreshes := h.Values("Refresh"); len(refreshes) > 0 {
		h.Del("Refresh")
		for _, refresh := range refreshes {
			refresh = refreshHTTPSchemeRE.ReplaceAllString(refresh, "https://")
			if rewriter != nil {
				refresh = string(rewriter([]byte(refresh), port))
			}
			refresh = refreshHTTPSchemeRE.ReplaceAllString(refresh, "https://")
			h.Add("Refresh", refresh)
		}
	}
}
