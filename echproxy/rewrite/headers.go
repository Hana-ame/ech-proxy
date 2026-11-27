// Package rewrite 负责 HTTP 请求头/响应头规则处理、CORS 跨域头设置、
// 响应体解压/重写/压缩、屏蔽域名剥离以及 Service Worker 动态脚本生成。
package rewrite

import (
	"net"
	"net/http"
	"net/url"
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
	if strings.HasPrefix(l, "access-control-request-") {
		return false
	}
	return strings.HasPrefix(l, "access-control-") ||
		strings.HasPrefix(l, "content-security-policy") ||
		l == "cross-origin-resource-policy" ||
		l == "cross-origin-opener-policy" ||
		l == "cross-origin-embedder-policy" ||
		l == "timing-allow-origin"
}

// CopyRawHeaders 纯透传拷贝 HTTP 头，仅剥离 RFC 2616 逐跳传输头，
// 完整保留请求与响应中的所有原始业务头（含 Cookie、Set-Cookie、Location、CSP、COOP/COEP/CORP 与 CORS 头）。
// 专用于 PAC / 443 原域名模式的完全透传。
func CopyRawHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// CopyHeaders 拷贝 HTTP 头（用于 8443 门户模式），自动剥离 RFC 2616 逐跳头与上游自带的响应侧 CORS/CSP 限制头。
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

func appendVaryHeader(dst http.Header, token string) {
	existing := dst.Values("Vary")
	tokens := make([]string, 0, len(existing)+1)
	hasToken := false
	for _, v := range existing {
		for _, part := range strings.Split(v, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			if p == "*" {
				dst.Set("Vary", "*")
				return
			}
			found := false
			for _, t := range tokens {
				if strings.EqualFold(t, p) {
					found = true
					break
				}
			}
			if !found {
				tokens = append(tokens, p)
			}
			if strings.EqualFold(p, token) {
				hasToken = true
			}
		}
	}
	if !hasToken {
		tokens = append(tokens, token)
	}
	dst.Set("Vary", strings.Join(tokens, ", "))
}

// normalizeHostPort 归一化 "host:port" 用于同源相等比较：小写化、剥离 IPv6 方括号、
// 并把 80/443 视为默认端口省略。只用于比较，不要求输出是合法的 host:port 字面量。
func normalizeHostPort(hp string) string {
	hp = strings.ToLower(strings.TrimSpace(hp))
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return strings.TrimSuffix(strings.Trim(hp, "[]"), ":")
	}
	h = strings.Trim(h, "[]")
	if p == "80" || p == "443" {
		return h
	}
	return h + ":" + p
}

// sameOriginHost 判断 Origin 头是否与请求的 Host 同源（忽略 scheme，只比 host:port）。
// "null"（sandbox iframe / file:// 的不透明源）与解析失败一律按时跨源处理。
func sameOriginHost(origin, reqHost string) bool {
	if origin == "" || reqHost == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return normalizeHostPort(u.Host) == normalizeHostPort(reqHost)
}

// ApplyCORSHeaders 为响应注入跨域许可头（仅用于 8443 门户模式与本地管理端点）。
//
// 安全约束：绝不反射任意 Origin。早期实现对任意 Origin 都回写 Access-Control-Allow-Origin
// 并附带 Allow-Credentials: true，同时无条件打开 Access-Control-Allow-Private-Network。
// 结果是任意公网页面都能从浏览器直接 fetch http://127.0.0.1:8443/debug/log 或 /statusz，
// 读出完整代理日志（含用户访问过的全部 URL）与运行状态，用户无需任何操作。
//
// 现在仅对同源 Origin 发放带凭据的许可：跨源请求拿不到 Allow-Origin，浏览器直接拒绝读取；
// 同源请求浏览器本就不校验 CORS 头，功能不受影响。
func ApplyCORSHeaders(dst http.Header, req *http.Request) {
	var origin, reqHeaders, reqHost string
	if req != nil {
		origin = req.Header.Get("Origin")
		reqHeaders = req.Header.Get("Access-Control-Request-Headers")
		reqHost = req.Host
	}
	switch {
	case origin != "" && !sameOriginHost(origin, reqHost):
		// 跨源：不发放读取许可，也不声明允许凭据。
		dst.Del("Access-Control-Allow-Origin")
		dst.Del("Access-Control-Allow-Credentials")
	case origin != "":
		dst.Set("Access-Control-Allow-Origin", origin)
		dst.Set("Access-Control-Allow-Credentials", "true")
		appendVaryHeader(dst, "Origin")
	default:
		// 无 Origin：导航请求或同源请求，浏览器不校验 CORS 头，保持无凭据通配即可。
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
	// 明确清除 PNA 许可：它允许公网页面通过预检直连本机端口，与上面的同源约束冲突。
	// 若上游自行下发该头，这里也要覆盖掉（本函数是管理端点/门户响应的最终裁定方）。
	dst.Del("Access-Control-Allow-Private-Network")
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
