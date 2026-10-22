// Package cookie 负责管理上游与客户端之间的 Cookie 注入、内存缓存、登出过期清理与 Set-Cookie 域名改写。
// 修复 #28：移除无鉴权控制面，并对 cookie_file 实施严格的受控目录校验，阻断任意文件读取外带风险。
package cookie

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	setCookieHasDomainRE = regexp.MustCompile(`(?i);\s*Domain=`)
	setCookieReplaceRE   = regexp.MustCompile(`(?i);\s*Domain=[^;]*`)
	setCookieSecureRE    = regexp.MustCompile(`(?i);\s*Secure`)
)

// Jar 是线程安全的内存 Cookie 存储器，支持按主机名及父域名共享 Cookie，并正确处理过期/登出删除。
type Jar struct {
	mu    sync.Mutex
	store map[string][]*http.Cookie
}

// DefaultJar 是全局默认的 CookieJar 实例。
var DefaultJar = NewJar()

func NewJar() *Jar {
	return &Jar{store: make(map[string][]*http.Cookie)}
}

func (j *Jar) Reset() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.store = make(map[string][]*http.Cookie)
}

// ReadFixedCookie 安全地获取预置 Cookie（修复 #28）：
//   - 若 cookieVal 是形如 "k=v" 的原始 Cookie 字符串，直接返回；
//   - 若通过 cookieFile 指定文件，仅允许读取受控 certs/ 目录下的纯文件名（禁止绝对路径、".." 路径穿越或任意系统路径读取）。
func ReadFixedCookie(cookieVal, cookieFile string) string {
	if cookieFile != "" {
		if content, ok := readSafeCookieFile(cookieFile); ok {
			return content
		}
		return ""
	}
	return strings.TrimSpace(cookieVal)
}

func readSafeCookieFile(rawPath string) (string, bool) {
	p := strings.TrimSpace(strings.TrimPrefix(rawPath, "file://"))
	if p == "" || filepath.IsAbs(p) || strings.Contains(p, "..") || strings.ContainsAny(p, `/\:`+"\r\n") {
		return "", false
	}
	clean := filepath.Clean(p)
	baseName := filepath.Base(clean)
	if baseName == "." || baseName == ".." || baseName != p {
		return "", false
	}
	for _, candidate := range []string{
		filepath.Join("certs", "l.moonchan.xyz", baseName),
		filepath.Join("..", "certs", "l.moonchan.xyz", baseName),
	} {
		if content, err := os.ReadFile(candidate); err == nil && len(content) > 0 {
			return strings.TrimSpace(string(content)), true
		}
	}
	return "", false
}

// Seed 将配置中的静态 Cookie 字符串或 Netscape 格式 Cookie 内容播种到 Jar 中。
func (j *Jar) Seed(host, raw string) {
	if raw == "" || host == "" {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()

	if strings.Contains(raw, "\n") {
		netscape := false
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) >= 7 && strings.TrimSpace(parts[5]) != "" {
				exp := now.Add(30 * 24 * time.Hour)
				if sec, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64); err == nil && sec > 0 {
					exp = time.Unix(sec, 0)
				}
				key := host
				if d := strings.TrimSpace(parts[0]); d != "" {
					if strings.HasPrefix(d, ".") || strings.EqualFold(strings.TrimSpace(parts[1]), "TRUE") {
						key = "." + strings.TrimPrefix(d, ".")
					} else {
						key = d
					}
				}
				j.saveOneLocked(key, &http.Cookie{
					Name:    strings.TrimSpace(parts[5]),
					Value:   strings.TrimSpace(parts[6]),
					Expires: exp,
				}, now)
				netscape = true
			}
		}
		if netscape {
			return
		}
	}

	for name, val := range ParseCookieString(raw) {
		c := &http.Cookie{Name: name, Value: val, Expires: now.Add(30 * 24 * time.Hour)}
		j.saveOneLocked(host, c, now)
		for _, d := range parentDomains(host) {
			j.saveOneLocked(d, c, now)
		}
	}
}

// SaveClientCookies 将浏览器请求携带的 Cookie 同步更新到 Jar。
func (j *Jar) SaveClientCookies(host string, req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		if c.Expires.IsZero() && c.MaxAge <= 0 {
			c.Expires = now.Add(30 * 24 * time.Hour)
		}
		j.saveOneLocked(host, c, now)
	}
}

// parseSetCookie 使用 Go 1.0+ 兼容的 (&http.Response{Header: ...}).Cookies() 解析单条 Set-Cookie，
// 避免依赖 Go 1.23+ 才引入的 http.ParseSetCookie，确保在 Go 1.20 / 1.21.4 及 go-win7 工具链下均可编译。
func parseSetCookie(raw string) (*http.Cookie, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	cookies := (&http.Response{Header: http.Header{"Set-Cookie": {raw}}}).Cookies()
	if len(cookies) == 0 || cookies[0] == nil {
		return nil, false
	}
	return cookies[0], true
}

// SaveResponseCookies 将上游响应的 Set-Cookie 存入 Jar；
// 若上游下发了过期/登出指令（Max-Age <= 0、Expires 已过期或值为 "deleted"），则主动从 Jar 中清除该 Cookie。
func (j *Jar) SaveResponseCookies(host string, resp *http.Response) {
	if resp == nil {
		return
	}
	scs := resp.Header.Values("Set-Cookie")
	if len(scs) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for _, s := range scs {
		c, ok := parseSetCookie(s)
		if !ok {
			continue
		}
		if c.MaxAge > 0 && c.Expires.IsZero() {
			c.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		}
		key := host
		if c.Domain != "" {
			if d := strings.TrimPrefix(c.Domain, "."); strings.Contains(d, ".") {
				key = "." + d
			}
		}
		// 检测上游显式删除/使 Cookie 过期的情形（如 Pixiv 登出或 Session 失效下发 PHPSESSID=deleted; Max-Age=0）
		if !isAlive(c, now) || strings.EqualFold(c.Value, "deleted") || c.Value == "" {
			j.deleteCookieLocked(host, key, c.Name)
			continue
		}
		j.saveOneLocked(key, c, now)
	}
}

// ApplyToRequest 默认以浏览器优先模式合并父域 Cookie、当前主机 Jar Cookie、客户端 Cookie 与预置固定 Cookie。
func (j *Jar) ApplyToRequest(host string, req *http.Request, fixedCookie string) {
	j.ApplyToRequestWithPriority(host, req, fixedCookie, "browser")
}

// ApplyToRequestWithPriority 按指定优先级策略（"browser" 或 "seed"）合并 Cookie 并写入请求头：
//   - "browser"（默认）：客户端请求携带的同名 Cookie 优先于 Jar/预置 Cookie，确保用户可在浏览器内正常登录/切换账号；
//   - "seed"：配置中的 fixedCookie 优先覆盖同名 Cookie。
func (j *Jar) ApplyToRequestWithPriority(host string, req *http.Request, fixedCookie, priority string) {
	j.mu.Lock()
	now := time.Now()
	merged := make(map[string]string)
	for _, d := range parentDomains(host) {
		j.collectAliveLocked(d, now, merged)
	}
	j.collectAliveLocked(host, now, merged)
	j.mu.Unlock()

	fixedMap := ParseCookieString(fixedCookie)
	if strings.EqualFold(priority, "seed") {
		for _, c := range req.Cookies() {
			if _, exists := merged[c.Name]; !exists && c.Name != "" {
				merged[c.Name] = c.Value
			}
		}
		for k, v := range fixedMap {
			merged[k] = v
		}
	} else {
		for k, v := range fixedMap {
			if _, exists := merged[k]; !exists {
				merged[k] = v
			}
		}
		for _, c := range req.Cookies() {
			if c.Name != "" {
				merged[c.Name] = c.Value
			}
		}
	}

	if len(merged) == 0 {
		return
	}
	names := make([]string, 0, len(merged))
	for k := range merged {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, k+"="+merged[k])
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
}

// RewriteSetCookieHeaders 将上游返回的 Set-Cookie Domain 改写为当前代理域名，并在 HTTP 模式下剥离 Secure 标记。
func RewriteSetCookieHeaders(h http.Header, cookieDomain string, httpMode bool) {
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
	for _, s := range scs {
		if setCookieHasDomainRE.MatchString(s) {
			s = setCookieReplaceRE.ReplaceAllString(s, "; Domain="+domain)
		}
		if httpMode {
			s = setCookieSecureRE.ReplaceAllString(s, "")
		}
		h.Add("Set-Cookie", s)
	}
}

// ParseCookieString 解析分号或换行分隔的 "k=v; k2=v2" 字符串。
func ParseCookieString(raw string) map[string]string {
	res := make(map[string]string)
	for _, part := range strings.FieldsFunc(strings.TrimSpace(raw), func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r'
	}) {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "#") {
			continue
		}
		if idx := strings.IndexByte(part, '='); idx > 0 {
			name := strings.TrimSpace(part[:idx])
			val := strings.TrimSpace(part[idx+1:])
			if name != "" {
				res[name] = val
			}
		}
	}
	return res
}

func (j *Jar) deleteCookieLocked(host, domainKey, name string) {
	keys := []string{host, domainKey, "." + strings.TrimPrefix(host, ".")}
	keys = append(keys, parentDomains(host)...)
	for _, k := range keys {
		list, ok := j.store[k]
		if !ok {
			continue
		}
		kept := list[:0]
		for _, c := range list {
			if c.Name != name {
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(j.store, k)
		} else {
			j.store[k] = kept
		}
	}
}

func (j *Jar) saveOneLocked(key string, c *http.Cookie, now time.Time) {
	list := j.store[key]
	keep := make(map[string]*http.Cookie, len(list)+1)
	for _, existing := range list {
		if isAlive(existing, now) {
			keep[existing.Name] = existing
		}
	}
	keep[c.Name] = c
	list = list[:0]
	for _, ck := range keep {
		list = append(list, ck)
	}
	j.store[key] = list
}

func (j *Jar) collectAliveLocked(key string, now time.Time, dst map[string]string) {
	list, ok := j.store[key]
	if !ok {
		return
	}
	alive := list[:0]
	for _, c := range list {
		if isAlive(c, now) {
			alive = append(alive, c)
			dst[c.Name] = c.Value
		}
	}
	if len(alive) == 0 {
		delete(j.store, key)
	} else {
		j.store[key] = alive
	}
}

func isAlive(c *http.Cookie, now time.Time) bool {
	return c.MaxAge >= 0 && (c.Expires.IsZero() || now.Before(c.Expires))
}

func parentDomains(host string) []string {
	var out []string
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		out = append(out, "."+strings.Join(parts[i:], "."))
	}
	return out
}