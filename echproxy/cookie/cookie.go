// Package cookie 负责管理上游与客户端之间的 Cookie 注入、内存缓存与 Set-Cookie 域名改写。
// 本模块仅依赖 Go 标准库，不依赖项目内任何其他包。
package cookie

import (
	"net"
	"net/http"
	"os"
	"regexp"
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

// Jar 是线程安全的内存 Cookie 存储器，支持按主机名及父域名共享 Cookie。
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

// ReadFixedCookie 从配置值或本地文件路径读取预置 Cookie 内容。
func ReadFixedCookie(cookieVal, cookieFile string) string {
	val := cookieVal
	if cookieFile != "" {
		val = cookieFile
	}
	if val == "" {
		return ""
	}
	path := strings.TrimPrefix(val, "file://")
	if content, err := os.ReadFile(path); err == nil && len(content) > 0 {
		return strings.TrimSpace(string(content))
	}
	return val
}

// Seed 将配置中的静态 Cookie 字符串或 Netscape 格式 Cookie 文件播种到 Jar 中。
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

// SaveClientCookies 将浏览器请求携带的新 Cookie 存入 Jar。
func (j *Jar) SaveClientCookies(host string, req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for _, c := range cookies {
		if c.Name == "" || j.hasAliveLocked(host, c.Name, now) {
			continue
		}
		if c.Expires.IsZero() && c.MaxAge <= 0 {
			c.Expires = now.Add(30 * 24 * time.Hour)
		}
		j.saveOneLocked(host, c, now)
	}
}

// SaveResponseCookies 将上游响应的 Set-Cookie 存入 Jar。
func (j *Jar) SaveResponseCookies(host string, resp *http.Response) {
	scs := resp.Header.Values("Set-Cookie")
	if len(scs) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for _, s := range scs {
		c, err := http.ParseSetCookie(s)
		if err != nil {
			continue
		}
		if c.MaxAge > 0 && c.Expires.IsZero() {
			c.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		}
		if !isAlive(c, now) {
			continue
		}
		key := host
		if c.Domain != "" {
			if d := strings.TrimPrefix(c.Domain, "."); strings.Contains(d, ".") {
				key = "." + d
			}
		}
		j.saveOneLocked(key, c, now)
	}
}

// ApplyToRequest 合并父域 Cookie、当前主机 Jar Cookie、客户端 Cookie 与预置固定 Cookie 并写入请求头。
func (j *Jar) ApplyToRequest(host string, req *http.Request, fixedCookie string) {
	j.mu.Lock()
	now := time.Now()
	merged := make(map[string]string)
	for _, d := range parentDomains(host) {
		j.collectAliveLocked(d, now, merged)
	}
	j.collectAliveLocked(host, now, merged)
	j.mu.Unlock()

	for _, c := range req.Cookies() {
		if _, exists := merged[c.Name]; !exists && c.Name != "" {
			merged[c.Name] = c.Value
		}
	}
	if len(merged) == 0 && fixedCookie != "" {
		for k, v := range ParseCookieString(fixedCookie) {
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return
	}
	parts := make([]string, 0, len(merged))
	for k, v := range merged {
		parts = append(parts, k+"="+v)
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

func (j *Jar) hasAliveLocked(host, name string, now time.Time) bool {
	for _, c := range j.store[host] {
		if c.Name == name && isAlive(c, now) {
			return true
		}
	}
	for _, d := range parentDomains(host) {
		for _, c := range j.store[d] {
			if c.Name == name && isAlive(c, now) {
				return true
			}
		}
	}
	return false
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
