package echproxy

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	cookieMu  sync.Mutex
	cookieJar = map[string][]*http.Cookie{}
)

// saveClientCookies 将客户端请求携带的所有 Cookie (包含浏览器端 JS document.cookie 写入的值)
// 保存进对应 host 的内存 CookieJar 中，防止客户端通过 JS 产生的新凭证丢失。
func saveClientCookies(host string, req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	cookieMu.Lock()
	defer cookieMu.Unlock()

	jar := cookieJar[host]
	keep := make(map[string]*http.Cookie, len(jar)+len(cookies))
	now := time.Now()
	for _, c := range jar {
		if isCookieAlive(c, now) {
			keep[c.Name] = c
		}
	}
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		// 客户端请求带过来的 Cookie 通常不带 Expires/MaxAge，赋予默认 30 天有效期
		if c.Expires.IsZero() && c.MaxAge <= 0 {
			c.Expires = now.Add(30 * 24 * time.Hour)
		}
		keep[c.Name] = c
	}
	jar = jar[:0]
	for _, c := range keep {
		jar = append(jar, c)
	}
	cookieJar[host] = jar
}

// saveCookies 保存上游响应下发的 Set-Cookie 头到 CookieJar
func saveCookies(host string, resp *http.Response) {
	sc := resp.Header.Values("Set-Cookie")
	if len(sc) == 0 {
		return
	}
	cookieMu.Lock()
	defer cookieMu.Unlock()

	jar := cookieJar[host]
	keep := make(map[string]*http.Cookie, len(jar)+len(sc))
	now := time.Now()
	for _, c := range jar {
		if !isCookieAlive(c, now) {
			continue
		}
		keep[c.Name] = c
	}
	for _, s := range sc {
		c, err := http.ParseSetCookie(s)
		if err != nil {
			continue
		}
		if c.MaxAge > 0 && c.Expires.IsZero() {
			c.Expires = now.Add(time.Duration(c.MaxAge) * time.Second)
		}
		if !isCookieAlive(c, now) {
			continue
		}
		keep[c.Name] = c
	}
	if len(keep) == 0 {
		delete(cookieJar, host)
		return
	}
	jar = jar[:0]
	for _, c := range keep {
		jar = append(jar, c)
	}
	cookieJar[host] = jar
}

func isCookieAlive(c *http.Cookie, now time.Time) bool {
	if c.MaxAge < 0 {
		return false
	}
	if !c.Expires.IsZero() && now.After(c.Expires) {
		return false
	}
	return true
}

// getFixedCookie 读取上游配置中的固定 Cookie 或从本地文件载入。
// 支持在 json 中写固定字符串、file:// 前缀路径，或直接写绝对/相对路径。
func getFixedCookie(uc UpstreamConfig) string {
	cookieVal := uc.Cookie
	if uc.CookieFile != "" {
		cookieVal = uc.CookieFile
	}
	if cookieVal == "" {
		if r, ok := uc.Headers["Cookie"]; ok && r.Value != "" {
			cookieVal = r.Value
		}
	}
	if cookieVal == "" {
		return ""
	}
	filePath := cookieVal
	if strings.HasPrefix(filePath, "file://") {
		filePath = strings.TrimPrefix(filePath, "file://")
	}
	// 若以路径形式存在，尝试从本地文件读取
	if strings.HasPrefix(filePath, "/") || strings.HasPrefix(filePath, "./") || strings.HasPrefix(filePath, "../") || strings.HasPrefix(cookieVal, "file://") {
		if content, err := os.ReadFile(filePath); err == nil {
			return strings.TrimSpace(string(content))
		}
	}
	return cookieVal
}

// applyCookies 将 CookieJar (上游 Set-Cookie + 客户端 JS Cookie)、客户端当前请求 Cookie、
// 以及本地固定/文件 Cookie 进行三方合并，写入即将发往上游的请求中。
func applyCookies(host string, req *http.Request, fixedCookie string) {
	cookieMu.Lock()
	now := time.Now()
	merged := map[string]string{}
	alive := cookieJar[host][:0]
	for _, c := range cookieJar[host] {
		if !isCookieAlive(c, now) {
			continue
		}
		alive = append(alive, c)
		merged[c.Name] = c.Value
	}
	if len(alive) == 0 {
		delete(cookieJar, host)
	} else {
		cookieJar[host] = alive
	}
	cookieMu.Unlock()

	// 合并当前请求中的 Cookie (若 Jar 中已有，以当前最新请求优先)
	for _, c := range req.Cookies() {
		merged[c.Name] = c.Value
	}

	// 合并配置中指定的固定/本地文件 Cookie (最高优先级，覆盖前两者同名项)
	if fixedCookie != "" {
		// 尝试按 "name=val; name2=val2" 解析
		parts := strings.Split(fixedCookie, ";")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			idx := strings.IndexByte(part, '=')
			if idx > 0 {
				merged[part[:idx]] = part[idx+1:]
			}
		}
	}

	if len(merged) == 0 {
		return
	}
	parts := make([]string, 0, len(merged))
	for name, val := range merged {
		parts = append(parts, name+"="+val)
	}
	req.Header.Set("Cookie", strings.Join(parts, "; "))
}
