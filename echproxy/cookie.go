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

// saveClientCookies saves all cookies carried by the client request (including values written by browser-side JS document.cookie)
// into the in-memory CookieJar for the corresponding host, preventing newly generated credentials from being lost.
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
		// Cookies sent by client requests typically lack Expires/MaxAge; assign default 30-day lifetime
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

// saveCookies saves Set-Cookie headers from upstream responses into the CookieJar
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

// getFixedCookie reads fixed cookies from upstream config or loads them from a local file.
// Supports raw strings in JSON, file:// prefixed paths, or direct absolute/relative paths.
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
	// If it exists in path form, attempt to read from local file
	if strings.HasPrefix(filePath, "/") || strings.HasPrefix(filePath, "./") || strings.HasPrefix(filePath, "../") || strings.HasPrefix(cookieVal, "file://") {
		if content, err := os.ReadFile(filePath); err == nil {
			return strings.TrimSpace(string(content))
		}
	}
	return cookieVal
}

// applyCookies performs a three-way merge among CookieJar (upstream Set-Cookie + client JS cookies),
// the current client request cookies, and local fixed/file cookies, writing them into the outgoing request.
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

	// Merge cookies from current request (if already in Jar, current latest request takes priority)
	for _, c := range req.Cookies() {
		merged[c.Name] = c.Value
	}

	// Merge fixed/local file cookies specified in config (highest priority, overrides previous same-named items)
	if fixedCookie != "" {
		// Attempt to parse as "name=val; name2=val2"
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
