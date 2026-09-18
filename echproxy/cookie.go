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

// parentDomains returns domain suffixes of host that contain at least one dot,
// e.g., "accounts.pixiv.net" -> [".pixiv.net"], "a.b.example.com" -> [".b.example.com", ".example.com"].
func parentDomains(host string) []string {
	var domains []string
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		domains = append(domains, "."+strings.Join(parts[i:], "."))
	}
	return domains
}

func saveOneCookieLocked(key string, c *http.Cookie, now time.Time) {
	jar := cookieJar[key]
	keep := make(map[string]*http.Cookie, len(jar)+1)
	for _, existing := range jar {
		if isCookieAlive(existing, now) {
			keep[existing.Name] = existing
		}
	}
	keep[c.Name] = c
	jar = jar[:0]
	for _, cookie := range keep {
		jar = append(jar, cookie)
	}
	cookieJar[key] = jar
}

// saveClientCookies saves all cookies carried by the client request (including values written by browser-side JS document.cookie)
// into the in-memory CookieJar for the corresponding host, preventing newly generated credentials from being lost.
func saveClientCookies(host string, req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	cookieMu.Lock()
	defer cookieMu.Unlock()

	now := time.Now()
	for _, c := range cookies {
		if c.Name == "" {
			continue
		}
		// Cookies sent by client requests typically lack Expires/MaxAge; assign default 30-day lifetime
		if c.Expires.IsZero() && c.MaxAge <= 0 {
			c.Expires = now.Add(30 * 24 * time.Hour)
		}
		saveOneCookieLocked(host, c, now)
	}
}

// saveCookies saves Set-Cookie headers from upstream responses into the CookieJar.
// If a cookie specifies a Domain attribute (e.g. Domain=.pixiv.net), it is stored under the domain key
// so that all subdomains sharing that parent domain can access it.
func saveCookies(host string, resp *http.Response) {
	sc := resp.Header.Values("Set-Cookie")
	if len(sc) == 0 {
		return
	}
	cookieMu.Lock()
	defer cookieMu.Unlock()

	now := time.Now()
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
		key := host
		if c.Domain != "" {
			d := strings.TrimPrefix(c.Domain, ".")
			if strings.Contains(d, ".") {
				key = "." + d
			}
		}
		saveOneCookieLocked(key, c, now)
	}
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

func collectAliveCookiesLocked(key string, now time.Time, merged map[string]string) {
	jar, ok := cookieJar[key]
	if !ok {
		return
	}
	alive := jar[:0]
	for _, c := range jar {
		if !isCookieAlive(c, now) {
			continue
		}
		alive = append(alive, c)
		merged[c.Name] = c.Value
	}
	if len(alive) == 0 {
		delete(cookieJar, key)
	} else {
		cookieJar[key] = alive
	}
}

// parseCookieString parses both standard semicolon-separated "name=val; name2=val2" format
// and Netscape HTTP Cookie File format (tab-delimited lines).
func parseCookieString(raw string) map[string]string {
	result := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return result
	}

	// Netscape / newline separated format
	if strings.Contains(raw, "\n") {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) >= 7 {
				name := strings.TrimSpace(parts[5])
				val := strings.TrimSpace(parts[6])
				if name != "" {
					result[name] = val
				}
				continue
			}
			// Line might be "name=val"
			if idx := strings.IndexByte(line, '='); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				val := strings.TrimSpace(line[idx+1:])
				val = strings.TrimRight(val, ";")
				if name != "" {
					result[name] = val
				}
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// Standard semicolon-separated format
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.IndexByte(part, '='); idx > 0 {
			name := strings.TrimSpace(part[:idx])
			val := strings.TrimSpace(part[idx+1:])
			if name != "" {
				result[name] = val
			}
		}
	}
	return result
}

// applyCookies performs a four-way merge among parent domain cookies, CookieJar for host,
// the current client request cookies, and local fixed/file cookies, writing them into the outgoing request.
func applyCookies(host string, req *http.Request, fixedCookie string) {
	cookieMu.Lock()
	now := time.Now()
	merged := map[string]string{}

	// 1. Merge domain-level cookies from parent domains of host (e.g. ".pixiv.net" for "www.pixiv.net")
	for _, d := range parentDomains(host) {
		collectAliveCookiesLocked(d, now, merged)
	}

	// 2. Merge host-specific cookies (e.g. "www.pixiv.net" overrides ".pixiv.net")
	collectAliveCookiesLocked(host, now, merged)
	cookieMu.Unlock()

	// Merge cookies from current request (if already in Jar, current latest request takes priority)
	for _, c := range req.Cookies() {
		merged[c.Name] = c.Value
	}

	// Merge fixed/local file cookies specified in config (highest priority, overrides previous same-named items)
	if fixedCookie != "" {
		for name, val := range parseCookieString(fixedCookie) {
			merged[name] = val
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
