package echproxy

import (
	"net/http"
	"os"
	"strconv"
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
	if content, err := os.ReadFile(filePath); err == nil && len(content) > 0 {
		return strings.TrimSpace(string(content))
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

// hasJarCookies checks whether cookieJar already contains any alive cookies for the host or its parent domains.
func hasJarCookies(host string) bool {
	cookieMu.Lock()
	defer cookieMu.Unlock()
	now := time.Now()
	for _, c := range cookieJar[host] {
		if isCookieAlive(c, now) {
			return true
		}
	}
	for _, d := range parentDomains(host) {
		for _, c := range cookieJar[d] {
			if isCookieAlive(c, now) {
				return true
			}
		}
	}
	return false
}

// parseCookieString parses both standard semicolon-separated "name=val; name2=val2" format
// and Netscape HTTP Cookie File format (tab-delimited lines).
func parseCookieString(raw string) map[string]string {
	result := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return result
	}

	// Netscape / newline-separated format
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

func readCookieFile(path string) string {
	filePath := path
	if strings.HasPrefix(filePath, "file://") {
		filePath = strings.TrimPrefix(filePath, "file://")
	}
	if content, err := os.ReadFile(filePath); err == nil {
		return strings.TrimSpace(string(content))
	}
	return path
}

// seedCookieRawLocked parses and inserts raw cookie content (either standard semicolon-separated
// or Netscape HTTP Cookie File format) into cookieJar. Must be called while holding cookieMu.
func seedCookieRawLocked(host, raw string, now time.Time) {
	if raw == "" {
		return
	}
	// 1. If Netscape HTTP Cookie File format (tab-separated lines)
	if strings.Contains(raw, "\n") {
		netscapeFound := false
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, "\t")
			if len(parts) >= 7 {
				domain := strings.TrimSpace(parts[0])
				includeSubdomains := strings.ToUpper(strings.TrimSpace(parts[1]))
				name := strings.TrimSpace(parts[5])
				val := strings.TrimSpace(parts[6])
				if name == "" {
					continue
				}
				exp := now.Add(30 * 24 * time.Hour)
				if expSec, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64); err == nil && expSec > 0 {
					exp = time.Unix(expSec, 0)
				}
				key := host
				if domain != "" {
					if strings.HasPrefix(domain, ".") || includeSubdomains == "TRUE" {
						key = "." + strings.TrimPrefix(domain, ".")
					} else {
						key = strings.TrimPrefix(domain, ".")
					}
				}
				saveOneCookieLocked(key, &http.Cookie{Name: name, Value: val, Expires: exp}, now)
				netscapeFound = true
			}
		}
		if netscapeFound {
			return
		}
	}

	// 2. Standard format (semicolon-separated or newline-separated key=val)
	parsed := parseCookieString(raw)
	for name, val := range parsed {
		c := &http.Cookie{Name: name, Value: val, Expires: now.Add(30 * 24 * time.Hour)}
		saveOneCookieLocked(host, c, now)
		for _, d := range parentDomains(host) {
			saveOneCookieLocked(d, c, now)
		}
		if !strings.HasPrefix(host, ".") && strings.Contains(host, ".") && len(parentDomains(host)) == 0 {
			saveOneCookieLocked("."+host, c, now)
		}
	}
}

// seedCookieRaw parses and seeds cookie content into cookieJar with mutex synchronization.
func seedCookieRaw(host, raw string) {
	if raw == "" {
		return
	}
	cookieMu.Lock()
	defer cookieMu.Unlock()
	seedCookieRawLocked(host, raw, time.Now())
}

// resetCookieJar resets the in-memory cookieJar (primarily used for unit testing).
func resetCookieJar() {
	cookieMu.Lock()
	defer cookieMu.Unlock()
	cookieJar = map[string][]*http.Cookie{}
}

// SeedCookiesFromConfig seeds initial cookies from all upstreams in Config (via cookie or cookie_file)
// into the in-memory cookieJar once at startup. Supports both standard format and Netscape HTTP Cookie File format.
// Because it seeds the jar only once:
// 1. Initial login credentials (like PHPSESSID) are available immediately on all subdomains.
// 2. Upstream Set-Cookie updates (like session rotation or new CF clearance) smoothly update
//    the jar without being repeatedly clobbered by static config on every request.
func SeedCookiesFromConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	cookieMu.Lock()
	defer cookieMu.Unlock()
	now := time.Now()

	for _, uc := range cfg.Upstreams {
		if raw := getFixedCookie(uc); raw != "" {
			seedCookieRawLocked(uc.Host, raw, now)
		}
		if uc.Wildcard != nil {
			w := uc.Wildcard
			raw := w.Cookie
			if raw == "" && w.CookieFile != "" {
				raw = readCookieFile(w.CookieFile)
			}
			if raw != "" {
				target := w.Host
				if target == "" {
					target = strings.TrimPrefix(w.UpstreamSuffix, ".")
				}
				seedCookieRawLocked(target, raw, now)
			}
		}
	}
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
