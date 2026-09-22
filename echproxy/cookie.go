package echproxy

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

func getCookiePriority(priority ...string) string {
	if len(priority) > 0 && priority[0] != "" {
		return strings.ToLower(strings.TrimSpace(priority[0]))
	}
	return "seed"
}

// saveClientCookies saves cookies carried by the client request into the in-memory CookieJar.
// When priority is "seed" (default), it preserves existing active jar credentials and only adds new keys.
// When priority is "browser", client request cookies can overwrite existing jar credentials.
func saveClientCookies(host string, req *http.Request, priority ...string) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	p := getCookiePriority(priority...)
	cookieMu.Lock()
	defer cookieMu.Unlock()

	now := time.Now()
	for _, c := range cookies {
		if c.Name == "" || strings.HasPrefix(c.Name, "_ech_") {
			continue
		}
		// Do not overwrite cookies already held and alive in jar for this host or its parent domains unless priority is browser
		if p != "browser" && isCookieInJarLocked(host, c.Name, now) {
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
		key := host
		if c.Domain != "" {
			d := strings.TrimPrefix(c.Domain, ".")
			if strings.Contains(d, ".") {
				key = "." + d
			}
		}
		// An expired/deleted cookie (Max-Age<=0 or past Expires) is an explicit instruction from
		// upstream to DROP the value. It must evict the matching jar entry, not merely be skipped:
		// keeping a stale session makes every later request replay a dead credential, so the
		// upstream treats the client as logged out forever (e.g. pixiv answers with a login
		// redirect whose return_to nests the whole URL, producing an endless redirect loop).
		if !isCookieAlive(c, now) {
			// Also evict from the request host: a value stored host-specifically for this
			// request must not survive just because the deletion carried a Domain attribute.
			deleteCookieLocked(host, c.Name, now)
			if key != host {
				deleteCookieLocked(key, c.Name, now)
			}
			continue
		}
		saveOneCookieLocked(key, c, now)
	}
}

// deleteCookieLocked removes any live jar entry with the given name under key (and, for a
// host key, under its parent domains) so an upstream deletion takes effect immediately.
// Must be called while holding cookieMu.
func deleteCookieLocked(key, name string, now time.Time) {
	if name == "" {
		return
	}
	keys := []string{key}
	if !strings.HasPrefix(key, ".") {
		keys = append(keys, parentDomains(key)...)
	}
	for _, k := range keys {
		jar, ok := cookieJar[k]
		if !ok {
			continue
		}
		alive := jar[:0]
		for _, existing := range jar {
			if existing.Name == name {
				continue
			}
			if isCookieAlive(existing, now) {
				alive = append(alive, existing)
			}
		}
		if len(alive) == 0 {
			delete(cookieJar, k)
		} else {
			cookieJar[k] = alive
		}
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

// isCookieInJarLocked reports whether cookieJar already contains an active cookie for name
// under host or any of its parent domains. Must be called while holding cookieMu.
func isCookieInJarLocked(host, name string, now time.Time) bool {
	for _, c := range cookieJar[host] {
		if c.Name == name && isCookieAlive(c, now) {
			return true
		}
	}
	for _, d := range parentDomains(host) {
		for _, c := range cookieJar[d] {
			if c.Name == name && isCookieAlive(c, now) {
				return true
			}
		}
	}
	return false
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
//     the jar without being repeatedly clobbered by static config on every request.
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
func applyCookies(host string, req *http.Request, fixedCookie string, priority ...string) {
	p := getCookiePriority(priority...)
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

	// 3. Merge client cookies:
	// If priority is "browser", client cookies override jar cookies (and empty/deleted values delete them).
	// Otherwise (default / "seed"), client cookies only supplement keys NOT already in jar.
	if p == "browser" {
		for _, c := range req.Cookies() {
			if strings.HasPrefix(c.Name, "_ech_") {
				continue
			}
			if c.Value == "" || c.Value == "deleted" {
				delete(merged, c.Name)
			} else {
				merged[c.Name] = c.Value
			}
		}
	} else {
		for _, c := range req.Cookies() {
			if strings.HasPrefix(c.Name, "_ech_") {
				continue
			}
			if _, exists := merged[c.Name]; !exists {
				merged[c.Name] = c.Value
			}
		}
	}

	// 4. Merge fixed/local file cookies specified in config (only in seed mode)
	if p != "browser" && fixedCookie != "" {
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


// syncJarCookiesToBrowser ensures critical session and preference cookies stored in cookieJar
// are synced to the browser via Set-Cookie headers under cookieDomain if the client
// is missing them or sent different (e.g. stale/guest) values.
func syncJarCookiesToBrowser(c *gin.Context, host, cookieDomain string, httpMode bool, priority ...string) {
	if cookieDomain == "" {
		return
	}
	if hh, _, err := net.SplitHostPort(cookieDomain); err == nil {
		cookieDomain = hh
	}
	cookieDomain = strings.TrimPrefix(cookieDomain, ".")

	p := getCookiePriority(priority...)
	// In browser mode, do not force-sync jar credentials back to the client.
	if p == "browser" {
		return
	}

	cookieMu.Lock()
	now := time.Now()
	jarCookies := map[string]string{}
	for _, d := range parentDomains(host) {
		collectAliveCookiesLocked(d, now, jarCookies)
	}
	collectAliveCookiesLocked(host, now, jarCookies)
	cookieMu.Unlock()

	if len(jarCookies) == 0 {
		return
	}

	clientCookies := map[string]string{}
	for _, ck := range c.Request.Cookies() {
		clientCookies[ck.Name] = ck.Value
	}

	secure := "; Secure"
	if httpMode {
		secure = ""
	}

	// Critical session and identity cookies that browser-side JS and navigation need:
	syncKeys := []string{"PHPSESSID", "device_token", "first_visit_datetime_pc", "yuid_b", "c_type"}
	for _, name := range syncKeys {
		jarVal, ok := jarCookies[name]
		if !ok || jarVal == "" {
			continue
		}
		clientVal, has := clientCookies[name]
		// In "seed" mode: sync if missing or differing from jar.
		if !has || clientVal != jarVal {
			c.Writer.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Domain=%s; Path=/; Max-Age=2592000; SameSite=Lax%s",
				name, jarVal, cookieDomain, secure))
		}
	}
}

// getEffectiveCookiePriority resolves whether "seed" or "browser" priority applies for the request.
// Priority resolution order:
// 1. Explicit URL parameter: ?_cookie_mode=seed or ?_cookie_mode=browser
// 2. Client cookie for exact entry: _ech_cookie_mode_<entry>=seed|browser
// 3. Client cookie for prefix (e.g. "pixiv" for "pixiv.l.moonchan.xyz" or "pixiv-accounts"): _ech_cookie_mode_<prefix>=seed|browser
// 4. Global client cookie: _ech_cookie_mode=seed|browser
// 5. Configured uc.CookiePriority ("seed" or "browser")
// 6. Default: if upstream has pre-configured cookie/cookie_file, default to "seed", otherwise "browser"
func getEffectiveCookiePriority(c *gin.Context, uc UpstreamConfig, entry string) string {
	if c != nil && c.Request != nil {
		if q := strings.ToLower(strings.TrimSpace(c.Query("_cookie_mode"))); q == "seed" || q == "browser" {
			return q
		}
		if val, err := c.Cookie("_ech_cookie_mode_" + entry); err == nil {
			val = strings.ToLower(strings.TrimSpace(val))
			if val == "seed" || val == "browser" {
				return val
			}
		}
		prefix := entry
		if idx := strings.Index(entry, "."); idx > 0 {
			prefix = entry[:idx]
		}
		if dashIdx := strings.Index(prefix, "-"); dashIdx > 0 {
			prefix = prefix[:dashIdx]
		}
		if prefix != "" {
			if val, err := c.Cookie("_ech_cookie_mode_" + prefix); err == nil {
				val = strings.ToLower(strings.TrimSpace(val))
				if val == "seed" || val == "browser" {
					return val
				}
			}
		}
		if val, err := c.Cookie("_ech_cookie_mode"); err == nil {
			val = strings.ToLower(strings.TrimSpace(val))
			if val == "seed" || val == "browser" {
				return val
			}
		}
	}

	if uc.CookiePriority != "" {
		return strings.ToLower(strings.TrimSpace(uc.CookiePriority))
	}
	if uc.Cookie != "" || uc.CookieFile != "" {
		return "seed"
	}
	return "browser"
}

// applyCookieModeSwitch modifies client cookies to activate either "seed" or "browser" mode for entry.
// In "seed" mode, it sets the mode cookie and pushes seed cookies to the browser.
// In "browser" mode, it sets the mode cookie and removes seed credentials from the browser.
func applyCookieModeSwitch(c *gin.Context, uc UpstreamConfig, entry, mode string) {
	cookieDomain := uc.CookieDomain
	if cookieDomain == "" {
		cookieDomain = entry
	}
	if hh, _, err := net.SplitHostPort(cookieDomain); err == nil {
		cookieDomain = hh
	}
	cookieDomain = strings.TrimPrefix(cookieDomain, ".")

	secure := "; Secure"
	if c.Request.TLS == nil {
		secure = ""
	}

	prefix := entry
	if idx := strings.Index(entry, "."); idx > 0 {
		prefix = entry[:idx]
	}
	if dashIdx := strings.Index(prefix, "-"); dashIdx > 0 {
		prefix = prefix[:dashIdx]
	}

	// Set mode tracking cookies on cookieDomain
	c.Writer.Header().Add("Set-Cookie", fmt.Sprintf("_ech_cookie_mode_%s=%s; Domain=%s; Path=/; Max-Age=31536000; SameSite=Lax%s",
		entry, mode, cookieDomain, secure))
	if prefix != entry && prefix != "" {
		c.Writer.Header().Add("Set-Cookie", fmt.Sprintf("_ech_cookie_mode_%s=%s; Domain=%s; Path=/; Max-Age=31536000; SameSite=Lax%s",
			prefix, mode, cookieDomain, secure))
	}

	rawCookie := getFixedCookie(uc)
	if rawCookie == "" {
		rawCookie = uc.Cookie
	}

	if mode == "seed" {
		if rawCookie != "" {
			seedCookieRaw(uc.Host, rawCookie)
			for name, val := range parseCookieString(rawCookie) {
				c.Writer.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; Domain=%s; Path=/; Max-Age=2592000; SameSite=Lax%s",
					name, val, cookieDomain, secure))
			}
		}
	} else if mode == "browser" {
		if rawCookie != "" {
			for name := range parseCookieString(rawCookie) {
				c.Writer.Header().Add("Set-Cookie", fmt.Sprintf("%s=; Domain=%s; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax%s",
					name, cookieDomain, secure))
			}
		}
	}
}

