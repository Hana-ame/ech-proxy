package echproxy

import (
	"net/http"
	"testing"
	"time"
)

// resetJar clears the package-level CookieJar for a test.
func resetJar() {
	cookieMu.Lock()
	cookieJar = map[string][]*http.Cookie{}
	cookieMu.Unlock()
}

// jarNames returns the names currently held under key (test helper; caller must NOT hold cookieMu).
func jarNames(key string) []string {
	cookieMu.Lock()
	defer cookieMu.Unlock()
	var names []string
	for _, c := range cookieJar[key] {
		names = append(names, c.Name)
	}
	return names
}

// setCookieResp builds a response carrying a single Set-Cookie header.
func setCookieResp(v string) *http.Response {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", v)
	return resp
}

// TestUpstreamDeleteEvictsStaleCookie is the regression test for the pixiv endless-redirect bug.
//
// When upstream answers with an explicit deletion (`Max-Age=0`, or an Expires in the past), the
// CookieJar must drop the stored value. Previously such cookies were merely skipped, so a dead
// session stayed in the jar and was replayed on every later request; the upstream then treated
// the client as permanently logged out. Against pixiv that surfaced as a login redirect whose
// return_to nested the whole URL, producing ERR_TOO_MANY_REDIRECTS.
func TestUpstreamDeleteEvictsStaleCookie(t *testing.T) {
	cases := []struct {
		name string
		// where the stale value is stored first
		storeKey  string
		setCookie string
	}{
		{
			name:      "deletion with Domain evicts host-stored value",
			storeKey:  "www.pixiv.net",
			setCookie: "PHPSESSID=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; path=/; Domain=.pixiv.net; secure; HttpOnly",
		},
		{
			name:      "deletion without Domain evicts host-stored value",
			storeKey:  "www.pixiv.net",
			setCookie: "PHPSESSID=deleted; Max-Age=0; path=/",
		},
		{
			name:      "deletion with Domain evicts domain-stored value",
			storeKey:  ".pixiv.net",
			setCookie: "PHPSESSID=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; path=/; Domain=.pixiv.net; secure; HttpOnly",
		},
		{
			name:      "negative Max-Age evicts",
			storeKey:  "www.pixiv.net",
			setCookie: "PHPSESSID=deleted; Max-Age=-1; path=/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetJar()
			now := time.Now()
			cookieMu.Lock()
			saveOneCookieLocked(tc.storeKey, &http.Cookie{
				Name: "PHPSESSID", Value: "STALE_SESSION", Expires: now.Add(24 * time.Hour),
			}, now)
			cookieMu.Unlock()

			saveCookies("www.pixiv.net", setCookieResp(tc.setCookie))

			for _, key := range []string{"www.pixiv.net", ".pixiv.net"} {
				for _, n := range jarNames(key) {
					if n == "PHPSESSID" {
						t.Fatalf("stale PHPSESSID survived upstream deletion under key %q; "+
							"every later request would replay a dead session", key)
					}
				}
			}
		})
	}
}

// TestUpstreamDeleteKeepsOtherCookies guards against over-deletion: evicting one cookie must not
// disturb unrelated entries held for the same host.
func TestUpstreamDeleteKeepsOtherCookies(t *testing.T) {
	resetJar()
	now := time.Now()
	cookieMu.Lock()
	saveOneCookieLocked("www.pixiv.net", &http.Cookie{Name: "PHPSESSID", Value: "STALE", Expires: now.Add(time.Hour)}, now)
	saveOneCookieLocked("www.pixiv.net", &http.Cookie{Name: "keepme", Value: "keep", Expires: now.Add(time.Hour)}, now)
	cookieMu.Unlock()

	saveCookies("www.pixiv.net", setCookieResp("PHPSESSID=deleted; Max-Age=0; path=/; Domain=.pixiv.net"))

	found := false
	for _, n := range jarNames("www.pixiv.net") {
		if n == "PHPSESSID" {
			t.Fatal("PHPSESSID should have been evicted")
		}
		if n == "keepme" {
			found = true
		}
	}
	if !found {
		t.Fatal("unrelated cookie 'keepme' was wrongly removed")
	}
}

// TestUpstreamSetCookieStillStores confirms a normal (alive) Set-Cookie is still persisted, so the
// deletion fix did not disable ordinary jar writes.
func TestUpstreamSetCookieStillStores(t *testing.T) {
	resetJar()
	saveCookies("www.pixiv.net", setCookieResp("PHPSESSID=fresh123; Max-Age=3600; path=/; Domain=.pixiv.net"))

	found := false
	for _, n := range jarNames(".pixiv.net") {
		if n == "PHPSESSID" {
			found = true
		}
	}
	if !found {
		t.Fatal("a live Set-Cookie was not stored in the jar")
	}
}
