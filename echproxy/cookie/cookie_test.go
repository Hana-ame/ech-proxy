package cookie

import (
	"net/http"
	"strings"
	"testing"
)

func TestJarEvictsDeletedAndExpiredResponseCookies(t *testing.T) {
	jar := NewJar()
	jar.Seed("www.pixiv.net", "PHPSESSID=old_session; theme=dark")

	// 上游返回 Set-Cookie: PHPSESSID=deleted; Max-Age=0
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"PHPSESSID=deleted; expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; path=/; domain=.pixiv.net",
			},
		},
	}
	jar.SaveResponseCookies("www.pixiv.net", resp)

	req, _ := http.NewRequest(http.MethodGet, "https://www.pixiv.net/", nil)
	jar.ApplyToRequest("www.pixiv.net", req, "")
	got := req.Header.Get("Cookie")
	if strings.Contains(got, "PHPSESSID") {
		t.Errorf("deleted PHPSESSID should have been evicted from Jar, but got Cookie: %q", got)
	}
	if !strings.Contains(got, "theme=dark") {
		t.Errorf("expected remaining cookie theme=dark, got %q", got)
	}
}

func TestCookiePriorityBrowserVsSeed(t *testing.T) {
	jar := NewJar()
	req, _ := http.NewRequest(http.MethodGet, "https://www.pixiv.net/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "from_browser"})

	// browser 优先级下，客户端 Cookie 胜出
	jar.ApplyToRequestWithPriority("www.pixiv.net", req, "token=from_seed; extra=1", "browser")
	if got := req.Header.Get("Cookie"); !strings.Contains(got, "token=from_browser") || !strings.Contains(got, "extra=1") {
		t.Errorf("browser priority got %q, want token=from_browser and extra=1", got)
	}

	// seed 优先级下，配置中的固定 Cookie 胜出
	req2, _ := http.NewRequest(http.MethodGet, "https://www.pixiv.net/", nil)
	req2.AddCookie(&http.Cookie{Name: "token", Value: "from_browser"})
	jar.ApplyToRequestWithPriority("www.pixiv.net", req2, "token=from_seed; extra=1", "seed")
	if got := req2.Header.Get("Cookie"); !strings.Contains(got, "token=from_seed") {
		t.Errorf("seed priority got %q, want token=from_seed", got)
	}
}

// TestParseSetCookieCompat 验证导出兼容解析器（issue #42），
// 确保 Go 1.21.4 降级编译路径不依赖 http.ParseSetCookie。
func TestParseSetCookieCompat(t *testing.T) {
	c, ok := ParseSetCookie("PHPSESSID=abc123; Path=/; Domain=.pixiv.net; Secure; HttpOnly; Max-Age=3600")
	if !ok || c == nil {
		t.Fatal("ParseSetCookie returned !ok")
	}
	if c.Name != "PHPSESSID" || c.Value != "abc123" || !c.Secure || !c.HttpOnly || c.MaxAge != 3600 {
		t.Errorf("unexpected parsed cookie: %+v", c)
	}
	if _, ok := ParseSetCookie("   "); ok {
		t.Error("empty Set-Cookie must parse as !ok")
	}
}
