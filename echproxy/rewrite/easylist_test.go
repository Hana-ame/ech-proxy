package rewrite

import (
	"strings"
	"testing"
)

func TestParseEasyListDeterministicSubset(t *testing.T) {
	raw := []byte(`[Adblock Plus 2.0]
! comment
||ads.example.com^
||tracker.example.org/pixel.gif
|https://cdn.example.net/ads.js
/banner/*/img^
@@||allowed.example.com^
||skip.example.com^$third-party
||rp.example.com^$removeparam=utm_source
||csp.example.com^$csp=script-src 'none'
||imp.example.com^$important
||bad.example.com^$badfilter
||deny.example.com^$denyallow=ok.example.com
##.generic-ad
example.com##.site-ad
~example.com##.negated-on-example
#@#.generic-except
example.com#@#.site-except
example.com#?#.proc:has-text(ad)
`)
	m := ParseEasyListNetworkRules(raw)

	blocks := []struct{ host, path string }{
		{"ads.example.com", "/"},
		{"sub.ads.example.com", "/x"},
		{"tracker.example.org", "/pixel.gif?a=1"},
		{"cdn.example.net", "/ads.js"},
		{"anything.test", "/banner/1/img"},
		{"rp.example.com", "/"},
		{"imp.example.com", "/"},
		{"deny.example.com", "/"},
	}
	for _, c := range blocks {
		if !m.ShouldBlock(c.host, c.path) {
			t.Errorf("should block %s%s", c.host, c.path)
		}
	}

	allowed := []struct{ host, path string }{
		{"allowed.example.com", "/"}, // @@ 例外
		{"skip.example.com", "/"},    // $third-party 近似规则 -> 整条丢弃
		{"bad.example.com", "/"},     // $badfilter -> 丢弃
		{"ok.example.com", "/"},      // $denyallow
		{"unrelated.example.net", "/"},
	}
	for _, c := range allowed {
		if m.ShouldBlock(c.host, c.path) {
			t.Errorf("should NOT block %s%s", c.host, c.path)
		}
	}

	if got := m.RemoveParamsFor("rp.example.com"); len(got) != 1 || got[0] != "utm_source" {
		t.Errorf("removeparam = %v, want [utm_source]", got)
	}
	if got := m.CSPFor("csp.example.com"); len(got) == 0 || !strings.Contains(got[0], "script-src") {
		t.Errorf("csp = %v, want script-src ...", got)
	}

	// cosmetic：通用 + 域限定，且 #@# 例外与 ~domain 排除在主域名及子域名上均生效；procedural 跳过
	for _, host := range []string{"example.com", "sub.example.com"} {
		cos := m.CosmeticFor(host)
		joined := strings.Join(cos, ",")
		if !strings.Contains(joined, ".generic-ad") || !strings.Contains(joined, ".site-ad") {
			t.Errorf("%s cosmetic missing selectors: %v", host, cos)
		}
		if strings.Contains(joined, ".generic-except") || strings.Contains(joined, ".site-except") || strings.Contains(joined, ".negated-on-example") {
			t.Errorf("%s cosmetic #@# or ~domain exception not applied: %v", host, cos)
		}
		if strings.Contains(joined, "has-text") {
			t.Errorf("procedural rule must be skipped: %v", cos)
		}
	}
	other := strings.Join(m.CosmeticFor("elsewhere.test"), ",")
	if !strings.Contains(other, ".generic-ad") || !strings.Contains(other, ".negated-on-example") || strings.Contains(other, ".site-ad") {
		t.Errorf("unrelated domain cosmetic wrong: %v", other)
	}
	if st := m.CosmeticStyle("example.com"); !strings.Contains(st, "ech-proxy-easylist-style") {
		t.Errorf("cosmetic style missing: %s", st)
	}
}

func TestStripMatchedURLsAndEscaped(t *testing.T) {
	m := ParseEasyListNetworkRules([]byte("||ads.example.com^\n||tracker.example.org/pixel.gif\n@@||allowed.example.com^\n"))
	html := []byte(`<html><body>
<script src="https://ads.example.com/x.js"></script>
<img src="//tracker.example.org/pixel.gif">
<script src="https://allowed.example.com/keep.js"></script>
<img src="https://cdn.ok.example/img.png">
</body></html>`)
	out, n := m.StripMatchedURLs(html)
	if n < 2 {
		t.Fatalf("expected >=2 stripped URLs, got %d", n)
	}
	s := string(out)
	if strings.Contains(s, "ads.example.com/x.js") || strings.Contains(s, "tracker.example.org/pixel.gif") {
		t.Errorf("ad URLs not stripped: %s", s)
	}
	if !strings.Contains(s, "allowed.example.com/keep.js") {
		t.Errorf("@@ exception URL must be kept: %s", s)
	}
	if !strings.Contains(s, "cdn.ok.example/img.png") {
		t.Errorf("unrelated URL must be kept: %s", s)
	}

	esc := []byte(`<script>(function(){var tpl="<\/script>";var s=document.createElement('script');s.src="\/\/ads.example.com\/x.js";})()</script>`)
	eout, en := m.StripEscapedURLs(esc)
	if en == 0 || strings.Contains(string(eout), "ads.example.com") {
		t.Errorf("escaped ad URL not stripped (n=%d): %s", en, string(eout))
	}
	if !strings.Contains(string(eout), `<\/script>`) {
		t.Errorf("StripEscapedURLs must not corrupt unrelated <\\/script> escapes in JS strings: %s", string(eout))
	}
}

func TestAdultScopedEasyListInjection(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled:       true,
		AdultSitesURL: "https://e/adult.txt",
		EasyListURL:   "https://e/easylist.txt",
		FetchFn: func(u string) ([]byte, error) {
			switch u {
			case "https://e/easylist.txt":
				return []byte("||ads.example.com^\n||tracker.example.org/pixel.gif\n##.ad-slot\n"), nil
			case "https://e/adult.txt":
				return []byte("adult.example.com\n"), nil
			default:
				return []byte(BuiltInAdScript), nil
			}
		},
	})
	if err := mgr.RefreshEasyListOnce(); err != nil {
		t.Fatalf("RefreshEasyListOnce: %v", err)
	}
	if al, err := mgr.RefreshAdultSitesOnce(); err != nil || len(al) != 1 {
		t.Fatalf("RefreshAdultSitesOnce: %v %v", al, err)
	}
	if !mgr.EasyListLoaded() {
		t.Fatal("EasyList should be loaded")
	}

	html := []byte(`<!DOCTYPE html><html><head></head><body><div class="ad-slot">x</div><script src="https://ads.example.com/x.js"></script></body></html>`)

	// adult 命中站点：剥离 EasyList 命中的 URL + 注入 cosmetic + 自有广告
	out := string(mgr.InjectIntoHTMLForHost(html, "adult.example.com"))
	if strings.Contains(out, "ads.example.com/x.js") {
		t.Errorf("adult site: EasyList-matched URL should be stripped: %s", out)
	}
	if !strings.Contains(out, "ech-proxy-easylist-style") || !strings.Contains(out, ".ad-slot") {
		t.Errorf("adult site: EasyList cosmetic style should be injected: %s", out)
	}
	if !strings.Contains(out, "slimgather.com") {
		t.Errorf("adult site: own ad script should be injected: %s", out)
	}

	// 非 adult 站点：完全不动
	untouched := mgr.InjectIntoHTMLForHost(html, "other.example.com")
	if string(untouched) != string(html) {
		t.Errorf("non-adult site must remain untouched, got: %s", unchanged(string(untouched)))
	}
}

func unchanged(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
