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
}

func TestEasyListNetworkBlockOnly_NoHTMLTampering(t *testing.T) {
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
				return []byte("// remote ads.js\nconsole.log('remote ad');"), nil
			}
		},
	})
	if _, err := mgr.RefreshOnce(); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if err := mgr.RefreshEasyListOnce(); err != nil {
		t.Fatalf("RefreshEasyListOnce: %v", err)
	}
	if al, err := mgr.RefreshAdultSitesOnce(); err != nil || len(al) != 1 {
		t.Fatalf("RefreshAdultSitesOnce: %v %v", al, err)
	}
	if !mgr.EasyListLoaded() {
		t.Fatal("EasyList should be loaded")
	}

	// 1. 网络层拦截验证 (domain + domain/path)
	if !mgr.ShouldBlockEasyList("ads.example.com", "/banner.js") {
		t.Errorf("expected ShouldBlockEasyList to return true for ads.example.com")
	}
	if !mgr.ShouldBlockEasyList("tracker.example.org", "/pixel.gif") {
		t.Errorf("expected ShouldBlockEasyList to return true for tracker.example.org/pixel.gif")
	}
	if mgr.ShouldBlockEasyList("adult.example.com", "/index.html") {
		t.Errorf("adult.example.com should not be blocked")
	}

	// 2. HTML 绝对不删除元素、不剥离 URL、不注入隐藏样式
	html := []byte(`<!DOCTYPE html><html><head></head><body><div class="ad-slot">x</div><script src="https://ads.example.com/x.js"></script></body></html>`)
	out := string(mgr.InjectIntoHTMLForHost(html, "adult.example.com"))

	if !strings.Contains(out, "https://ads.example.com/x.js") {
		t.Errorf("EasyList must NOT strip URLs from HTML body: %s", out)
	}
	if strings.Contains(out, "ech-proxy-easylist-style") {
		t.Errorf("EasyList must NOT inject cosmetic hiding CSS style: %s", out)
	}
	if !strings.Contains(out, `<div class="ad-slot">x</div>`) {
		t.Errorf("HTML elements must remain untouched: %s", out)
	}
	if !strings.Contains(out, "remote ad") {
		t.Errorf("own ad script should be injected before </body>: %s", out)
	}
}
