package rewrite

import (
	"errors"
	"testing"
)

var errTestFetch = errors.New("fetch failed")

func TestParseEasyListNetworkRulesSubset(t *testing.T) {
	raw := []byte(`[Adblock Plus 2.0]
! comment line
||ads.example.com^
||tracker.example.org/pixel.gif
|https://cdn.example.net/ads.js
/banner/*/img^
@@||exception.example.com^
||ignored.example.com^$third-party
example.com##.ad-slot
##.generic-ad
/regex[0-9]+/
||*.wild.example^
`)
	m := ParseEasyListNetworkRules(raw)

	if !m.Match("ads.example.com", "/") {
		t.Error("host-only rule ||ads.example.com^ should block")
	}
	if !m.Match("sub.ads.example.com", "/x") {
		t.Error("host-only rule should match subdomains (suffix)")
	}
	if !m.Match("tracker.example.org", "/pixel.gif?x=1") {
		t.Error("host+path rule should block matching path")
	}
	if !m.Match("cdn.example.net", "/ads.js") {
		t.Error("absolute URL rule |https://... should block")
	}
	if !m.Match("anything.test", "/banner/1/img") {
		t.Error("path-only rule /banner/*/img should block")
	}
	if m.Match("exception.example.com", "/") {
		t.Error("@@ exception rules must be skipped (not blocked)")
	}
	if m.Match("ignored.example.com", "/") {
		t.Error("rules with $options must be skipped")
	}
	if m.Match("example.com", "/ad-slot") {
		t.Error("cosmetic filters must not cause network blocking")
	}
	if m.Match("evil.test", "/regex123/") {
		t.Error("regex rules must be skipped")
	}
	if m.Match("wild.example", "/") {
		t.Error("wildcard host rules must be skipped")
	}
}

func TestParseAdsAllowlistTextMultiLine(t *testing.T) {
	raw := []byte(`# ads.txt: 只放行精确的 host/path
slimgather.com/csDz9.6gbv2Z5-leSgWTQ_9ENDzeU-zQNkzlESwaNbSZ0f3cNtT/Mu3DMNTnAX5i
https://fussyreturn.com/b/XZV.sFdDG/la0SYyWHcX/XeNmw9BufZNUql/kTPKTjcs1XMmzbcIxZM-jSEjtSN/z_UZz/NtzPEOy-NaQl
//proto.example.com/p.js
bare.example.com
wrapped.example.com
/path/to/script.js
folded.example.com/a/b/\
c/d.js
`)
	rules := ParseAdsAllowlistText(raw)

	// 精确路径放行
	if !Allows(rules, "slimgather.com", "/csDz9.6gbv2Z5-leSgWTQ_9ENDzeU-zQNkzlESwaNbSZ0f3cNtT/Mu3DMNTnAX5i") {
		t.Error("exact ads.txt path should be allowed")
	}
	// 同域但不同路径绝不放行（防止放出同域其他人的广告）
	if Allows(rules, "slimgather.com", "/some/other/ad.js") {
		t.Error("same host but different path must NOT be allowed")
	}
	if !Allows(rules, "fussyreturn.com", "/b/XZV.sFdDG/la0SYyWHcX/XeNmw9BufZNUql/kTPKTjcs1XMmzbcIxZM-jSEjtSN/z_UZz/NtzPEOy-NaQl") {
		t.Error("https:// entry should be allowed")
	}
	if !Allows(rules, "proto.example.com", "/p.js") {
		t.Error("protocol-relative entry should be allowed")
	}
	// 裸域名行被忽略
	if Allows(rules, "bare.example.com", "/anything") {
		t.Error("bare-domain entry must be ignored (no domain-level allow)")
	}
	// 折行：域名一行 + /path 下一行
	if !Allows(rules, "wrapped.example.com", "/path/to/script.js") {
		t.Error("wrapped entry should be joined and allowed")
	}
	// 反斜杠续行
	if !Allows(rules, "folded.example.com", "/a/b/c/d.js") {
		t.Error("backslash-continued entry should be allowed")
	}
}

func TestShouldBlockEasyListPrecedence(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		FetchFn: func(u string) ([]byte, error) {
			switch u {
			case DefaultEasyListURL:
				return []byte("||ads.example.com^\n||tracker.example.org/pixel.gif\n||slimgather.com^\n"), nil
			case DefaultAdsAllowlistURL:
				return []byte("slimgather.com/csDz9.6gbv2Z5-leSgWTQ_9ENDzeU-zQNkzlESwaNbSZ0f3cNtT/Mu3DMNTnAX5i\n"), nil
			default:
				return []byte(BuiltInAdScript), nil
			}
		},
	})
	if _, err := mgr.RefreshEasyListOnce(); err != nil {
		t.Fatalf("RefreshEasyListOnce: %v", err)
	}
	if _, err := mgr.RefreshAdsAllowlistOnce(); err != nil {
		t.Fatalf("RefreshAdsAllowlistOnce: %v", err)
	}
	if !mgr.EasyListBlockingEnabled() {
		t.Fatal("EasyList blocking should be enabled with ads.txt present")
	}
	if !mgr.ShouldBlockEasyList("ads.example.com", "/ad.js") {
		t.Error("EasyList host rule should block")
	}
	if !mgr.ShouldBlockEasyList("tracker.example.org", "/pixel.gif") {
		t.Error("EasyList path rule should block")
	}
	// 精确放行的那条不拦
	if mgr.ShouldBlockEasyList("slimgather.com", "/csDz9.6gbv2Z5-leSgWTQ_9ENDzeU-zQNkzlESwaNbSZ0f3cNtT/Mu3DMNTnAX5i") {
		t.Error("exact ads.txt path must be allowed")
	}
	// 同域其他路径仍要拦（防止放出同域其他人的广告）
	if !mgr.ShouldBlockEasyList("slimgather.com", "/other/ad.js") {
		t.Error("same host but different path must still be blocked")
	}
	if mgr.ShouldBlockEasyList("github.com", "/") {
		t.Error("unrelated host must not be blocked")
	}
}

func TestShouldBlockEasyListDisabledWithoutAdsTxt(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		FetchFn: func(u string) ([]byte, error) {
			if u == DefaultEasyListURL {
				return []byte("||ads.example.com^\n"), nil
			}
			return nil, errTestFetch
		},
	})
	_, _ = mgr.RefreshEasyListOnce()
	_, _ = mgr.RefreshAdsAllowlistOnce() // ads.txt 拉不到 -> 无放行清单
	if mgr.EasyListBlockingEnabled() {
		t.Error("without ads.txt, EasyList blocking must stay disabled")
	}
	if mgr.ShouldBlockEasyList("ads.example.com", "/") {
		t.Error("without ads.txt nothing may be blocked")
	}
}

func TestShouldBlockEasyListRequiresMatcher(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		FetchFn: func(u string) ([]byte, error) { return []byte(BuiltInAdScript), nil },
	})
	// 未刷新 EasyList -> 无 matcher -> 一律不拦（安全默认）
	if mgr.ShouldBlockEasyList("ads.example.com", "/") {
		t.Error("without EasyList matcher nothing should be blocked")
	}
}
