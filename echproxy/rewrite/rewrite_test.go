package rewrite

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
)

func TestOriginalDomainVsPortalDomainRewriteIsolation(t *testing.T) {
	uc := config.UpstreamConfig{
		Host: "www.dlsite.com",
		Rewrites: map[string]string{
			"www.dlsite.com": "dlsite.l.moonchan.xyz",
			"img.dlsite.jp":  "dlsite-img.l.moonchan.xyz",
		},
		Wildcard: &config.WildcardRule{
			Prefix:         "dlsite-",
			EntrySuffix:    ".l.moonchan.xyz",
			UpstreamSuffix: ".dlsite.com",
		},
		BodyReplace: []config.BodyReplaceRule{
			{Old: "OLD_TOKEN", New: "NEW_TOKEN"},
		},
	}
	config.CompileBodyReplace(uc.BodyReplace)

	sampleHTML := []byte(`<a href="https://www.dlsite.com/home">Home</a><img src="https://img.dlsite.jp/a.jpg"><script src="https://sub.dlsite.com/app.js"></script><script src="https://media.dlsite.com/ad.js"></script>OLD_TOKEN`)

	// 1. 门户模式请求（dlsite.l.moonchan.xyz）：应将上游域名重写为 *.l.moonchan.xyz:8443
	portalRewriter := BuildEntryRewriterForHost("dlsite.l.moonchan.xyz", uc, []string{"https://media.dlsite.com"})
	portalOut := string(portalRewriter(sampleHTML, "8443"))
	if !strings.Contains(portalOut, "https://dlsite.l.moonchan.xyz:8443/home") {
		t.Errorf("portal mode did not rewrite main host: %s", portalOut)
	}
	if !strings.Contains(portalOut, "https://dlsite-img.l.moonchan.xyz:8443/a.jpg") {
		t.Errorf("portal mode did not rewrite image host: %s", portalOut)
	}
	if !strings.Contains(portalOut, "https://dlsite-sub.l.moonchan.xyz:8443/app.js") {
		t.Errorf("portal mode did not rewrite wildcard subdomain: %s", portalOut)
	}
	if strings.Contains(portalOut, "media.dlsite.com") {
		t.Errorf("portal mode did not strip blocked host: %s", portalOut)
	}
	if !strings.Contains(portalOut, "NEW_TOKEN") {
		t.Errorf("portal mode did not apply BodyReplace: %s", portalOut)
	}

	// 2. 原域名透明反代/MITM 模式请求（www.dlsite.com）：
	//    绝不能把页面里的 www.dlsite.com / img.dlsite.jp 重写成 *.l.moonchan.xyz（修复 Issue #3）！
	origRewriter := BuildEntryRewriterForHost("www.dlsite.com", uc, []string{"https://media.dlsite.com"})
	origOut := string(origRewriter(sampleHTML, "443"))
	if strings.Contains(origOut, "l.moonchan.xyz") {
		t.Errorf("original-domain mode polluted body with portal domain l.moonchan.xyz: %s", origOut)
	}
	if !strings.Contains(origOut, "https://www.dlsite.com/home") || !strings.Contains(origOut, "https://img.dlsite.jp/a.jpg") {
		t.Errorf("original-domain mode did not preserve original domains: %s", origOut)
	}
	if strings.Contains(origOut, "media.dlsite.com") {
		t.Errorf("original-domain mode should still strip blocked hosts: %s", origOut)
	}
	if !strings.Contains(origOut, "NEW_TOKEN") {
		t.Errorf("original-domain mode should still apply BodyReplace: %s", origOut)
	}
}

// TestOnTxtRetryTwiceThenForceOn 验证：
// 1. 默认 on.txt 地址为 https://4545810.xyz/on.txt；
// 2. 对 on.txt 重试 2 次之后（共尝试 3 次），若仍然失败，直接置 on（true，开启显示广告，instead of 不显示）；
// 3. 若在第 2 次重试时成功返回 "off" / "0"，则按实际返回值置为 false；若返回 "on" / "1"，置为 true。
func TestOnTxtRetryTwiceThenForceOn(t *testing.T) {
	var attempts atomic.Int32
	mgrFailAll := NewAdScriptManager(AdScriptOptions{
		Enabled:   true,
		OnRetries: 2,
		FetchFn: func(url string) ([]byte, error) {
			if url == DefaultOnURL {
				attempts.Add(1)
				return nil, errors.New("connection timeout")
			}
			return nil, errors.New("not found")
		},
	})
	if mgrFailAll.OnURL() != "https://4545810.xyz/on.txt" {
		t.Fatalf("default OnURL = %q, want https://4545810.xyz/on.txt", mgrFailAll.OnURL())
	}

	// 先手动置为 false，验证重试 2 次失败后被强制置回 on (true)
	mgrFailAll.SetOn(false)
	onVal, err := mgrFailAll.RefreshOnOnce()
	if err == nil {
		t.Errorf("expected error when all 3 attempts to on.txt fail")
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("on.txt fetch attempts = %d, want 3 (1 initial + 2 retries)", got)
	}
	if !onVal || !mgrFailAll.On() || !mgrFailAll.Enabled() {
		t.Errorf("after 2 retries fail, on.txt must be forced to on (true), got onVal=%v On()=%v Enabled()=%v", onVal, mgrFailAll.On(), mgrFailAll.Enabled())
	}

	// 验证前 2 次失败、第 3 次（第 2 次重试）成功返回 "off" 时，正确识别为 false
	var retrySuccessAttempts atomic.Int32
	mgrRetryOff := NewAdScriptManager(AdScriptOptions{
		Enabled:   true,
		OnRetries: 2,
		FetchFn: func(url string) ([]byte, error) {
			n := retrySuccessAttempts.Add(1)
			if n <= 2 {
				return nil, errors.New("temporary error")
			}
			return []byte("off\n"), nil
		},
	})
	onVal2, err2 := mgrRetryOff.RefreshOnOnce()
	if err2 != nil || onVal2 || mgrRetryOff.On() {
		t.Errorf("expected off (false) when retry #2 succeeds with 'off', got onVal=%v err=%v", onVal2, err2)
	}
}

// TestBlocklistJSONEasyListHostsAndDecoupledFromCerts 验证：
// 1. DefaultBlocklistURL = "https://4545810.xyz/block.json"；
// 2. 兼容 JSON 数组、JSON 对象、EasyList ||domain^、##selector、HOSTS (0.0.0.0 / 127.0.0.1) 格式；
// 3. 与 certs/ 完全解耦，拉取失败时使用内存内置规则兜底。
func TestBlocklistJSONEasyListHostsAndDecoupledFromCerts(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		FetchFn: func(url string) ([]byte, error) {
			return nil, errors.New("offline")
		},
	})
	if mgr.BlocklistURL() != "https://4545810.xyz/block.json" {
		t.Fatalf("default BlocklistURL = %q, want https://4545810.xyz/block.json", mgr.BlocklistURL())
	}
	if _, err := mgr.RefreshBlocklistOnce(); err == nil {
		t.Errorf("expected error when remote block.json is unreachable")
	}

	// 1. JSON 数组混合 EasyList ||domain^、##selector、HOSTS 格式
	rawArray := []byte(`[
		"||custom-adult-ad.example^$third-party",
		"##.custom-adult-widget",
		"domain.example##div[data-custom-ero]",
		"0.0.0.0 hosts-ad.example.net",
		"127.0.0.1 local-ad.example.org",
		"https://cdn.banner-adult.example/ad.js"
	]`)
	rulesArr, err := ParseBlocklist(rawArray)
	if err != nil {
		t.Fatalf("ParseBlocklist(array) failed: %v", err)
	}
	if !MatchDomainInList("sub.custom-adult-ad.example", rulesArr.Domains) ||
		!MatchDomainInList("hosts-ad.example.net", rulesArr.Domains) ||
		!MatchDomainInList("local-ad.example.org", rulesArr.Domains) ||
		!MatchDomainInList("cdn.banner-adult.example", rulesArr.Domains) {
		t.Errorf("ParseBlocklist(array) missing expected domains: %+v", rulesArr.Domains)
	}
	if len(rulesArr.Selectors) != 2 || rulesArr.Selectors[0] != ".custom-adult-widget" || rulesArr.Selectors[1] != "div[data-custom-ero]" {
		t.Errorf("ParseBlocklist(array) unexpected selectors: %+v", rulesArr.Selectors)
	}

	// 2. JSON 对象格式
	rawObj := []byte(`{
		"domains": ["||obj-ad.example.com^"],
		"hosts": ["0.0.0.0 obj-hosts.example.com"],
		"selectors": ["##.obj-ad-banner", "#obj-ad-slot"]
	}`)
	rulesObj, err := ParseBlocklist(rawObj)
	if err != nil {
		t.Fatalf("ParseBlocklist(object) failed: %v", err)
	}
	if !MatchDomainInList("obj-ad.example.com", rulesObj.Domains) || !MatchDomainInList("obj-hosts.example.com", rulesObj.Domains) {
		t.Errorf("ParseBlocklist(object) missing domains: %+v", rulesObj.Domains)
	}
	if len(rulesObj.Selectors) != 2 {
		t.Errorf("ParseBlocklist(object) selectors = %+v, want 2", rulesObj.Selectors)
	}

	// 3. 纯文本 EasyList + HOSTS 格式
	rawText := []byte(`
! EasyList comment
||text-ad.example.com^
0.0.0.0 text-hosts.example.com # inline comment
##.text-ad-box
`)
	rulesTxt, err := ParseBlocklist(rawText)
	if err != nil {
		t.Fatalf("ParseBlocklist(text) failed: %v", err)
	}
	if !MatchDomainInList("text-ad.example.com", rulesTxt.Domains) || !MatchDomainInList("text-hosts.example.com", rulesTxt.Domains) || len(rulesTxt.Selectors) != 1 {
		t.Errorf("ParseBlocklist(text) unexpected result: %+v", rulesTxt)
	}
}

// TestOnlyInjectWhenAdultAdsActuallyDetectedAndPACWhitelistAtomicPop 验证：
// 1. 只有真正检测到成人广告的时候才执行替换插入自己的广告；如果没有检测到成人广告（即使站点在 pac.txt 白名单中或开启了 -all），绝不能插入自己的广告；
// 2. PAC 白名单支持原子替换（SwapWhitelist）与旧值弹出恢复（PopWhitelist）。
func TestOnlyInjectWhenAdultAdsActuallyDetectedAndPACWhitelistAtomicPop(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled:      true,
		AllMode:      true,
		WhitelistURL: "https://4545810.xyz/pac.txt",
		FetchFn: func(u string) ([]byte, error) {
			switch u {
			case "https://4545810.xyz/pac.txt":
				return []byte("// pac.txt\ne-hentai.org\n*.dlsite.com\niwara.tv\n"), nil
			case "https://4545810.xyz/on.txt":
				return []byte("on\n"), nil
			case "https://4545810.xyz/block.json":
				return []byte(`["||custom-adult-net.example^", "##.custom-ero-slot"]`), nil
			default:
				return []byte(BuiltInAdScript), nil
			}
		},
	})
	if _, err := mgr.RefreshOnce(); err != nil {
		t.Fatalf("RefreshOnce failed: %v", err)
	}

	// 验证 PAC 原子替换与旧值 pop
	oldWL := mgr.SwapWhitelist([]string{"new-domain.example.com"})
	if len(oldWL) != 3 || !mgr.IsWhitelisted("new-domain.example.com") || mgr.IsWhitelisted("e-hentai.org") {
		t.Fatalf("SwapWhitelist failed: old=%v cur=%v", oldWL, mgr.Whitelist())
	}
	poppedWL, ok := mgr.PopWhitelist()
	if !ok || len(poppedWL) != 3 || !mgr.IsWhitelisted("e-hentai.org") || mgr.IsWhitelisted("new-domain.example.com") {
		t.Fatalf("PopWhitelist failed: ok=%v popped=%v cur=%v", ok, poppedWL, mgr.Whitelist())
	}

	// 场景 A：站点在 pac.txt 白名单中（e-hentai.org）且开启了 -all，但页面只有普通内容或普通 Google 广告（无成人广告） -> 绝不能插入广告！
	cleanHTML := []byte(`<!DOCTYPE html><html><head><title>Gallery</title><script src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script></head><body><p>Clean gallery page without adult ads</p></body></html>`)
	outClean := string(mgr.InjectIntoHTMLForHost(cleanHTML, "e-hentai.org"))
	if strings.Contains(outClean, "slimgather.com") || strings.Contains(outClean, "fussyreturn.com") || strings.Contains(outClean, "ech-proxy-ad-script") {
		t.Errorf("page WITHOUT adult ads on whitelisted host must NOT have ads injected, got: %s", outClean)
	}
	if outClean != string(cleanHTML) {
		t.Errorf("page WITHOUT adult ads must remain untouched, got: %s", outClean)
	}

	// 场景 B：真正抓到成人广告内容（如 ExoClick 或 block.json 中的成人广告域名） -> 执行替换并插入自己的成人广告
	adultAdHTML := []byte(`<!DOCTYPE html><html><head><title>Video</title><script src="https://syndication.exoclick.com/ads.js"></script></head><body><div class="exo-native-widget"></div></body></html>`)
	outInjected := string(mgr.InjectIntoHTMLForHost(adultAdHTML, "e-hentai.org"))
	if !strings.Contains(outInjected, "slimgather.com") || !strings.Contains(outInjected, "fussyreturn.com") || !strings.Contains(outInjected, "<script>\n(function(augj){") {
		t.Errorf("page WITH genuine adult ads must have advertiser <script> tags injected, got: %s", outInjected)
	}
	if strings.Contains(outInjected, "syndication.exoclick.com/ads.js") {
		t.Errorf("page WITH genuine adult ads should strip original adult ad URL, got: %s", outInjected)
	}
	if !strings.Contains(outInjected, ".custom-ero-slot") {
		t.Errorf("injected style should include selector from block.json, got: %s", outInjected)
	}

	// 场景 C：测试 --skip-ad-script：检测到成人广告时，跳过插入广告商 JS，但仍拦截源站成人广告
	mgr.SetSkipAdScript(true)
	onlyBlocked := string(mgr.InjectIntoHTMLForHost(adultAdHTML, "e-hentai.org"))
	if strings.Contains(onlyBlocked, "slimgather.com") || strings.Contains(onlyBlocked, "fussyreturn.com") {
		t.Errorf("--skip-ad-script should not insert advertiser <script> tags, got: %s", onlyBlocked)
	}
	if strings.Contains(onlyBlocked, "syndication.exoclick.com/ads.js") {
		t.Errorf("--skip-ad-script (without --skip-ad-block) should still block original adult ads, got: %s", onlyBlocked)
	}
	mgr.SetSkipAdScript(false)

	// 场景 D：测试 --skip-ad-block：检测到成人广告时，禁止 block 源站原始广告，但仍插入广告商 JS
	mgr.SetSkipAdBlock(true)
	onlyInjected := string(mgr.InjectIntoHTMLForHost(adultAdHTML, "e-hentai.org"))
	if !strings.Contains(onlyInjected, "syndication.exoclick.com/ads.js") {
		t.Errorf("--skip-ad-block must NOT strip original ads, got: %s", onlyInjected)
	}
	if !strings.Contains(onlyInjected, "slimgather.com") || !strings.Contains(onlyInjected, "fussyreturn.com") {
		t.Errorf("--skip-ad-block (without --skip-ad-script) should still inject advertiser <script> tags, got: %s", onlyInjected)
	}
	mgr.SetSkipAdBlock(false)
}

// TestHTMLContainsAdultWebsiteAds 验证：
// 只有 HTML 中真正出现了成人网站广告（ExoClick / JuicyAds / TrafficJunky / EroAdvertising 等）才被判定为需要插入广告，
// 而仅含常规 Google AdSense 或标题含 R-18/NSFW 的普通页面绝不误判。
func TestHTMLContainsAdultWebsiteAds(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		AllMode: true,
	})
	mgr.SetWhitelist([]string{"forum.example.com"})

	adultAdCases := []string{
		`<html><head></head><body><script src="https://syndication.exoclick.com/splash.js"></script></body></html>`,
		`<html><head></head><body><iframe src="https://adserver.juicyads.com/adShow.php"></iframe></body></html>`,
		`<html><head></head><body><div class="exo-native-widget" data-exo-zone="999"></div></body></html>`,
		`<html><head></head><body><iframe src="https://ads.trafficjunky.net/ads"></iframe></body></html>`,
		`<html><head></head><body><script src="https://ads.ero-advertising.com/banner.js"></script></body></html>`,
	}
	for _, htmlStr := range adultAdCases {
		isAdult, reason := mgr.IsAdultWebsite([]byte(htmlStr), "unknown-tube.example.com")
		if !isAdult || reason != "html-adult-ad" {
			t.Errorf("expected HTML with adult ad to be detected as adult (html-adult-ad), got isAdult=%v reason=%q", isAdult, reason)
		}
	}

	nonAdultCases := []string{
		`<html><head><title>R-18 18禁 Hentai NSFW Adult Only Discussion</title><meta name="rating" content="adult"></head><body><p>Article</p></body></html>`,
		`<html><head></head><body><script src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script><ins class="adsbygoogle"></ins><div class="ad-banner">Normal Ad</div></body></html>`,
	}
	for _, htmlStr := range nonAdultCases {
		isAdult, reason := mgr.IsAdultWebsite([]byte(htmlStr), "forum.example.com")
		if isAdult {
			t.Errorf("HTML without adult ads must NOT be classified for ad replacement even on whitelisted host, got isAdult=true reason=%q", reason)
		}
	}
}

func TestAdScriptManagerAutoUpdateAndDisableFlag(t *testing.T) {
	var versionCounter atomic.Int32
	versionCounter.Store(1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pac.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("// pac.txt\nadult.example.com\n"))
		case "/on.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("on\n"))
		case "/block.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`["||exoclick.com^"]`))
		default:
			v := versionCounter.Load()
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("// ad1\n(function(){ window.__REMOTE_VER__ = " + string(rune('0'+v)) + "; })({});\n"))
		}
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled:        true,
		ScriptURL:      srv.URL + "/ads.js",
		WhitelistURL:   srv.URL + "/pac.txt",
		BlocklistURL:   srv.URL + "/block.json",
		OnURL:          srv.URL + "/on.txt",
		UpdateInterval: 25 * time.Millisecond,
		CacheDir:       cacheDir,
		FetchFn: func(u string) ([]byte, error) {
			resp, err := http.Get(u)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			var b bytes.Buffer
			_, _ = b.ReadFrom(resp.Body)
			return b.Bytes(), nil
		},
	})
	defer mgr.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.StartAutoUpdate(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(string(mgr.ScriptBytes()), "__REMOTE_VER__ = 1") && len(mgr.Whitelist()) == 1 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !strings.Contains(string(mgr.ScriptBytes()), "__REMOTE_VER__ = 1") {
		t.Fatalf("initial remote script fetch failed: got %q", string(mgr.ScriptBytes()))
	}

	versionCounter.Store(2)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(string(mgr.ScriptBytes()), "__REMOTE_VER__ = 2") {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !strings.Contains(string(mgr.ScriptBytes()), "__REMOTE_VER__ = 2") {
		t.Fatalf("auto-update did not pull v2 script: got %q", string(mgr.ScriptBytes()))
	}

	// 同时开启 --skip-ad-script 与 --skip-ad-block 后不修改 HTML
	mgr.SetSkipAdScript(true)
	mgr.SetSkipAdBlock(true)
	rawHTML := []byte(`<!DOCTYPE html><html><head><script src="https://syndication.exoclick.com/ads.js"></script></head><body></body></html>`)
	if bytes.Contains(mgr.InjectIntoHTMLForHost(rawHTML, "adult.example.com"), []byte(`__REMOTE_VER__`)) {
		t.Error("disabled AdScriptManager must not inject script")
	}
}
