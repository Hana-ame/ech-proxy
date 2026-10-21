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

// TestUnifiedRemotePACWhitelistAndAdsJSScriptTagInjection 验证：
// 1. 默认白名单地址为 https://4545810.xyz/pac.txt（格式为一行一个 domain，支持 // pac.txt 注释），拉取失败 fallback = []；
// 2. 默认广告脚本地址为 https://4545810.xyz/ads.js，拉取失败使用内置 fallback（slimgather.com + fussyreturn.com 两个 <script> 标签）；
// 3. 支持 --skip-ad-script（跳过插入广告 JS）与 --skip-ad-block（禁止 block 原始广告）。
func TestUnifiedRemotePACWhitelistAndAdsJSScriptTagInjection(t *testing.T) {
	mgrDefault := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		FetchFn: func(url string) ([]byte, error) {
			return nil, errors.New("network unreachable")
		},
	})
	if mgrDefault.WhitelistURL() != "https://4545810.xyz/pac.txt" {
		t.Errorf("default WhitelistURL = %q, want https://4545810.xyz/pac.txt", mgrDefault.WhitelistURL())
	}
	if mgrDefault.ScriptURL() != "https://4545810.xyz/ads.js" {
		t.Errorf("default ScriptURL = %q, want https://4545810.xyz/ads.js", mgrDefault.ScriptURL())
	}
	if got := mgrDefault.Whitelist(); len(got) != 0 {
		t.Errorf("initial Whitelist before fetch = %v, want empty []", got)
	}
	if _, err := mgrDefault.RefreshWhitelistOnce(); err == nil {
		t.Errorf("expected error when remote fetch fails")
	}
	if got := mgrDefault.Whitelist(); len(got) != 0 {
		t.Errorf("Whitelist on fetch failure = %v, want fallback = empty []", got)
	}

	shouldFail := false
	mgrCustom := NewAdScriptManager(AdScriptOptions{
		Enabled:      true,
		WhitelistURL: "https://4545810.xyz/pac.txt",
		FetchFn: func(u string) ([]byte, error) {
			if shouldFail {
				return nil, errors.New("502 bad gateway")
			}
			if u == "https://4545810.xyz/pac.txt" {
				return []byte("// pac.txt\ne-hentai.org\n*.dlsite.com\niwara.tv\n"), nil
			}
			return []byte(BuiltInAdScript), nil
		},
	})
	domains, err := mgrCustom.RefreshWhitelistOnce()
	if err != nil || len(domains) != 3 {
		t.Fatalf("RefreshWhitelistOnce got (%v, %v), want 3 domains", domains, err)
	}
	if !mgrCustom.IsWhitelisted("e-hentai.org") || !mgrCustom.IsWhitelisted("www.dlsite.com") || !mgrCustom.IsWhitelisted("ec.iwara.tv") {
		t.Errorf("expected domains in pac.txt (and their subdomains) to match IsWhitelisted")
	}
	if mgrCustom.IsWhitelisted("github.com") {
		t.Errorf("unlisted domain github.com must not match IsWhitelisted")
	}

	// 白名单站点 -> 剥离原网页广告，并将内置/远程 ads.js 的每个广告段放入 <script>...</script> 标签中插入
	sampleHTML := []byte(`<!DOCTYPE html><html><head><title>Gallery</title><script src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script></head><body></body></html>`)
	injected := string(mgrCustom.InjectIntoHTMLForHost(sampleHTML, "e-hentai.org"))
	if !strings.Contains(injected, "slimgather.com") || !strings.Contains(injected, "fussyreturn.com") || !strings.Contains(injected, "<script>\n(function(augj){") {
		t.Errorf("whitelisted domain e-hentai.org should have <script> tags for slimgather.com and fussyreturn.com injected, got: %s", injected)
	}
	if strings.Contains(injected, "pagead2.googlesyndication.com/pagead/js/adsbygoogle.js") {
		t.Errorf("whitelisted domain e-hentai.org should have original ads stripped, got: %s", injected)
	}

	// 测试 --skip-ad-script：跳过插入广告商 JS，但仍拦截源站原始广告
	mgrCustom.SetSkipAdScript(true)
	onlyBlocked := string(mgrCustom.InjectIntoHTMLForHost(sampleHTML, "e-hentai.org"))
	if strings.Contains(onlyBlocked, "slimgather.com") || strings.Contains(onlyBlocked, "fussyreturn.com") {
		t.Errorf("--skip-ad-script should not insert advertiser <script> tags, got: %s", onlyBlocked)
	}
	if strings.Contains(onlyBlocked, "pagead2.googlesyndication.com/pagead/js/adsbygoogle.js") {
		t.Errorf("--skip-ad-script (without --skip-ad-block) should still block original ads, got: %s", onlyBlocked)
	}
	mgrCustom.SetSkipAdScript(false)

	// 测试 --skip-ad-block：禁止 block 源站原始广告，但仍插入广告商 JS
	mgrCustom.SetSkipAdBlock(true)
	onlyInjected := string(mgrCustom.InjectIntoHTMLForHost(sampleHTML, "e-hentai.org"))
	if !strings.Contains(onlyInjected, "pagead2.googlesyndication.com/pagead/js/adsbygoogle.js") {
		t.Errorf("--skip-ad-block must NOT strip original ads, got: %s", onlyInjected)
	}
	if !strings.Contains(onlyInjected, "slimgather.com") || !strings.Contains(onlyInjected, "fussyreturn.com") {
		t.Errorf("--skip-ad-block (without --skip-ad-script) should still inject advertiser <script> tags, got: %s", onlyInjected)
	}
	mgrCustom.SetSkipAdBlock(false)

	// 非白名单且无成人广告的站点 -> 原样返回
	unlistedOut := mgrCustom.InjectIntoHTMLForHost(sampleHTML, "github.com")
	if bytes.Contains(unlistedOut, []byte(`slimgather.com`)) {
		t.Errorf("non-whitelisted site without adult ads should not be modified in default mode")
	}

	// 后续拉取失败时，fallback 重置为空列表 []
	shouldFail = true
	_, _ = mgrCustom.RefreshWhitelistOnce()
	if got := mgrCustom.Whitelist(); len(got) != 0 {
		t.Errorf("after subsequent fetch failure, Whitelist = %v, want fallback = empty []", got)
	}
}

// TestHTMLContainsAdultWebsiteAds 验证：
// HTML 中出现了成人网站广告（ExoClick / JuicyAds / TrafficJunky / EroAdvertising 等）的网站被判定为黄网，
// 而仅含常规 Google AdSense 或标题含 R-18/NSFW 的普通网站绝不误判为黄网。
func TestHTMLContainsAdultWebsiteAds(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		Enabled: true,
		AllMode: true,
	})
	if len(mgr.Whitelist()) != 0 {
		t.Fatalf("expected empty whitelist")
	}

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
			t.Errorf("non-adult HTML should NOT be classified as adult website, got isAdult=true reason=%q", reason)
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
	rawHTML := []byte(`<!DOCTYPE html><html><head></head><body></body></html>`)
	if bytes.Contains(mgr.InjectIntoHTMLForHost(rawHTML, "adult.example.com"), []byte(`<script>`)) {
		t.Error("disabled AdScriptManager must not inject script")
	}
}
