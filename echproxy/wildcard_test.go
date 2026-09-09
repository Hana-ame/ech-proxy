package echproxy

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestMain 把通配入口 mode 探测的 DNS 解析替换为无网络假解析器：
// matchWildcard 会对每个子域打真实 DoH（wildcardMode → resolveHostIP），
// 单测里既慢（每个子域一次查询）又随 DoH 可达性抖动 flaky，失败的探测还会
// 写进 10 分钟全局缓存污染后续匹配。统一注入 Cloudflare 段 IP（判定为 ECH），
// 需要验证「非 CF → sni」判定的用例再用 stubResolveIP 注入非 CF IP。
func TestMain(m *testing.M) {
	clearWildcardModeCache()
	resolveIPFn = func(ctx context.Context, host string) (string, error) {
		return cloudflareTestIP, nil
	}
	os.Exit(m.Run())
}

// cloudflareTestIP 单测用的 Cloudflare 段 IP（isCloudflareIP 判定为 ECH）。
const cloudflareTestIP = "104.16.5.1"

// nonCFTestIP 单测用的非 Cloudflare IP（isCloudflareIP 判定为 sni）。
const nonCFTestIP = "3.214.0.1"

// stubResolveIP 把通配探测的 DNS 解析固定为 ip 并清空 mode 缓存，测完还原
// 解析器并再清一次缓存，避免用例间互相污染。用于确定性验证 ECH/SNI 判定。
func stubResolveIP(t *testing.T, ip string) {
	t.Helper()
	prev := resolveIPFn
	clearWildcardModeCache()
	resolveIPFn = func(ctx context.Context, host string) (string, error) { return ip, nil }
	t.Cleanup(func() {
		resolveIPFn = prev
		clearWildcardModeCache()
	})
}

// clearWildcardModeCache 清空通配 mode 探测缓存，避免用例间互相污染。
func clearWildcardModeCache() {
	wildcardModeCache.Range(func(k, v any) bool {
		wildcardModeCache.Delete(k)
		return true
	})
}

func TestMatchWildcard(t *testing.T) {
	cfg := UpstreamMap{
		"iwara.l.moonchan.xyz": {
			Host: "iwara.tv",
			Wildcard: &WildcardRule{
				Prefix:         "iwara-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".iwara.tv",
				Referer:        "https://www.iwara.tv/",
			},
		},
	}
	cases := []struct{ host, want string }{
		{"iwara-filesq.l.moonchan.xyz", "filesq.iwara.tv"},
		{"iwara-video.l.moonchan.xyz", "video.iwara.tv"},
		{"iwara-x.l.moonchan.xyz", "x.iwara.tv"},
	}
	for _, c := range cases {
		uc, ok := matchWildcard(cfg, c.host)
		if !ok {
			t.Errorf("%s: not matched", c.host)
			continue
		}
		if uc.Host != c.want {
			t.Errorf("%s: want %s got %s", c.host, c.want, uc.Host)
		}
		if !strings.HasPrefix(uc.Referer, "https://www.iwara.tv") && uc.Mode == "" {
			t.Errorf("%s: referer missing", c.host)
		}
	}
	if _, ok := matchWildcard(cfg, "iwara.l.moonchan.xyz"); ok {
		t.Error("exact entry should not match wildcard")
	}
	if _, ok := matchWildcard(cfg, "pixiv.l.moonchan.xyz"); ok {
		t.Error("non-wildcard host should not match")
	}
}

func TestReplaceWildcardDomain(t *testing.T) {
	rw := buildRewriter(map[string]string{
		"iwara.tv":      "iwara.l.moonchan.xyz",
		"www.pixiv.net": "pixiv.l.moonchan.xyz",
		"*.iwara.tv":    "iwara-*.l.moonchan.xyz",
		"*.pixiv.net":   "pixiv-*.l.moonchan.xyz",
	})
	body := []byte(`{"url":"https://filesq.iwara.tv/file/abc.mp4","img":"https://i.iwara.tv/x.jpg","api":"https://api.iwara.tv/trending","bare":"https://iwara.tv/","dl":"https://dl.pixiv.net/zip/a.zip","www":"https://www.pixiv.net/a"}`)
	got := string(rw(body, "8443"))
	want := `{"url":"https://iwara-filesq.l.moonchan.xyz:8443/file/abc.mp4","img":"https://iwara-i.l.moonchan.xyz:8443/x.jpg","api":"https://iwara-api.l.moonchan.xyz:8443/trending","bare":"https://iwara.l.moonchan.xyz:8443/","dl":"https://pixiv-dl.l.moonchan.xyz:8443/zip/a.zip","www":"https://pixiv.l.moonchan.xyz:8443/a"}`
	if got != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}

func TestSWInjectPrepend(t *testing.T) {
	cfg := UpstreamMap{
		"iwara.l.moonchan.xyz": {
			Host: "iwara.tv",
			Wildcard: &WildcardRule{
				Prefix:         "iwara-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".iwara.tv",
				Referer:        "https://www.iwara.tv/",
			},
		},
		"iwara-api.l.moonchan.xyz": {Host: "api.iwara.tv"},
	}
	inject := swOverrideJS(buildSWProxyMap(cfg, "8443"), collectWildcardRules(cfg), nil)
	// 注入代码必须是合法 JS: 有 install/activate/fetch 监听。
	for _, want := range []string{"install", "activate", "fetch", "__wtMap", "__wtRules", "iwara-", ".l.moonchan.xyz", "iwara-api.l.moonchan.xyz:8443"} {
		if !strings.Contains(inject, want) {
			t.Errorf("inject missing %q", want)
		}
	}
	// 通配规则包含 iwara
	if !strings.Contains(inject, "iwara.tv") {
		t.Errorf("wildcard suffix missing in inject")
	}
}

func TestBuildEntryRewriterInherit(t *testing.T) {
	cfg := UpstreamMap{
		"iwara.l.moonchan.xyz": {
			Host: "iwara.tv",
			Wildcard: &WildcardRule{
				Prefix:         "iwara-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".iwara.tv",
				Referer:        "https://www.iwara.tv/",
			},
		},
		"iwara-api.l.moonchan.xyz": {Host: "api.iwara.tv"},
	}
	// 子入口无 wildcard, 应继承主入口规则。
	sub := cfg["iwara-api.l.moonchan.xyz"]
	sub.Wildcard = inheritWildcard(cfg, "iwara-api.l.moonchan.xyz")
	if sub.Wildcard == nil {
		t.Fatal("inheritWildcard returned nil")
	}
	rw := buildEntryRewriter(sub, nil)
	body := []byte(`{"u":"https://filesq.iwara.tv/a.mp4","bare":"https://iwara.tv/"}`)
	got := string(rw(body, "8443"))
	for _, want := range []string{"iwara-filesq.l.moonchan.xyz:8443", "iwara.l.moonchan.xyz:8443"} {
		if !strings.Contains(got, want) {
			t.Errorf("rewrite result missing %q: %s", want, got)
		}
	}
	// 主入口自身也应推导裸域 + 通配。
	rwMain := buildEntryRewriter(cfg["iwara.l.moonchan.xyz"], nil)
	if !strings.Contains(string(rwMain([]byte(`https://news.iwara.tv/x`), "")), "iwara-news.l.moonchan.xyz") {
		t.Error("main entry wildcard rewrite failed")
	}
}

func TestFixedCookieOverride(t *testing.T) {
	cfg := UpstreamMap{
		"ex.l.moonchan.xyz": {
			Host:   "exhentai.org",
			Cookie: "igneous=xxx; ipb_member_id=123; ipb_pass_hash=abc",
		},
		"iwara.l.moonchan.xyz": {
			Host:   "iwara.tv",
			Cookie: "auth_token=abc123",
			Wildcard: &WildcardRule{
				Prefix:         "iwara-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".iwara.tv",
			},
		},
	}

	// 固定 cookie 原样覆盖内存 jar + 客户端 cookie（proxy.go 里 outReq.Header.Set
	// "Cookie" 在 applyCookies 之后）。该注入内联在 handler 内，无 mock 上游时
	// 断不了请求头；这里只验证配置解析 + 通配继承。旧版本在此发真实上游请求
	// 验证「不崩」，超时 ~15s 且失败静默 skip，已移除。
	if got := cfg["ex.l.moonchan.xyz"].Cookie; got != "igneous=xxx; ipb_member_id=123; ipb_pass_hash=abc" {
		t.Errorf("fixed cookie = %q", got)
	}

	// 通配入口继承主入口固定 cookie。
	uc, ok := matchWildcard(cfg, "iwara-api.l.moonchan.xyz")
	if !ok {
		t.Fatal("wildcard match failed")
	}
	if uc.Cookie != "auth_token=abc123" {
		t.Errorf("wildcard cookie inherit: got %q", uc.Cookie)
	}
}

// 回归: dlsite login 链接里域名前是 URL 编码 %2F,
// 十六进制字符 F/2 不能被当成子域, 也不能被当域名残留拒绝替换。
func TestURLEncodedDomainRewrite(t *testing.T) {
	rw := buildRewriter(map[string]string{
		"www.dlsite.com": "dlsite.l.moonchan.xyz",
		"*.dlsite.com":   "dlsite-*.l.moonchan.xyz",
	})
	body := []byte(`<a href="/home/login/=/skip_register/1/_query/https%3A%2F%2Fwww.dlsite.com%2Fhome%2Fmypage">login</a>`)
	got := string(rw(body, "8443"))
	want := `<a href="/home/login/=/skip_register/1/_query/https%3A%2F%2Fdlsite.l.moonchan.xyz:8443%2Fhome%2Fmypage">login</a>`
	if got != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
	// 普通子域不受影响
	body2 := []byte(`{"u":"https://ch.dlsite.com/x"}`)
	got2 := string(rw(body2, "8443"))
	if !strings.Contains(got2, "dlsite-ch.l.moonchan.xyz:8443") {
		t.Errorf("plain subdomain broken: %s", got2)
	}
}

// 回归: dlsite 页面里的被墙第三方域名(Google 字体/jsapi)应从响应剔除,
// 避免浏览器直连挂起超时。ECH/SNI 都到不了这些域名。
func TestBlockedThirdPartyHosts(t *testing.T) {
	rw := buildEntryRewriter(UpstreamConfig{
		Host: "www.dlsite.com",
		Rewrites: map[string]string{
			"www.dlsite.com": "dlsite.l.moonchan.xyz",
		},
	}, testBlockedHosts)
	body := []byte(`<head>
<link href="https://fonts.googleapis.com/css?family=Sawarabi+Gothic" rel="stylesheet">
<script type="text/javascript" src="https://www.google.com/jsapi"></script>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.10.1/jquery.min.js"></script>
<link href="https://dlsite.l.moonchan.xyz:8443/css/reset.css" rel="stylesheet">
</head>`)
	got := string(rw(body, "8443"))
	for _, blocked := range []string{"fonts.googleapis.com", "www.google.com/jsapi", "ajax.googleapis.com"} {
		if strings.Contains(got, blocked) {
			t.Errorf("blocked host %q still present:\n%s", blocked, got)
		}
	}
	if !strings.Contains(got, "dlsite.l.moonchan.xyz:8443/css/reset.css") {
		t.Errorf("normal rewrite broken:\n%s", got)
	}
}

// 回归: dlsite 页面里的被墙第三方域名(Google 字体/jsapi)应从响应剔除,
// 避免浏览器直连挂起超时。ECH/SNI 都到不了这些域名。
func TestBlockedThirdPartyStrip(t *testing.T) {
	rw := buildEntryRewriter(UpstreamConfig{
		Host:     "www.dlsite.com",
		Rewrites: map[string]string{"www.dlsite.com": "dlsite.l.moonchan.xyz"},
	}, testBlockedHosts)
	body := []byte(`<link href="https://fonts.googleapis.com/css?family=Sawarabi+Gothic" rel="stylesheet">
<script type="text/javascript" src="https://www.google.com/jsapi"></script>
<link href="https://dlsite.l.moonchan.xyz:8443/css/reset.css" rel="stylesheet">`)
	got := string(rw(body, "8443"))
	for _, b := range []string{"fonts.googleapis.com", "www.google.com/jsapi"} {
		if strings.Contains(got, b) {
			t.Errorf("blocked %q still present:\n%s", b, got)
		}
	}
	if !strings.Contains(got, "dlsite.l.moonchan.xyz:8443/css/reset.css") {
		t.Errorf("normal rewrite broken:\n%s", got)
	}
}

// 回归: 上游 Set-Cookie 规范化 —— Domain 改写为代理域,
// http 模式下去掉 Secure 标志, 浏览器才能正常存储前端状态 cookie
// (dlsite 语言/成人确认弹窗无限循环的根因)。
func TestSetCookieNormalize(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "display_language=zh_cn; expires=Wed, 13 Aug 2027 00:00:00 GMT; Max-Age=31536000; path=/; Domain=.dlsite.com; Secure")
	h.Add("Set-Cookie", "host_only=1; path=/")
	// http 模式 (TLS==nil): 去 Secure + 改 Domain
	rewriteSetCookieDomains(h, "dlsite.l.moonchan.xyz:8443", true)
	got := h.Values("Set-Cookie")
	if len(got) != 2 {
		t.Fatalf("Set-Cookie count = %d", len(got))
	}
	if !strings.Contains(got[0], "Domain=dlsite.l.moonchan.xyz") {
		t.Errorf("domain not rewritten: %s", got[0])
	}
	if strings.Contains(got[0], "dlsite.com") || strings.Contains(got[0], "Secure") {
		t.Errorf("old domain or Secure still present: %s", got[0])
	}
	if !strings.Contains(got[1], "host_only=1") {
		t.Errorf("host-only cookie broken: %s", got[1])
	}
}

// 回归: 前端 JS 用 document.cookie 设置语言/状态 cookie 时带
// Domain=.dlsite.com, 必须重写为代理域且不带端口
// (cookie Domain 属性不允许端口, 带端口浏览器拒绝 → 语言弹窗无限循环)。
func TestJSDomainCookieRewrite(t *testing.T) {
	rw := buildEntryRewriter(UpstreamConfig{
		Host: "www.dlsite.com",
		Wildcard: &WildcardRule{
			Prefix:         "dlsite-",
			EntrySuffix:    ".l.moonchan.xyz",
			UpstreamSuffix: ".dlsite.com",
		},
		Rewrites: map[string]string{"www.dlsite.com": "dlsite.l.moonchan.xyz"},
	}, nil)
	body := []byte(`document.cookie = 'display_language=zh_cn; path=/; Domain=.dlsite.com';location='https://www.dlsite.com/x'`)
	got := string(rw(body, "8443"))
	if !strings.Contains(got, "Domain=dlsite.l.moonchan.xyz") {
		t.Errorf("cookie Domain not rewritten to proxy host: %s", got)
	}
	if strings.Contains(got, "Domain=dlsite.l.moonchan.xyz:8443") {
		t.Errorf("cookie Domain must not contain port: %s", got)
	}
	if !strings.Contains(got, "dlsite.l.moonchan.xyz:8443/x") {
		t.Errorf("location rewrite broken: %s", got)
	}
}

// testBlockedHosts 测试用 blocked 列表 (对应 Config.BlockedHosts)。
var testBlockedHosts = []string{
	"https://fonts.googleapis.com",
	"https://fonts.gstatic.com",
	"https://www.google.com/jsapi",
	"https://ajax.googleapis.com",
	"https://www.googletagmanager.com",
	"https://media.dlsite.com",
}
