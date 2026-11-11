package echproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
)

// TestProxyPACUsesLocalPACTxt 验证引擎层：PACFile 指向本地 pac.txt 时，
// /proxy.pac 与 /statusz 都反映本地清单（而不是在线默认名单）。
//
// 这是「自定义本地 text fn = pac.txt，存在则默认使用本地」的端到端落点：
// 用户把一个 pac.txt 放到程序目录后，浏览器从 http://127.0.0.1:8443/proxy.pac
// 拿到的必须是本地那几条域名。
func TestProxyPACUsesLocalPACTxt(t *testing.T) {
	localPAC := filepath.Join(t.TempDir(), "pac.txt")
	if err := os.WriteFile(localPAC, []byte("# 自定义本地 pac.txt\nlocal-pac-site.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	adMgr := NewAdScriptManager(AdScriptOptions{
		Enabled:  true,
		PACFile:  localPAC,
		CacheDir: t.TempDir(),
		// 远端拉取器一旦被用于本地文件即视为 bug，这里直接 fail。
		FetchFn: func(url string) ([]byte, error) {
			t.Fatalf("local pac.txt must not be fetched remotely, got url=%q", url)
			return nil, nil
		},
	})
	defer adMgr.Stop()

	if kind := adMgr.WhitelistSourceKind(); kind != WhitelistKindLocal {
		t.Fatalf("whitelist kind = %q, want %q", kind, WhitelistKindLocal)
	}
	if got := adMgr.Whitelist(); len(got) != 1 || got[0] != "local-pac-site.example.com" {
		t.Fatalf("whitelist from local pac.txt = %v", got)
	}

	engine := NewEngineWithOptions(EngineOptions{
		Config:   &config.Config{Upstreams: config.UpstreamMap{}},
		AdScript: adMgr,
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/proxy.pac", nil)
	req.Host = "127.0.0.1:8443"
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /proxy.pac status = %d", rec.Code)
	}
	pac := rec.Body.String()
	if !strings.Contains(pac, `"local-pac-site.example.com":true`) {
		t.Fatalf("PAC must contain local pac.txt domain, got: %s", pac)
	}

	// /statusz 必须能看出「用的是本地文件」，否则用户无法确认本地是否生效。
	recZ := httptest.NewRecorder()
	reqZ := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/statusz", nil)
	reqZ.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recZ, reqZ)
	body := recZ.Body.String()
	if !strings.Contains(body, `"whitelist_kind":"local-pac"`) {
		t.Fatalf("/statusz should report whitelist_kind=local-pac, got: %s", body)
	}
	if !strings.Contains(body, `"whitelist_count":1`) {
		t.Fatalf("/statusz whitelist_count should be 1, got: %s", body)
	}
}

// TestProxyPACFallsBackToRemoteWhenNoLocalFile 验证没有本地 pac.txt 时仍走在线来源（行为不变）。
func TestProxyPACFallsBackToRemoteWhenNoLocalFile(t *testing.T) {
	adMgr := NewAdScriptManager(AdScriptOptions{
		Enabled:    true,
		NoLocalPAC: true,
		CacheDir:   t.TempDir(),
	})
	defer adMgr.Stop()
	if kind := adMgr.WhitelistSourceKind(); kind != WhitelistKindRemote {
		t.Fatalf("kind = %q, want %q", kind, WhitelistKindRemote)
	}
	if url := adMgr.WhitelistURL(); url != DefaultWhitelistURL {
		t.Fatalf("whitelist url = %q, want %q", url, DefaultWhitelistURL)
	}
}
