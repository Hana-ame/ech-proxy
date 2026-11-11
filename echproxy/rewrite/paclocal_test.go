package rewrite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResolveWhitelistSourceLocalPriority 验证「本地 pac.txt 存在则默认用本地，否则用在线」的判定次序：
//  1. 显式 -whitelist-url 永远优先（此时本地 pac.txt 不再参与）；
//  2. 自动探测命中 <candidates>/pac.txt -> kind=local-pac，URL 为 file:// 绝对路径；
//  3. 全都不存在 -> 在线 DefaultWhitelistURL，kind=remote；
//  4. -no-local-pac -> 即使本地文件存在也用在线；
//  5. 非法本地文件（空 / HTML 错误页 / 目录）被跳过并给出 Warning，不让坏文件把白名单清空。
func TestResolveWhitelistSourceLocalPriority(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "pac.txt")
	if err := os.WriteFile(local, []byte("# local pac\nlocal-site.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. 显式 URL 压过本地文件
	got := ResolveWhitelistSource(WhitelistSourceOptions{
		ExplicitURL: "https://example.com/custom-pac.txt",
		Candidates:  []string{local},
	})
	if got.URL != "https://example.com/custom-pac.txt" || got.Kind != WhitelistKindExplicit {
		t.Fatalf("explicit url should win: %+v", got)
	}

	// 1b. 显式本地路径也归入 explicit，并记录 LocalPath
	got = ResolveWhitelistSource(WhitelistSourceOptions{ExplicitURL: "file://" + local})
	if got.Kind != WhitelistKindExplicit || got.LocalPath != local || !strings.HasPrefix(got.URL, "file://") {
		t.Fatalf("explicit local file: %+v", got)
	}

	// 2. 自动探测命中本地文件
	got = ResolveWhitelistSource(WhitelistSourceOptions{Candidates: []string{filepath.Join(dir, "nope.txt"), local}})
	if got.Kind != WhitelistKindLocal || got.LocalPath != local {
		t.Fatalf("auto-detect local pac.txt failed: %+v", got)
	}
	if got.URL != localSourceURL(local) {
		t.Fatalf("local source url = %q, want %q", got.URL, localSourceURL(local))
	}

	// 3. 都不存在 -> 在线
	got = ResolveWhitelistSource(WhitelistSourceOptions{Candidates: []string{filepath.Join(dir, "missing.txt")}})
	if got.URL != DefaultWhitelistURL || got.Kind != WhitelistKindRemote || got.LocalPath != "" {
		t.Fatalf("fallback to remote failed: %+v", got)
	}

	// 4. -no-local-pac 强制在线
	got = ResolveWhitelistSource(WhitelistSourceOptions{Candidates: []string{local}, DisableLocal: true})
	if got.Kind != WhitelistKindRemote || got.URL != DefaultWhitelistURL || len(got.Warnings) == 0 {
		t.Fatalf("no-local-pac should force remote: %+v", got)
	}

	// 5. 非法本地文件：空文件 / HTML 错误页 / 目录都被跳过并回退在线，且带 Warning
	empty := filepath.Join(dir, "empty-pac.txt")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	html := filepath.Join(dir, "html-pac.txt")
	if err := os.WriteFile(html, []byte("<!DOCTYPE html><html><body>403 Forbidden</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "pacdir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got = ResolveWhitelistSource(WhitelistSourceOptions{Candidates: []string{empty, html, sub}})
	if got.Kind != WhitelistKindRemote || got.URL != DefaultWhitelistURL {
		t.Fatalf("invalid local files should fall back to remote: %+v", got)
	}
	if len(got.Warnings) != 3 {
		t.Fatalf("expected 3 warnings for invalid candidates, got %v", got.Warnings)
	}

	// 6. 显式 -pac-file 指向非法内容 -> 回退在线并 Warning
	got = ResolveWhitelistSource(WhitelistSourceOptions{ExplicitPath: html, Candidates: []string{local}})
	if got.Kind != WhitelistKindLocal || got.LocalPath != local {
		t.Fatalf("bad explicit -pac-file should fall through to auto-detect: %+v", got)
	}
	if len(got.Warnings) == 0 {
		t.Fatalf("expected warning for bad explicit -pac-file, got none")
	}
}

// TestNewAdScriptManagerPrefersLocalPAC 验证管理器层面：本地 pac.txt 存在时
// 白名单立刻来自本地文件、Kind=local-pac、且不会被 cache/pac.txt 旧缓存顶掉；
// 文件更新后 RefreshWhitelistOnce 热加载到新内容。
func TestNewAdScriptManagerPrefersLocalPAC(t *testing.T) {
	local := filepath.Join(t.TempDir(), "pac.txt")
	if err := os.WriteFile(local, []byte("local-only.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cacheDir, cachedWhitelistName), []byte("stale-cache.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	remoteFetched := false
	m := NewAdScriptManager(AdScriptOptions{
		Enabled:  true,
		CacheDir: cacheDir,
		FetchFn: func(url string) ([]byte, error) {
			remoteFetched = true
			return []byte("remote.example.com\n"), nil
		},
		// 测试平台没有真实的 <exeDir>/pac.txt，这里显式给出候选路径模拟自动探测命中。
		PACFile: local,
	})
	defer m.Stop()

	if m.WhitelistSourceKind() != WhitelistKindLocal {
		t.Fatalf("whitelist kind = %q, want %q", m.WhitelistSourceKind(), WhitelistKindLocal)
	}
	if m.WhitelistLocalPath() != local {
		t.Fatalf("local path = %q, want %q", m.WhitelistLocalPath(), local)
	}
	if got := m.Whitelist(); len(got) != 1 || got[0] != "local-only.example.com" {
		t.Fatalf("whitelist should come from local pac.txt immediately, got %v", got)
	}
	for _, d := range m.Whitelist() {
		if strings.Contains(d, "stale-cache") {
			t.Fatalf("cache/pac.txt must not override local pac.txt, got %v", m.Whitelist())
		}
	}

	if _, err := m.RefreshWhitelistOnce(); err != nil {
		t.Fatalf("refresh local whitelist: %v", err)
	}
	if remoteFetched {
		t.Fatalf("local pac.txt must not be replaced by remote fetch")
	}
	if got := m.Whitelist(); len(got) != 1 || got[0] != "local-only.example.com" {
		t.Fatalf("unexpected whitelist after refresh: %v", got)
	}

	// 本地文件被编辑 -> 热加载
	if err := os.WriteFile(local, []byte("edited-one.example.com\nedited-two.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RefreshWhitelistOnce(); err != nil {
		t.Fatalf("hot reload: %v", err)
	}
	if got := m.Whitelist(); len(got) != 2 {
		t.Fatalf("hot reload should pick up edited pac.txt, got %v", got)
	}
	// 本地来源不写 cache/pac.txt（不污染缓存，也不会与用户文件互相顶）
	if raw, err := os.ReadFile(filepath.Join(cacheDir, cachedWhitelistName)); err != nil || !strings.Contains(string(raw), "stale-cache") {
		t.Fatalf("cache/pac.txt should stay untouched for local source, err=%v raw=%q", err, string(raw))
	}
}

// TestNewAdScriptManagerLocalPACReloadInterval 验证本地来源用短周期热加载、在线来源保持 30 分钟。
func TestNewAdScriptManagerLocalPACReloadInterval(t *testing.T) {
	local := filepath.Join(t.TempDir(), "pac.txt")
	if err := os.WriteFile(local, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := NewAdScriptManager(AdScriptOptions{Enabled: true, PACFile: local, NoLocalPAC: false})
	defer m.Stop()
	if m.whitelistKind != WhitelistKindLocal {
		t.Fatalf("kind = %q", m.whitelistKind)
	}
	if d := m.refreshInterval(); d != 30*time.Second {
		t.Fatalf("local refresh interval = %v, want 30s", d)
	}

	mRemote := NewAdScriptManager(AdScriptOptions{
		Enabled:      true,
		NoLocalPAC:   true,
		WhitelistURL: "https://example.com/pac.txt",
	})
	defer mRemote.Stop()
	if d := mRemote.refreshInterval(); d != DefaultAdScriptUpdateInterval {
		t.Fatalf("remote refresh interval = %v, want %v", d, DefaultAdScriptUpdateInterval)
	}
}

// TestDefaultLocalWhitelistCandidates 验证候选顺序：程序目录 → 数据目录 → 当前目录，且去重。
func TestDefaultLocalWhitelistCandidates(t *testing.T) {
	dataDir := t.TempDir()
	cands := DefaultLocalWhitelistCandidates(dataDir)
	if len(cands) < 2 {
		t.Fatalf("expected at least exe-dir and data-dir candidates, got %v", cands)
	}
	found := false
	for _, c := range cands {
		if c == filepath.Join(dataDir, LocalWhitelistFileName) {
			found = true
		}
		if filepath.Base(c) != LocalWhitelistFileName {
			t.Fatalf("candidate must be pac.txt: %v", cands)
		}
	}
	if !found {
		t.Fatalf("data-dir candidate missing: %v", cands)
	}
	// 传给空 DataDir 时不应出现空路径或 "pac.txt" 裸相对路径
	for _, c := range DefaultLocalWhitelistCandidates("") {
		if c == LocalWhitelistFileName {
			t.Fatalf("empty DataDir must not produce bare relative pac.txt: %v", c)
		}
	}
}

// TestIsLocalWhitelistSource 验证 file:// 与裸路径都判为本地，http(s) 判为远程。
func TestIsLocalWhitelistSource(t *testing.T) {
	cases := map[string]bool{
		"https://4545810.xyz/pac.txt":   false,
		"http://127.0.0.1:8443/pac.txt": false,
		"file:///tmp/pac.txt":           true,
		"/tmp/pac.txt":                  true,
		"./pac.txt":                     true,
		"":                              false,
	}
	for in, want := range cases {
		if got := IsLocalWhitelistSource(in); got != want {
			t.Errorf("IsLocalWhitelistSource(%q) = %v, want %v", in, got, want)
		}
	}
}
