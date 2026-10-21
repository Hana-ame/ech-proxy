package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

// TestFilenameIs443 pins the exact-suffix rule: only a filename ending in
// ".443.exe" (.*.443.exe) selects port 443. A substring hit in the middle of the name must
// not trigger it — an intermediate build renamed ".443.beta.exe" would
// otherwise bind a privileged port the operator never asked for.
func TestFilenameIs443(t *testing.T) {
	cases := map[string]bool{
		// The intended builds.
		"ech-proxy.443.exe":          true,
		"foo.443.exe":                true,
		"proxy.443.exe":              true,
		"ech-proxy.EXE":              false, // unrelated case, no suffix
		`C:\tools\ech-proxy.443.exe`: true,
		"/opt/ech-proxy.443.exe":     true,

		// Exact suffix, different case on Windows.
		"ech-proxy.443.EXE": true,

		// Substring only — must NOT trigger.
		"ech-proxy.443.beta.exe":  false,
		"ech-proxy.443.debug.exe": false,
		"ech-proxy.443-old.exe":   false,

		// Other suffixes and the historical default.
		"ech-proxy.exe":         false,
		"ech-proxy.8443.exe":    false,
		"ech-proxy.444.exe":     false,
		"443.exe":               false, // the suffix is ".443.exe", not "443.exe"
		"ech-proxy.443":         false, // no .exe
		"ech-proxy.443.zip":     false,
		"ech-proxy.443.exe.txt": false,

		// Empty and odd inputs.
		"":         false,
		"\\":       false,
		".443.exe": true,
	}
	for name, want := range cases {
		if got := filenameIs443(name); got != want {
			t.Errorf("filenameIs443(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseCLIArgsSubcommandsFlagsAndSysProxyDefaults(t *testing.T) {
	noEnv := func(string) string { return "" }

	// 1. 默认主流（mainstream）启动为 smart 模式（PAC HTTPS Proxy），默认 ipmode = ipv4 ("v4")，监听 127.0.0.1:8443，不开启 PortalMode 或 LocalProxy
	c1, err := parseCLIArgs("ech-proxy", nil, noEnv)
	if err != nil || c1.Action != "run" || c1.Mode != "smart" || c1.AllMode || c1.PortalMode || c1.IPMode != "v4" || c1.Addr != "127.0.0.1:8443" || c1.LocalProxy {
		t.Errorf("default parseCLIArgs = %+v, %v", c1, err)
	}
	if c1.SysProxy != SysProxyPAC || !c1.EnableTray || c1.HideConsole || c1.SkipAdScript || c1.SkipAdBlock {
		t.Errorf("smart mode defaults: SysProxy=%q EnableTray=%v HideConsole=%v SkipAdScript=%v SkipAdBlock=%v",
			c1.SysProxy, c1.EnableTray, c1.HideConsole, c1.SkipAdScript, c1.SkipAdBlock)
	}

	// 2. 测试快捷 Flag 一览：-4, -6, -dual, -all, --skip-ad-script, --skip-ad-block
	cFlag4, err := parseCLIArgs("ech-proxy", []string{"-4"}, noEnv)
	if err != nil || cFlag4.IPMode != "v4" {
		t.Errorf("-4 parseCLIArgs = %+v, %v", cFlag4, err)
	}
	cFlag6, err := parseCLIArgs("ech-proxy", []string{"-6"}, noEnv)
	if err != nil || cFlag6.IPMode != "v6" {
		t.Errorf("-6 parseCLIArgs = %+v, %v", cFlag6, err)
	}
	cFlagDual, err := parseCLIArgs("ech-proxy", []string{"-dual"}, noEnv)
	if err != nil || cFlagDual.IPMode != "dual" {
		t.Errorf("-dual parseCLIArgs = %+v, %v", cFlagDual, err)
	}
	if _, err := parseCLIArgs("ech-proxy", []string{"-4", "-6"}, noEnv); err == nil {
		t.Error("expected error when both -4 and -6 are passed")
	}

	cAllSkip, err := parseCLIArgs("ech-proxy", []string{"-all", "--skip-ad-script", "--skip-ad-block"}, noEnv)
	if err != nil || !cAllSkip.AllMode || !cAllSkip.SkipAdScript || !cAllSkip.SkipAdBlock {
		t.Errorf("-all --skip-ad-script --skip-ad-block parseCLIArgs = %+v, %v", cAllSkip, err)
	}

	// 3. 验证当文件名不包含 .443.exe 时，严禁开启 443 模式或监听 443 端口
	for _, forbiddenArgs := range [][]string{
		{"local"},
		{"443"},
		{"-local"},
		{"-mode", "local"},
		{"-addr", "127.0.0.1:443"},
		{"-addr", ":443"},
	} {
		if _, err := parseCLIArgs("ech-proxy.exe", forbiddenArgs, noEnv); err == nil {
			t.Errorf("expected error for non-.443.exe with args %v, got nil", forbiddenArgs)
		}
	}

	// 4. .*.443.exe 只和 listen 443 有关：只开启 443 方案，不回退到 8443（FallbackAddr=""），不改系统代理，不运行托盘/更新器/CONNECT
	c2, err := parseCLIArgs("ech-proxy.443.exe", nil, noEnv)
	if err != nil || !c2.LocalProxy || c2.PortalMode || c2.Addr != "127.0.0.1:443" || c2.FallbackAddr != "" || c2.SysProxy != SysProxyOff || c2.EnableTray || !c2.NoAutoUpdate || c2.AllowConnect {
		t.Errorf(".443.exe parseCLIArgs = %+v, %v (expected strict listen-443-only isolation)", c2, err)
	}
	if _, err := parseCLIArgs("ech-proxy.443.exe", []string{"-addr", "127.0.0.1:8443"}, noEnv); err == nil {
		t.Error("expected error when .443.exe is given a non-443 listen address")
	}

	// 4b. .8443.exe 自动进入 8443 门户方案（PortalMode=true, SysProxy=SysProxyOff）；非 .8443.exe 禁止显式开启 portal 子命令
	c8443, err := parseCLIArgs("ech-proxy.8443.exe", nil, noEnv)
	if err != nil || !c8443.PortalMode || c8443.LocalProxy || c8443.Mode != "portal" || c8443.SysProxy != SysProxyOff {
		t.Errorf(".8443.exe parseCLIArgs = %+v, %v", c8443, err)
	}
	if _, err := parseCLIArgs("ech-proxy.exe", []string{"portal"}, noEnv); err == nil {
		t.Error("expected error when non-.8443.exe requests portal subcommand")
	}

	// 5. 子命令 ca install / ca uninstall / update / logs
	cUninstall, err := parseCLIArgs("ech-proxy", []string{"ca", "uninstall"}, noEnv)
	if err != nil || cUninstall.Action != "ca-uninstall" {
		t.Errorf("ca uninstall got %+v, %v", cUninstall, err)
	}
	cUpdate, err := parseCLIArgs("ech-proxy", []string{"update"}, noEnv)
	if err != nil || cUpdate.Action != "update" {
		t.Errorf("update subcommand got %+v, %v", cUpdate, err)
	}

	// 6. .443.exe 下 -local 与 -http 互斥报错
	if _, err := parseCLIArgs("ech-proxy.443.exe", []string{"-local", "-http"}, noEnv); err == nil {
		t.Error("expected error when both -local and -http are set")
	}
}

func TestSysProxyManagerAtomicReplaceAndOldValuePop(t *testing.T) {
	drv := &stubSysProxyDriver{}
	// 预设用户原本已有一个旧的 PAC 地址，验证原子替换与旧值 pop 恢复
	_ = drv.ApplyPAC("http://corp.example.com/legacy.pac")

	mgr := NewSysProxyManager("0.0.0.0:8443", drv)
	mgr.nowUnix = func() int64 { return 1700000000 }

	// 1. 切换为默认白名单 PAC 模式（带 ?t= 时间戳防缓存参数），旧值被压栈
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC): %v", err)
	}
	st, _ := drv.Query()
	wantPAC := "http://127.0.0.1:8443/proxy.pac?t=1700000000"
	if st.Mode != SysProxyPAC || st.AutoConfigURL != wantPAC {
		t.Errorf("after SetMode(PAC): state=%+v, want AutoConfigURL=%q", st, wantPAC)
	}

	// 2. 开启 all 模式后切换为 PAC 模式（带 ?mode=all&t= 参数），再次压栈
	mgr.SetAllMode(true)
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC all): %v", err)
	}
	st, _ = drv.Query()
	wantAllPAC := "http://127.0.0.1:8443/proxy.pac?mode=all&t=1700000000"
	if st.Mode != SysProxyPAC || st.AutoConfigURL != wantAllPAC {
		t.Errorf("after SetMode(PAC all): state=%+v, want AutoConfigURL=%q", st, wantAllPAC)
	}

	// 3. 调用 Pop() 弹出上一次的 PAC 地址（wantPAC）
	popped, ok, err := mgr.Pop()
	if err != nil || !ok || popped.AutoConfigURL != wantPAC {
		t.Fatalf("Pop() #1 got (%+v, %v, %v), want AutoConfigURL=%q", popped, ok, err, wantPAC)
	}
	st, _ = drv.Query()
	if st.AutoConfigURL != wantPAC {
		t.Errorf("after Pop() #1: driver state=%+v, want %q", st, wantPAC)
	}

	// 4. 退出时自动 pop 恢复进程启动前的初始旧值（http://corp.example.com/legacy.pac）
	mgr.CleanupOnExit()
	st, _ = drv.Query()
	if st.Mode != SysProxyPAC || st.AutoConfigURL != "http://corp.example.com/legacy.pac" {
		t.Errorf("after CleanupOnExit: state=%+v, want restored legacy PAC", st)
	}
}

func TestTrayControllerMenuRefinementsUninstallCAAndUpdate(t *testing.T) {
	drv := &stubSysProxyDriver{}
	sysMgr := NewSysProxyManager("127.0.0.1:8443", drv)
	console := &stubConsoleDriver{visible: true}

	var openedURL, copiedText, installedCA, uninstalledCA, switchedIPMode string
	updateChecked := false
	exited := false
	// mu 串行化「异步托盘回调写入」与「测试主 goroutine 读取」，消除 -race 数据竞争
	// （InstallCA / UninstallCA / CheckUpdate / OpenFeedback 经 echproxy.SafeGo 异步执行）。
	var mu sync.Mutex

	tc := NewTrayController("127.0.0.1:8443", "https://l.moonchan.xyz:8443", "/tmp/ca.pem", sysMgr, console, func() {
		exited = true
	})
	tc.SetIPModeFn = func(m string) { mu.Lock(); switchedIPMode = m; mu.Unlock() }
	tc.OpenURLFn = func(u string) { mu.Lock(); openedURL = u; mu.Unlock() }
	tc.CopyClipboardFn = func(s string) error { mu.Lock(); copiedText = s; mu.Unlock(); return nil }
	tc.InstallCAFn = func(p string) error { mu.Lock(); installedCA = p; mu.Unlock(); return nil }
	tc.UninstallCAFn = func(p string) error { mu.Lock(); uninstalledCA = p; mu.Unlock(); return nil }
	tc.CheckUpdateFn = func() (bool, error) { mu.Lock(); updateChecked = true; mu.Unlock(); return true, nil }

	items := tc.MenuItems()
	var titles []string
	for _, it := range items {
		if !it.Separator {
			titles = append(titles, it.Title)
		}
		if strings.Contains(it.Title, "全局") {
			t.Errorf("tray menu must NOT display global proxy mode, found: %q", it.Title)
		}
		if strings.Contains(it.Title, "广告") || strings.Contains(strings.ToLower(it.Title), "ad script") {
			t.Errorf("tray menu must hide ad settings, found: %q", it.Title)
		}
		if strings.Contains(it.Title, "打开 Web 门户") {
			t.Errorf("tray menu should replace 打开门户 with 反馈, found: %q", it.Title)
		}
	}
	joined := strings.Join(titles, " | ")
	for _, mustHave := range []string{
		"反馈 (https://chatto.moonchan.xyz)",
		"强制 v4 出口",
		"强制 v6 出口",
		"双端出口",
		"一键安装本地 CA 根证书 (Install CA)",
		"卸载本地 CA 根证书 (Uninstall CA)",
		"检查更新 (Check Update)",
	} {
		if !strings.Contains(joined, mustHave) {
			t.Errorf("tray menu missing %q in items: %s", mustHave, joined)
		}
	}

	tc.HandleCommand(TrayCmdIPModeV6)
	if tc.CurrentIPMode() != "v6" || switchedIPMode != "v6" || !strings.Contains(tc.TooltipText(), "v6出口") {
		t.Errorf("after TrayCmdIPModeV6: cur=%q switched=%q tooltip=%q", tc.CurrentIPMode(), switchedIPMode, tc.TooltipText())
	}
	tc.HandleCommand(TrayCmdIPModeDual)
	if tc.CurrentIPMode() != "dual" || switchedIPMode != "dual" || !strings.Contains(tc.TooltipText(), "双端出口") {
		t.Errorf("after TrayCmdIPModeDual: cur=%q switched=%q tooltip=%q", tc.CurrentIPMode(), switchedIPMode, tc.TooltipText())
	}
	tc.HandleCommand(TrayCmdIPModeV4)
	if tc.CurrentIPMode() != "v4" || switchedIPMode != "v4" || !strings.Contains(tc.TooltipText(), "v4出口") {
		t.Errorf("after TrayCmdIPModeV4: cur=%q switched=%q tooltip=%q", tc.CurrentIPMode(), switchedIPMode, tc.TooltipText())
	}

	tc.HandleCommand(TrayCmdInstallCA)
	tc.HandleCommand(TrayCmdUninstallCA)
	tc.HandleCommand(TrayCmdCheckUpdate)
	tc.HandleCommand(TrayCmdOpenFeedback)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := openedURL != "" && uninstalledCA != "" && updateChecked && installedCA != ""
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	gotInstalled, gotUninstalled, gotUpdateChecked, gotOpenedURL := installedCA, uninstalledCA, updateChecked, openedURL
	mu.Unlock()
	if gotInstalled != "/tmp/ca.pem" {
		t.Errorf("TrayCmdInstallCA got %q, want /tmp/ca.pem", gotInstalled)
	}
	if gotUninstalled != "/tmp/ca.pem" {
		t.Errorf("TrayCmdUninstallCA got %q, want /tmp/ca.pem", gotUninstalled)
	}
	if !gotUpdateChecked {
		t.Errorf("TrayCmdCheckUpdate did not invoke CheckUpdateFn")
	}
	if gotOpenedURL != "https://chatto.moonchan.xyz" {
		t.Errorf("TrayCmdOpenFeedback opened %q, want https://chatto.moonchan.xyz", gotOpenedURL)
	}

	tc.HandleCommand(TrayCmdToggleConsole)
	if tc.IsConsoleVisible() {
		t.Error("console should be hidden after first toggle")
	}
	tc.HandleCommand(TrayCmdToggleConsole)
	if !tc.IsConsoleVisible() {
		t.Error("console should be visible after second toggle")
	}

	tc.HandleCommand(TrayCmdSysProxyPAC)
	tc.HandleCommand(TrayCmdCopyPACURL)
	mu.Lock()
	gotCopiedText := copiedText
	mu.Unlock()
	if gotCopiedText != "http://127.0.0.1:8443/proxy.pac" {
		t.Errorf("copied PAC URL = %q, want http://127.0.0.1:8443/proxy.pac", gotCopiedText)
	}

	if shouldExit := tc.HandleCommand(TrayCmdExit); !shouldExit || !exited {
		t.Errorf("TrayCmdExit should return true and invoke OnExit")
	}
	if sysMgr.Mode() != SysProxyOff {
		t.Errorf("TrayCmdExit must clean up system proxy, got mode=%q", sysMgr.Mode())
	}
}

func TestUpdaterParseChecksumsAndAutoDownloadReplaceOnExit(t *testing.T) {
	releaseText := `
checksums.txt
sha256:29ec803c87048d5033fdf7d4c3dd91724090c3657e31a598e5b75fb1f36ca3dc
715 Bytes
ech-proxy-android-3.2.0.apk
sha256:408668f480df4413b5d7346801092b765bff4713e33b45f6a1eaadc09aa47a2f
ech-proxy-darwin-amd64
sha256:7c35b82fbcd51f9dc06a06e016f7af9af6ed7105565c3df1a79d3a2e661547f3
ech-proxy-linux-386
sha256:ca1c64497f97624a9c86349b465bcb0b4ba1fa8aafb35ca0531dea4e256cdd61
ech-proxy-linux-amd64
sha256:67d8b51ba5f1cdeff88564dabda44038fce2a7ddb0c6001b74a3e26cc9854f55
ech-proxy-linux-arm64
sha256:04fb2de70675d29499782a6791907b37de7c86c1afa8c65884bc155936c3fedf
ech-proxy-windows-386.exe
sha256:08e7e3e7b4668ae5ec49bf3715c646b59dc3171eb25ce6fcb50b61aa6b14a9a5
ech-proxy-windows-amd64.exe
sha256:a711c923e0dd55e3aef0610c76ccf48bb8123624d40feda3afcacaffe19aa4ee
ech-proxy-windows-arm64.exe
sha256:fcb8f707ccc5317a7813036ede4e89a5f5bff3bfc1ae74f9ae9046d39a3e95ca
`
	parsed := ParseChecksumsTxt([]byte(releaseText))
	wantHashes := map[string]string{
		"ech-proxy-windows-386.exe":   "08e7e3e7b4668ae5ec49bf3715c646b59dc3171eb25ce6fcb50b61aa6b14a9a5",
		"ech-proxy-windows-amd64.exe": "a711c923e0dd55e3aef0610c76ccf48bb8123624d40feda3afcacaffe19aa4ee",
		"ech-proxy-windows-arm64.exe": "fcb8f707ccc5317a7813036ede4e89a5f5bff3bfc1ae74f9ae9046d39a3e95ca",
		"ech-proxy-linux-386":         "ca1c64497f97624a9c86349b465bcb0b4ba1fa8aafb35ca0531dea4e256cdd61",
		"ech-proxy-linux-amd64":       "67d8b51ba5f1cdeff88564dabda44038fce2a7ddb0c6001b74a3e26cc9854f55",
		"ech-proxy-linux-arm64":       "04fb2de70675d29499782a6791907b37de7c86c1afa8c65884bc155936c3fedf",
		"ech-proxy-darwin-amd64":      "7c35b82fbcd51f9dc06a06e016f7af9af6ed7105565c3df1a79d3a2e661547f3",
	}
	for asset, wantH := range wantHashes {
		if parsed[asset] != wantH {
			t.Errorf("ParseChecksumsTxt[%q] = %q, want %q", asset, parsed[asset], wantH)
		}
	}

	dir := t.TempDir()
	exePath := filepath.Join(dir, "ech-proxy.exe")
	oldBinary := bytes.Repeat([]byte("OLD_VERSION_BIN_"), 128)
	newBinary := bytes.Repeat([]byte("NEW_VERSION_BIN_"), 128)
	newSum := sha256.Sum256(newBinary)
	newHashHex := hex.EncodeToString(newSum[:])

	if err := os.WriteFile(exePath, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums.txt":
			_, _ = w.Write([]byte(newHashHex + "  ech-proxy-windows-amd64.exe\n"))
		case "/ech-proxy-windows-amd64.exe":
			_, _ = w.Write(newBinary)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	upd := NewUpdater(UpdaterOptions{
		ExePath:         exePath,
		GOOS:            "windows",
		GOARCH:          "amd64",
		ChecksumsURL:    srv.URL + "/checksums.txt",
		DownloadBaseURL: srv.URL,
		MinBinaryBytes:  512,
		FetchFn:         echproxy.FetchBytes,
	})

	staged, err := upd.CheckAndDownloadOnce()
	if err != nil || !staged || !upd.IsUpdateStaged() {
		t.Fatalf("CheckAndDownloadOnce got staged=%v, err=%v", staged, err)
	}
	if _, err := os.Stat(upd.StagedPath()); err != nil {
		t.Fatalf("staged file %s missing: %v", upd.StagedPath(), err)
	}

	replaced, err := upd.ApplyStagedUpdateOnExit()
	if err != nil || !replaced {
		t.Fatalf("ApplyStagedUpdateOnExit got replaced=%v, err=%v", replaced, err)
	}
	gotAfterExit, err := os.ReadFile(exePath)
	if err != nil || !bytes.Equal(gotAfterExit, newBinary) {
		t.Fatalf("executable was not replaced with new binary on exit")
	}

	stagedAgain, err := upd.CheckAndDownloadOnce()
	if err != nil || stagedAgain {
		t.Errorf("second CheckAndDownloadOnce after update should report already up to date, got staged=%v err=%v", stagedAgain, err)
	}
}

func TestRunToolActionsCheckHostsCAAndLogs(t *testing.T) {
	var out bytes.Buffer
	code := runToolAction(CLICommand{Action: "help"}, &out)
	if code != 0 || !strings.Contains(out.String(), "--skip-ad-script") || !strings.Contains(out.String(), "--skip-ad-block") || !strings.Contains(out.String(), "-dual") {
		t.Errorf("help action returned code=%d, out=%q", code, out.String())
	}

	out.Reset()
	code = runToolAction(CLICommand{
		Action:    "check",
		ConfigURL: "../certs/l.moonchan.xyz/upstream.json",
	}, &out)
	if code != 0 || !strings.Contains(out.String(), "OK: no issues found") {
		t.Errorf("check valid config returned code=%d, out=%q", code, out.String())
	}

	out.Reset()
	code = runToolAction(CLICommand{
		Action:    "check",
		ConfigURL: filepath.Join(t.TempDir(), "nonexistent.json"),
	}, &out)
	if code != 2 {
		t.Errorf("check nonexistent file returned code=%d, want 2", code)
	}

	out.Reset()
	dir := t.TempDir()
	exportFile := filepath.Join(dir, "exported-ca.crt")
	code = runToolAction(CLICommand{
		Action:       "ca-export",
		DataDir:      dir,
		CAExportPath: exportFile,
	}, &out)
	if code != 0 {
		t.Fatalf("ca-export returned code=%d, out=%q", code, out.String())
	}
	if b, err := os.ReadFile(exportFile); err != nil || !strings.Contains(string(b), "BEGIN CERTIFICATE") {
		t.Errorf("exported CA file invalid: err=%v", err)
	}

	logDir := t.TempDir()
	mgr, err := echproxy.NewLogger(echproxy.LoggerOptions{
		LogDir:     logDir,
		ConsoleOut: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	_, _ = mgr.Write([]byte("hello from local log\n"))
	mgr.RecordCrash("test-comp", "boom", []byte("stack-line-1\n"))
	_ = mgr.Close()

	out.Reset()
	if code := runToolAction(CLICommand{Action: "logs-tail", LogDir: logDir}, &out); code != 0 || !strings.Contains(out.String(), "hello from local log") {
		t.Errorf("logs-tail failed: code=%d out=%q", code, out.String())
	}

	out.Reset()
	if code := runToolAction(CLICommand{Action: "logs-crash", LogDir: logDir}, &out); code != 0 || !strings.Contains(out.String(), "boom") {
		t.Errorf("logs-crash failed: code=%d out=%q", code, out.String())
	}

	out.Reset()
	if code := runToolAction(CLICommand{Action: "logs-clean", LogDir: logDir}, &out); code != 0 {
		t.Errorf("logs-clean failed: code=%d out=%q", code, out.String())
	}
}