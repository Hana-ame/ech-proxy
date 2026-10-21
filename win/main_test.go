package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

// TestFilenameIs443 pins the exact-suffix rule: only a filename ending in
// ".443.exe" selects port 443. A substring hit in the middle of the name must
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

func TestParseCLIArgsWhitelistIPModeAndAllMode(t *testing.T) {
	noEnv := func(string) string { return "" }

	// 1. 默认启动为 smart 白名单模式，监听 127.0.0.1:8443，ipmode 默认为 ipv4 ("v4")，AllMode=false，WhitelistURL=""
	c1, err := parseCLIArgs("ech-proxy", nil, noEnv)
	if err != nil || c1.Action != "run" || c1.Mode != "smart" || c1.AllMode || c1.IPMode != "v4" || c1.WhitelistURL != "" {
		t.Errorf("default parseCLIArgs = %+v, %v (want IPMode=v4)", c1, err)
	}
	if c1.SysProxy != SysProxyPAC || !c1.EnableTray || c1.HideConsole || c1.NoAdScript {
		t.Errorf("smart mode defaults: SysProxy=%q EnableTray=%v HideConsole=%v NoAdScript=%v", c1.SysProxy, c1.EnableTray, c1.HideConsole, c1.NoAdScript)
	}

	// 2. 验证 ipmode flag: [default]=ipv4 ("v4"), dual = 双栈 ("dual"), 4 = ipv4 only ("v4"), 6 = ipv6 only ("v6")
	cIPDual, err := parseCLIArgs("ech-proxy", []string{"-ipmode", "dual"}, noEnv)
	if err != nil || cIPDual.IPMode != "dual" {
		t.Errorf("-ipmode dual got IPMode=%q, err=%v; want dual", cIPDual.IPMode, err)
	}
	cIP4, err := parseCLIArgs("ech-proxy", []string{"-ipmode", "4"}, noEnv)
	if err != nil || cIP4.IPMode != "v4" {
		t.Errorf("-ipmode 4 got IPMode=%q, err=%v; want v4", cIP4.IPMode, err)
	}
	cIPv4, err := parseCLIArgs("ech-proxy", []string{"-ipmode", "ipv4"}, noEnv)
	if err != nil || cIPv4.IPMode != "v4" {
		t.Errorf("-ipmode ipv4 got IPMode=%q, err=%v; want v4", cIPv4.IPMode, err)
	}
	cIP6, err := parseCLIArgs("ech-proxy", []string{"-ipmode", "6"}, noEnv)
	if err != nil || cIP6.IPMode != "v6" {
		t.Errorf("-ipmode 6 got IPMode=%q, err=%v; want v6", cIP6.IPMode, err)
	}
	if _, err := parseCLIArgs("ech-proxy", []string{"-ipmode", "invalid"}, noEnv); err == nil {
		t.Error("expected error for invalid -ipmode value")
	}

	// 3. 验证 all 模式（-all / -mode all / 子命令 all）
	for _, args := range [][]string{{"-all"}, {"-mode", "all"}, {"all"}} {
		cAll, err := parseCLIArgs("ech-proxy", args, noEnv)
		if err != nil || !cAll.AllMode {
			t.Errorf("args %v got AllMode=%v, err=%v; want AllMode=true", args, cAll.AllMode, err)
		}
	}

	// 4. 显式传入 -whitelist-url、-ad-script-url、-no-ad-script 等参数
	c3, err := parseCLIArgs("ech-proxy", []string{
		"-sys-proxy", "global",
		"-hide-console",
		"-no-tray",
		"-no-ad-script",
		"-all",
		"-ipmode", "4",
		"-ad-script-url", "https://example.com/custom.js",
		"-whitelist-url", "https://example.com/whitelist.json",
		"-ad-script-interval", "10m",
		"-log-dir", "/tmp/my-logs",
	}, noEnv)
	if err != nil || c3.SysProxy != SysProxyGlobal || !c3.HideConsole || c3.EnableTray || !c3.NoAdScript ||
		!c3.AllMode || c3.IPMode != "v4" ||
		c3.AdScriptURL != "https://example.com/custom.js" ||
		c3.WhitelistURL != "https://example.com/whitelist.json" ||
		c3.AdScriptInterval != 10*time.Minute || c3.LogDir != "/tmp/my-logs" {
		t.Errorf("explicit flags failed: %+v, %v", c3, err)
	}

	// 5. 子命令 sysproxy pac / global / clear / status 与 logs path / tail / crash / clean
	for _, sub := range []struct {
		args []string
		want string
	}{
		{[]string{"sysproxy", "pac"}, "sysproxy-pac"},
		{[]string{"sysproxy", "global"}, "sysproxy-global"},
		{[]string{"sysproxy", "clear"}, "sysproxy-clear"},
		{[]string{"sysproxy", "status"}, "sysproxy-status"},
		{[]string{"logs", "path"}, "logs-path"},
		{[]string{"logs", "tail"}, "logs-tail"},
		{[]string{"logs", "crash"}, "logs-crash"},
		{[]string{"logs", "clean"}, "logs-clean"},
	} {
		cmd, err := parseCLIArgs("ech-proxy", sub.args, noEnv)
		if err != nil || cmd.Action != sub.want {
			t.Errorf("%v got Action=%q, err=%v; want %q", sub.args, cmd.Action, err, sub.want)
		}
	}

	// 6. -local 与 -http 互斥报错
	if _, err := parseCLIArgs("ech-proxy", []string{"-local", "-http"}, noEnv); err == nil {
		t.Error("expected error when both -local and -http are set")
	}
}

func TestSysProxyManagerLifecycleAndAllModePAC(t *testing.T) {
	drv := &noopSysProxyDriver{}
	mgr := NewSysProxyManager("0.0.0.0:8443", drv)
	mgr.nowUnix = func() int64 { return 1700000000 }

	// 1. 默认白名单 PAC 模式
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC): %v", err)
	}
	st, _ := drv.Query()
	wantPAC := "http://127.0.0.1:8443/proxy.pac?t=1700000000"
	if st.Mode != SysProxyPAC || st.AutoConfigURL != wantPAC {
		t.Errorf("after SetMode(PAC): state=%+v, want AutoConfigURL=%q", st, wantPAC)
	}

	// 2. 开启 all 模式后，PAC URL 自动附带 ?mode=all
	mgr.SetAllMode(true)
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC all): %v", err)
	}
	st, _ = drv.Query()
	wantAllPAC := "http://127.0.0.1:8443/proxy.pac?mode=all&t=1700000000"
	if st.AutoConfigURL != wantAllPAC {
		t.Errorf("after SetAllMode(true): AutoConfigURL=%q, want %q", st.AutoConfigURL, wantAllPAC)
	}

	// 3. 退出时自动清理系统代理（防止浏览器断网）
	mgr.CleanupOnExit()
	st, _ = drv.Query()
	if st.Mode != SysProxyOff || st.AutoConfigURL != "" || st.ProxyServer != "" {
		t.Errorf("after CleanupOnExit: state=%+v, want Mode=off", st)
	}
}

func TestTrayControllerConsoleToggleAndMenuCommands(t *testing.T) {
	drv := &noopSysProxyDriver{}
	sysMgr := NewSysProxyManager("127.0.0.1:8443", drv)
	console := &memoryConsoleDriver{visible: true}
	adMgr := echproxy.NewAdScriptManager(echproxy.AdScriptOptions{Enabled: true})

	var openedURL, copiedText, installedCA string
	exited := false

	tc := NewTrayController("127.0.0.1:8443", "https://l.moonchan.xyz:8443", "/tmp/ca.pem", sysMgr, console, func() {
		exited = true
	})
	tc.AdScript = adMgr
	tc.LogDir = "/tmp/ech-logs"
	tc.OpenURLFn = func(u string) { openedURL = u }
	tc.CopyClipboardFn = func(s string) error { copiedText = s; return nil }
	tc.InstallCAFn = func(p string) error { installedCA = p; return nil }

	if !tc.IsConsoleVisible() {
		t.Fatal("console should start visible")
	}
	tc.HandleCommand(TrayCmdToggleConsole)
	if tc.IsConsoleVisible() {
		t.Error("console should be hidden after first toggle")
	}
	tc.HandleCommand(TrayCmdToggleConsole)
	if !tc.IsConsoleVisible() {
		t.Error("console should be visible after second toggle")
	}

	tc.HandleCommand(TrayCmdToggleAdScript)
	if adMgr.Enabled() {
		t.Error("adScript should be disabled after toggle")
	}
	tc.HandleCommand(TrayCmdToggleAdScript)
	if !adMgr.Enabled() {
		t.Error("adScript should be enabled after second toggle")
	}

	if shouldExit := tc.HandleCommand(TrayCmdExit); !shouldExit || !exited {
		t.Errorf("TrayCmdExit should return true and invoke OnExit")
	}
	_ = openedURL
	_ = copiedText
	_ = installedCA
}

func TestRunToolActionsCheckHostsCAAndLogs(t *testing.T) {
	var out bytes.Buffer
	code := runToolAction(CLICommand{
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
	logFile := filepath.Join(logDir, "ech-proxy.log")
	_ = os.WriteFile(logFile, []byte("line1\nline2\n"), 0o644)

	out.Reset()
	if code := runToolAction(CLICommand{Action: "logs-tail", LogDir: logDir}, &out); code != 0 || !strings.Contains(out.String(), "line2") {
		t.Errorf("logs-tail failed: code=%d out=%q", code, out.String())
	}
	out.Reset()
	if code := runToolAction(CLICommand{Action: "logs-clean", LogDir: logDir}, &out); code != 0 {
		t.Errorf("logs-clean failed: code=%d out=%q", code, out.String())
	}
}