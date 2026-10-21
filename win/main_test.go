package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestParseCLIArgsSubcommandsFlagsAndSysProxyDefaults(t *testing.T) {
	noEnv := func(string) string { return "" }

	// 1. 默认启动为 smart 模式，监听 127.0.0.1:8443，默认自动开启 PAC 系统代理与系统托盘
	c1, err := parseCLIArgs("ech-proxy", nil, noEnv)
	if err != nil || c1.Action != "run" || c1.Mode != "smart" || c1.Addr != "127.0.0.1:8443" || c1.LocalProxy {
		t.Errorf("default parseCLIArgs = %+v, %v", c1, err)
	}
	if c1.SysProxy != SysProxyPAC || !c1.EnableTray || c1.HideConsole {
		t.Errorf("smart mode defaults: SysProxy=%q EnableTray=%v HideConsole=%v, want pac/true/false", c1.SysProxy, c1.EnableTray, c1.HideConsole)
	}

	// 2. .443.exe 自动进入 local 模式并监听 127.0.0.1:443（默认不改系统代理 SysProxyOff，保留托盘）
	c2, err := parseCLIArgs("ech-proxy.443.exe", nil, noEnv)
	if err != nil || !c2.LocalProxy || c2.Addr != "127.0.0.1:443" || c2.FallbackAddr != "127.0.0.1:8443" || c2.SysProxy != SysProxyOff {
		t.Errorf(".443.exe parseCLIArgs = %+v, %v", c2, err)
	}

	// 3. 显式传入 -sys-proxy global -hide-console -no-tray
	c3, err := parseCLIArgs("ech-proxy", []string{"-sys-proxy", "global", "-hide-console", "-no-tray"}, noEnv)
	if err != nil || c3.SysProxy != SysProxyGlobal || !c3.HideConsole || c3.EnableTray {
		t.Errorf("explicit tray/sys-proxy flags failed: %+v, %v", c3, err)
	}

	// 4. 子命令 sysproxy pac / global / clear / status
	for _, sub := range []struct {
		arg  string
		want string
	}{
		{"pac", "sysproxy-pac"},
		{"global", "sysproxy-global"},
		{"clear", "sysproxy-clear"},
		{"status", "sysproxy-status"},
	} {
		cmd, err := parseCLIArgs("ech-proxy", []string{"sysproxy", sub.arg}, noEnv)
		if err != nil || cmd.Action != sub.want {
			t.Errorf("sysproxy %s got Action=%q, err=%v; want %q", sub.arg, cmd.Action, err, sub.want)
		}
	}

	// 5. 子命令 check 与 -check-config 等价
	c4, err := parseCLIArgs("ech-proxy", []string{"check", "-config", "my.json"}, noEnv)
	if err != nil || c4.Action != "check" || c4.ConfigURL != "my.json" {
		t.Errorf("subcommand 'check' parseCLIArgs = %+v, %v", c4, err)
	}

	// 6. -local 与 -http 互斥报错
	if _, err := parseCLIArgs("ech-proxy", []string{"-local", "-http"}, noEnv); err == nil {
		t.Error("expected error when both -local and -http are set")
	}
}

func TestSysProxyManagerLifecycleAndExitCleanup(t *testing.T) {
	drv := &noopSysProxyDriver{}
	mgr := NewSysProxyManager("0.0.0.0:8443", drv)
	mgr.nowUnix = func() int64 { return 1700000000 }

	// 1. 切换为 PAC 模式（带 ?t= 时间戳防缓存参数）
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC): %v", err)
	}
	st, _ := drv.Query()
	wantPAC := "http://127.0.0.1:8443/proxy.pac?t=1700000000"
	if st.Mode != SysProxyPAC || st.AutoConfigURL != wantPAC {
		t.Errorf("after SetMode(PAC): state=%+v, want AutoConfigURL=%q", st, wantPAC)
	}

	// 2. 切换为 Global 全局代理模式
	if err := mgr.SetMode(SysProxyGlobal); err != nil {
		t.Fatalf("SetMode(Global): %v", err)
	}
	st, _ = drv.Query()
	if st.Mode != SysProxyGlobal || st.ProxyServer != "127.0.0.1:8443" || !strings.Contains(st.ProxyBypass, "<local>") {
		t.Errorf("after SetMode(Global): state=%+v", st)
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

	var copiedText, installedCA string
	exited := false
	openedURLs := make(chan string, 8)

	tc := NewTrayController("127.0.0.1:8443", "https://l.moonchan.xyz:8443", "/tmp/ca.pem", sysMgr, console, func() {
		exited = true
	})
	tc.OpenURLFn = func(u string) { openedURLs <- u }
	tc.CopyClipboardFn = func(s string) error { copiedText = s; return nil }
	tc.InstallCAFn = func(p string) error { installedCA = p; return nil }

	// 1. 测试双击/菜单切换 Console 窗口显隐
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

	// 2. 测试托盘右键切换 PAC / Global / Clear 模式与勾选状态
	tc.HandleCommand(TrayCmdSysProxyPAC)
	if sysMgr.Mode() != SysProxyPAC || !strings.Contains(tc.TooltipText(), "系统PAC自动分流") {
		t.Errorf("expected PAC mode and tooltip, got mode=%q tooltip=%q", sysMgr.Mode(), tc.TooltipText())
	}

	tc.HandleCommand(TrayCmdSysProxyGlobal)
	if sysMgr.Mode() != SysProxyGlobal || !strings.Contains(tc.TooltipText(), "全局系统代理") {
		t.Errorf("expected Global mode and tooltip, got mode=%q tooltip=%q", sysMgr.Mode(), tc.TooltipText())
	}

	// 3. 测试复制 PAC URL
	tc.HandleCommand(TrayCmdCopyPACURL)
	if copiedText != "http://127.0.0.1:8443/proxy.pac" {
		t.Errorf("copied PAC URL = %q, want http://127.0.0.1:8443/proxy.pac", copiedText)
	}

	// 3b. 测试「反馈 / 聊天」菜单项打开项目反馈页（外部链接）
	tc.HandleCommand(TrayCmdFeedbackChat)
	select {
	case u := <-openedURLs:
		if u != "https://chatto.moonchan.xyz" {
			t.Errorf("feedback/chat URL = %q, want https://chatto.moonchan.xyz", u)
		}
	case <-time.After(time.Second):
		t.Error("TrayCmdFeedbackChat did not open a URL")
	}

	// 3c. 确认右键菜单结构包含「反馈 / 聊天」项
	var foundFeedback bool
	for _, mi := range tc.MenuItems() {
		if mi.ID == TrayCmdFeedbackChat {
			foundFeedback = true
			if !strings.Contains(mi.Title, "反馈") || !strings.Contains(mi.Title, "Chat") {
				t.Errorf("feedback menu title = %q, want bilingual 反馈/Chat", mi.Title)
			}
		}
	}
	if !foundFeedback {
		t.Error("MenuItems() missing TrayCmdFeedbackChat entry")
	}

	// 4. 测试退出命令自动清理系统代理并触发回调
	if shouldExit := tc.HandleCommand(TrayCmdExit); !shouldExit || !exited {
		t.Errorf("TrayCmdExit should return true and invoke OnExit")
	}
	if sysMgr.Mode() != SysProxyOff {
		t.Errorf("TrayCmdExit must clean up system proxy, got mode=%q", sysMgr.Mode())
	}
	_ = installedCA
}

func TestRunToolActionsCheckHostsAndCA(t *testing.T) {
	// 1. 测试 check 子命令校验生产配置返回 0
	var out bytes.Buffer
	code := runToolAction(CLICommand{
		Action:    "check",
		ConfigURL: "../certs/l.moonchan.xyz/upstream.json",
	}, &out)
	if code != 0 || !strings.Contains(out.String(), "OK: no issues found") {
		t.Errorf("check valid config returned code=%d, out=%q", code, out.String())
	}

	// 2. 测试 check 子命令对不存在文件返回 2
	out.Reset()
	code = runToolAction(CLICommand{
		Action:    "check",
		ConfigURL: filepath.Join(t.TempDir(), "nonexistent.json"),
	}, &out)
	if code != 2 {
		t.Errorf("check nonexistent file returned code=%d, want 2", code)
	}

	// 3. 测试 ca export 子命令
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
}
