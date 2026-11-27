package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
)

// pacQueryAll 解析 PAC URL 上的路由参数，判断是否为「全代理」版本。
func pacQueryAll(t *testing.T, pacURL string) bool {
	t.Helper()
	u, err := url.Parse(pacURL)
	if err != nil {
		t.Fatalf("parse PAC URL %q: %v", pacURL, err)
	}
	return u.Query().Get("mode") == "all"
}

// TestRefreshPACHotToggle 覆盖托盘「全代理」热开关的核心行为：
// 在 PAC 模式下切换 ALL 必须重新写入系统 PAC（带 mode=all），且**不得压栈**，
// 否则用户反复勾选几次后，退出恢复栈里会堆满同一份 PAC 记录。
func TestRefreshPACHotToggle(t *testing.T) {
	drv := &stubSysProxyDriver{}
	mgr := NewSysProxyManager("127.0.0.1:8443", drv)
	var clock int64 = 1000
	mgr.nowUnix = func() int64 { clock++; return clock }

	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC): %v", err)
	}
	baseDepth := mgr.HistoryDepth()
	st, _ := drv.Query()
	if pacQueryAll(t, st.AutoConfigURL) {
		t.Fatalf("initial PAC should be whitelist mode, got %q", st.AutoConfigURL)
	}

	mgr.SetAllMode(true)
	pacURL, applied, err := mgr.RefreshPAC()
	if err != nil || !applied {
		t.Fatalf("RefreshPAC(all=true) applied=%v err=%v", applied, err)
	}
	if !pacQueryAll(t, pacURL) {
		t.Fatalf("PAC URL after enabling ALL = %q, want mode=all", pacURL)
	}
	st, _ = drv.Query()
	if st.Mode != SysProxyPAC || st.AutoConfigURL != pacURL {
		t.Fatalf("system driver state = %+v, want PAC %q", st, pacURL)
	}
	if got := mgr.HistoryDepth(); got != baseDepth {
		t.Fatalf("hot toggle must not push restore stack: depth %d -> %d", baseDepth, got)
	}

	mgr.SetAllMode(false)
	offURL, applied, err := mgr.RefreshPAC()
	if err != nil || !applied {
		t.Fatalf("RefreshPAC(all=false) applied=%v err=%v", applied, err)
	}
	if pacQueryAll(t, offURL) {
		t.Fatalf("PAC URL after disabling ALL = %q, want whitelist version", offURL)
	}
	if got := mgr.HistoryDepth(); got != baseDepth {
		t.Fatalf("hot toggle back must not push restore stack: depth %d -> %d", baseDepth, got)
	}
}

// TestRefreshPACOutsidePACModeIsNoop 确保热刷新不会在直连 / 全局代理下偷偷改系统代理。
func TestRefreshPACOutsidePACModeIsNoop(t *testing.T) {
	drv := &stubSysProxyDriver{}
	mgr := NewSysProxyManager("127.0.0.1:8443", drv)
	mgr.SetAllMode(true)
	_, applied, err := mgr.RefreshPAC()
	if err != nil || applied {
		t.Fatalf("RefreshPAC outside PAC mode applied=%v err=%v, want no-op", applied, err)
	}
	if st, _ := drv.Query(); st.Mode == SysProxyPAC {
		t.Fatalf("driver state changed to PAC (%+v), want untouched", st)
	}
	if mgr.ShouldRefreshPAC() {
		t.Fatal("ShouldRefreshPAC must be false when not in PAC mode")
	}
}

// TestShouldRefreshPACDetectsStaleScope 覆盖启动阶段的对齐判断：
// 系统残留的白名单版 PAC + 本次 -all 启动 => 需要刷新；两者一致则不需要。
func TestShouldRefreshPACDetectsStaleScope(t *testing.T) {
	drv := &stubSysProxyDriver{}
	mgr := NewSysProxyManager("127.0.0.1:8443", drv)
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC): %v", err)
	}
	if mgr.ShouldRefreshPAC() {
		t.Fatal("freshly applied whitelist PAC matches allMode=false, must not refresh")
	}

	mgr.SetAllMode(true)
	if !mgr.ShouldRefreshPAC() {
		t.Fatal("stale whitelist PAC with allMode=true must trigger refresh")
	}
	if _, applied, err := mgr.RefreshPAC(); err != nil || !applied {
		t.Fatalf("RefreshPAC: applied=%v err=%v", applied, err)
	}
	if mgr.ShouldRefreshPAC() {
		t.Fatal("after refresh, PAC scope and allMode agree, must not refresh again")
	}
}

// TestPACIsGlobal 校验 PAC URL 全代理识别，包含 mode=all / global=1 与非法输入。
func TestPACIsGlobal(t *testing.T) {
	cases := map[string]bool{
		"http://127.0.0.1:8443/proxy.pac":                false,
		"http://127.0.0.1:8443/proxy.pac?mode=all":       true,
		"http://127.0.0.1:8443/proxy.pac?t=123&mode=all": true,
		"http://127.0.0.1:8443/proxy.pac?global=1":       true,
		"http://127.0.0.1:8443/proxy.pac?mode=whitelist": false,
		"": false,
		"http://127.0.0.1:8443/proxy.pac?fallback=1.2.3.4": false,
	}
	for in, want := range cases {
		if got := pacIsGlobal(in); got != want {
			t.Errorf("pacIsGlobal(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestTrayAllModeToggle 端到端串联托盘控制器：菜单项勾选状态、AdScriptManager
// 与 SysProxyManager 三方状态必须同步翻转，且系统 PAC 立即带上 mode=all。
func TestTrayAllModeToggle(t *testing.T) {
	drv := &stubSysProxyDriver{}
	mgr := NewSysProxyManager("127.0.0.1:8443", drv)
	if err := mgr.SetMode(SysProxyPAC); err != nil {
		t.Fatalf("SetMode(PAC): %v", err)
	}
	ad := rewrite.NewAdScriptManager(rewrite.AdScriptOptions{Enabled: false})
	tc := NewTrayController("127.0.0.1:8443", "", "", mgr, &stubConsoleDriver{}, func() {})
	tc.AdScript = ad

	if tc.AllMode() {
		t.Fatal("ALL mode must start disabled")
	}
	if tc.HandleCommand(TrayCmdAllMode) {
		t.Fatal("ALL toggle must not request process exit")
	}
	if !tc.AllMode() || !mgr.AllMode() || !ad.AllMode() {
		t.Fatalf("ALL state not propagated: tray=%v sysproxy=%v ad=%v", tc.AllMode(), mgr.AllMode(), ad.AllMode())
	}
	st, _ := drv.Query()
	if !pacQueryAll(t, st.AutoConfigURL) {
		t.Fatalf("system PAC after enabling ALL = %q, want mode=all", st.AutoConfigURL)
	}

	var checked *TrayMenuItem
	for i := range tc.MenuItems() {
		if tc.MenuItems()[i].ID == TrayCmdAllMode {
			checked = &tc.MenuItems()[i]
		}
	}
	if checked == nil || !checked.Checked {
		t.Fatalf("tray menu ALL item should be checked, got %+v", checked)
	}

	if tc.HandleCommand(TrayCmdAllMode) {
		t.Fatal("ALL toggle back must not request process exit")
	}
	if tc.AllMode() || mgr.AllMode() || ad.AllMode() {
		t.Fatalf("ALL state not cleared: tray=%v sysproxy=%v ad=%v", tc.AllMode(), mgr.AllMode(), ad.AllMode())
	}
	st, _ = drv.Query()
	if pacQueryAll(t, st.AutoConfigURL) {
		t.Fatalf("system PAC after disabling ALL = %q, want whitelist version", st.AutoConfigURL)
	}
	if !strings.Contains(st.AutoConfigURL, "/proxy.pac") {
		t.Fatalf("unexpected PAC URL %q", st.AutoConfigURL)
	}
}

// TestTrayAllModeOpensPACFromDirect 在直连状态下勾选 ALL，应顺带打开 PAC，
// 否则开关看起来毫无效果（用户最容易踩的坑）。
func TestTrayAllModeOpensPACFromDirect(t *testing.T) {
	drv := &stubSysProxyDriver{}
	mgr := NewSysProxyManager("127.0.0.1:8443", drv)
	tc := NewTrayController("127.0.0.1:8443", "", "", mgr, &stubConsoleDriver{}, func() {})
	tc.AdScript = rewrite.NewAdScriptManager(rewrite.AdScriptOptions{Enabled: false})

	if err := tc.SetAllMode(true); err != nil {
		t.Fatalf("SetAllMode(true) from direct: %v", err)
	}
	st, _ := drv.Query()
	if st.Mode != SysProxyPAC {
		t.Fatalf("system proxy mode = %s, want pac", st.Mode)
	}
	if !pacQueryAll(t, st.AutoConfigURL) {
		t.Fatalf("system PAC = %q, want mode=all", st.AutoConfigURL)
	}
}

// TestDefaultAllModeReachesTrayMenu 锁死「-all 默认开启」这条契约的最后一公里：
// parseCLIArgs 默认值 → SysProxyManager → 托盘菜单勾选状态。
//
// 中间这一段（把 cmd.AllMode 灌进 manager、再由 MenuItems() 读回来渲染）此前没有任何
// 测试覆盖：已有用例要么只断言 CLICommand.AllMode 字段，要么手动 SetAllMode 走热切换。
// 于是「双击启动后托盘没勾选」这种反馈无法用测试证伪——链路任何一段被改坏，现象都一样。
func TestDefaultAllModeReachesTrayMenu(t *testing.T) {
	noEnv := func(string) string { return "" }

	// 模拟双击：没有任何参数，文件名是普通（非 .443 / .8443）名字。
	cmd, err := parseCLIArgs("ech-proxy-windows-amd64.exe", nil, noEnv)
	if err != nil {
		t.Fatalf("parseCLIArgs: %v", err)
	}
	if !cmd.AllMode {
		t.Fatalf("默认 AllMode = false；subAll 自 7d7c248 起为 true，双击启动必须开启全代理")
	}

	// 复刻 main() 的接线顺序：先建 manager 并灌入 AllMode，再建托盘控制器。
	drv := &stubSysProxyDriver{}
	mgr := NewSysProxyManager("127.0.0.1:8443", drv)
	mgr.SetAllMode(cmd.AllMode)
	ad := rewrite.NewAdScriptManager(rewrite.AdScriptOptions{Enabled: false, AllMode: cmd.AllMode})
	tc := NewTrayController("127.0.0.1:8443", "", "", mgr, &stubConsoleDriver{}, func() {})
	tc.AdScript = ad

	if !tc.AllMode() {
		t.Fatal("TrayController.AllMode() = false，期望 true")
	}
	items := tc.MenuItems()
	var all *TrayMenuItem
	for i := range items {
		if items[i].ID == TrayCmdAllMode {
			all = &items[i]
		}
	}
	if all == nil {
		t.Fatal("托盘菜单里找不到 TrayCmdAllMode 项")
	}
	if !all.Checked {
		t.Fatalf("菜单项 %q 未勾选，期望 Checked=true", all.Title)
	}
}
