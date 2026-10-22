package main

import "sync"

// 本文件提供可在任意 GOOS（含 Windows 目标）编译的测试替身。
//
// 背景：真实的 noopSysProxyDriver / memoryConsoleDriver 分别定义在
// sysproxy_other.go 与 tray_other.go（均带 //go:build !windows），
// 而 win/main_test.go 没有构建标签；CI 对 GOOS=windows 执行 go vet 时，
// 测试包会因 undefined 而编译失败。这里给出可移植的等价实现。

type stubSysProxyDriver struct {
	mu    sync.Mutex
	state SysProxyState
}

var _ SysProxyDriver = (*stubSysProxyDriver)(nil)

func (d *stubSysProxyDriver) ApplyPAC(pacURL string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = SysProxyState{Mode: SysProxyPAC, AutoConfigURL: pacURL}
	return nil
}

func (d *stubSysProxyDriver) ApplyGlobal(proxyHostPort, bypass string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = SysProxyState{Mode: SysProxyGlobal, ProxyServer: proxyHostPort, ProxyBypass: bypass}
	return nil
}

func (d *stubSysProxyDriver) Clear() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = SysProxyState{Mode: SysProxyOff}
	return nil
}

func (d *stubSysProxyDriver) Query() (SysProxyState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state, nil
}

func (d *stubSysProxyDriver) Restore(state SysProxyState) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state = state
	return nil
}

type stubConsoleDriver struct {
	mu      sync.Mutex
	visible bool
}

var _ ConsoleWindowDriver = (*stubConsoleDriver)(nil)

func (d *stubConsoleDriver) IsVisible() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.visible
}

func (d *stubConsoleDriver) SetVisible(visible bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.visible = visible
}

func (d *stubConsoleDriver) DisableCloseButton() {}
