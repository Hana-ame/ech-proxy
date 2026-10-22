//go:build windows

package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const (
	internetSettingsRegPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	// WinINet InternetSetOptionW 常量（对齐 V2rayN 系统代理设置实现，兼容 Windows 7~11 32/64 位）
	internetOptionRefresh             = 37
	internetOptionSettingsChanged     = 39
	internetOptionPerConnectionOption = 75

	internetPerConnFlags         = 1
	internetPerConnProxyServer   = 2
	internetPerConnProxyBypass   = 3
	internetPerConnAutoConfigURL = 4

	proxyTypeDirect       = 0x00000001
	proxyTypeProxy        = 0x00000002
	proxyTypeAutoProxyURL = 0x00000004
	proxyTypeAutoDetect   = 0x00000008

	// ptrSize 在 32 位 Windows (GOARCH=386) 下为 4，在 64 位 Windows (GOARCH=amd64) 下为 8。
	ptrSize = unsafe.Sizeof(uintptr(0))
)

var (
	modwininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modwininet.NewProc("InternetSetOptionW")
)

func safeCallProc(p *syscall.LazyProc, a ...uintptr) (uintptr, uintptr, error) {
	if p == nil {
		return 0, 0, syscall.EINVAL
	}
	if err := p.Find(); err != nil {
		return 0, 0, err
	}
	return p.Call(a...)
}

// internetPerConnOption 对应 Win32 <wininet.h> INTERNET_PER_CONN_OPTIONW 结构体。
type internetPerConnOption struct {
	dwOption uint32
	dwValue  [8 / ptrSize]uintptr
}

// internetPerConnOptionList 对应 Win32 INTERNET_PER_CONN_OPTION_LISTW 结构体。
type internetPerConnOptionList struct {
	dwSize        uint32
	pszConnection *uint16
	dwOptionCount uint32
	dwOptionError uint32
	pOptions      uintptr
}

type windowsSysProxyDriver struct{}

func newPlatformSysProxyDriver() SysProxyDriver {
	return &windowsSysProxyDriver{}
}

// ApplyPAC 设置 Windows 系统代理为 PAC 自动配置脚本模式（写入注册表并调用 WinINet 立即刷新）。
func (d *windowsSysProxyDriver) ApplyPAC(pacURL string) error {
	if err := writeInternetSettingsReg(false, "", "", pacURL); err != nil {
		return err
	}
	flags := uint32(proxyTypeDirect | proxyTypeAutoProxyURL)
	updateDefaultConnectionSettings(flags)
	_ = applyWinINetPerConn(flags, "", "", pacURL)
	notifyWinINetRefresh()
	return nil
}

// ApplyGlobal 设置 Windows 系统代理为全局 HTTP/HTTPS 代理模式。
func (d *windowsSysProxyDriver) ApplyGlobal(proxyHostPort, bypass string) error {
	if err := writeInternetSettingsReg(true, proxyHostPort, bypass, ""); err != nil {
		return err
	}
	flags := uint32(proxyTypeDirect | proxyTypeProxy)
	updateDefaultConnectionSettings(flags)
	_ = applyWinINetPerConn(flags, proxyHostPort, bypass, "")
	notifyWinINetRefresh()
	return nil
}

// Clear 清除 Windows 系统代理与 PAC 设置，恢复直连模式。
func (d *windowsSysProxyDriver) Clear() error {
	if err := writeInternetSettingsReg(false, "", "", ""); err != nil {
		return err
	}
	flags := uint32(proxyTypeDirect)
	updateDefaultConnectionSettings(flags)
	_ = applyWinINetPerConn(flags, "", "", "")
	notifyWinINetRefresh()
	return nil
}

// Restore 将 Windows 系统代理还原为指定状态（无损恢复全局代理、自动代理、PAC 及原始标志位）。
func (d *windowsSysProxyDriver) Restore(st SysProxyState) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsRegPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry %s: %w", internetSettingsRegPath, err)
	}
	defer k.Close()

	var enableVal uint32
	if st.ProxyEnable {
		enableVal = 1
	}
	_ = k.SetDWordValue("ProxyEnable", enableVal)

	if st.ProxyServer != "" {
		_ = k.SetStringValue("ProxyServer", st.ProxyServer)
	} else {
		_ = k.DeleteValue("ProxyServer")
	}

	if st.ProxyBypass != "" {
		_ = k.SetStringValue("ProxyOverride", st.ProxyBypass)
	} else {
		_ = k.DeleteValue("ProxyOverride")
	}

	if strings.TrimSpace(st.AutoConfigURL) != "" {
		_ = k.SetStringValue("AutoConfigURL", st.AutoConfigURL)
	} else {
		_ = k.DeleteValue("AutoConfigURL")
	}

	var autoDetectVal uint32
	if st.AutoDetect {
		autoDetectVal = 1
	}
	_ = k.SetDWordValue("AutoDetect", autoDetectVal)

	// 计算 WinINet Flags
	flags := uint32(proxyTypeDirect)
	if st.ProxyEnable && strings.TrimSpace(st.ProxyServer) != "" {
		flags |= proxyTypeProxy
	}
	if strings.TrimSpace(st.AutoConfigURL) != "" {
		flags |= proxyTypeAutoProxyURL
	}
	if st.AutoDetect {
		flags |= proxyTypeAutoDetect
	}
	if st.RawFlags != 0 {
		flags |= (st.RawFlags & ^uint32(proxyTypeProxy|proxyTypeAutoProxyURL|proxyTypeAutoDetect))
		if st.AutoDetect {
			flags |= proxyTypeAutoDetect
		}
		if st.ProxyEnable && strings.TrimSpace(st.ProxyServer) != "" {
			flags |= proxyTypeProxy
		}
		if strings.TrimSpace(st.AutoConfigURL) != "" {
			flags |= proxyTypeAutoProxyURL
		}
	}

	updateDefaultConnectionSettings(flags)
	_ = applyWinINetPerConn(flags, st.ProxyServer, st.ProxyBypass, st.AutoConfigURL)
	notifyWinINetRefresh()
	return nil
}

// Query 读取当前 Windows 注册表中的系统代理状态（包含全局代理、自动代理与 PAC 设置）。
func (d *windowsSysProxyDriver) Query() (SysProxyState, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsRegPath, registry.QUERY_VALUE)
	if err != nil {
		return SysProxyState{Mode: SysProxyOff}, err
	}
	defer k.Close()

	autoURL, _, _ := k.GetStringValue("AutoConfigURL")
	proxyEnable, _, _ := k.GetIntegerValue("ProxyEnable")
	proxyServer, _, _ := k.GetStringValue("ProxyServer")
	proxyOverride, _, _ := k.GetStringValue("ProxyOverride")
	autoDetectReg, _, _ := k.GetIntegerValue("AutoDetect")

	var rawFlags uint32
	var hasRawFlags bool
	if connKey, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsRegPath+`\Connections`, registry.QUERY_VALUE); err == nil {
		if buf, _, err := connKey.GetBinaryValue("DefaultConnectionSettings"); err == nil && len(buf) > 8 {
			rawFlags = uint32(buf[8])
			hasRawFlags = true
		}
		connKey.Close()
	}

	autoDetect := autoDetectReg != 0
	proxyEnabled := proxyEnable != 0
	hasPAC := strings.TrimSpace(autoURL) != ""

	if hasRawFlags {
		if rawFlags&proxyTypeAutoDetect != 0 {
			autoDetect = true
		}
		if rawFlags&proxyTypeProxy != 0 {
			proxyEnabled = true
		}
		if rawFlags&proxyTypeAutoProxyURL != 0 {
			hasPAC = true
		}
	} else {
		rawFlags = proxyTypeDirect
		if proxyEnabled {
			rawFlags |= proxyTypeProxy
		}
		if hasPAC {
			rawFlags |= proxyTypeAutoProxyURL
		}
		if autoDetect {
			rawFlags |= proxyTypeAutoDetect
		}
	}

	st := SysProxyState{
		Mode:          SysProxyOff,
		ProxyEnable:   proxyEnabled,
		ProxyServer:   proxyServer,
		ProxyBypass:   proxyOverride,
		AutoDetect:    autoDetect,
		AutoConfigURL: autoURL,
		RawFlags:      rawFlags,
	}

	if hasPAC && strings.TrimSpace(autoURL) != "" {
		st.Mode = SysProxyPAC
	} else if proxyEnabled && strings.TrimSpace(proxyServer) != "" {
		st.Mode = SysProxyGlobal
	}
	return st, nil
}

func updateDefaultConnectionSettings(flags uint32) {
	if connKey, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsRegPath+`\Connections`, registry.SET_VALUE|registry.QUERY_VALUE); err == nil {
		for _, valName := range []string{"DefaultConnectionSettings", "SavedLegacySettings"} {
			if buf, _, err := connKey.GetBinaryValue(valName); err == nil && len(buf) > 8 {
				buf[8] = byte(flags)
				_ = connKey.SetBinaryValue(valName, buf)
			}
		}
		connKey.Close()
	}
}

func writeInternetSettingsReg(enableProxy bool, proxyServer, proxyBypass, autoConfigURL string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsRegPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry %s: %w", internetSettingsRegPath, err)
	}
	defer k.Close()

	var enableVal uint32
	if enableProxy {
		enableVal = 1
	}
	if err := k.SetDWordValue("ProxyEnable", enableVal); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}
	if proxyServer != "" {
		if err := k.SetStringValue("ProxyServer", proxyServer); err != nil {
			return fmt.Errorf("set ProxyServer: %w", err)
		}
	}
	if proxyBypass != "" {
		if err := k.SetStringValue("ProxyOverride", proxyBypass); err != nil {
			return fmt.Errorf("set ProxyOverride: %w", err)
		}
	}
	if autoConfigURL != "" {
		if err := k.SetStringValue("AutoConfigURL", autoConfigURL); err != nil {
			return fmt.Errorf("set AutoConfigURL: %w", err)
		}
	} else {
		_ = k.DeleteValue("AutoConfigURL")
	}
	return nil
}

func applyWinINetPerConn(flags uint32, proxyServer, proxyBypass, autoConfigURL string) error {
	srvPtr, _ := syscall.UTF16PtrFromString(proxyServer)
	bypPtr, _ := syscall.UTF16PtrFromString(proxyBypass)
	pacPtr, _ := syscall.UTF16PtrFromString(autoConfigURL)

	opts := [4]internetPerConnOption{
		{dwOption: internetPerConnFlags, dwValue: [8 / ptrSize]uintptr{0: uintptr(flags)}},
		{dwOption: internetPerConnProxyServer, dwValue: [8 / ptrSize]uintptr{0: uintptr(unsafe.Pointer(srvPtr))}},
		{dwOption: internetPerConnProxyBypass, dwValue: [8 / ptrSize]uintptr{0: uintptr(unsafe.Pointer(bypPtr))}},
		{dwOption: internetPerConnAutoConfigURL, dwValue: [8 / ptrSize]uintptr{0: uintptr(unsafe.Pointer(pacPtr))}},
	}

	list := internetPerConnOptionList{
		dwSize:        uint32(unsafe.Sizeof(internetPerConnOptionList{})),
		pszConnection: nil, // 默认局域网连接
		dwOptionCount: uint32(len(opts)),
		pOptions:      uintptr(unsafe.Pointer(&opts[0])),
	}

	r1, _, err := safeCallProc(
		procInternetSetOption,
		0,
		internetOptionPerConnectionOption,
		uintptr(unsafe.Pointer(&list)),
		uintptr(list.dwSize),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func notifyWinINetRefresh() {
	_, _, _ = safeCallProc(procInternetSetOption, 0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = safeCallProc(procInternetSetOption, 0, internetOptionRefresh, 0, 0)
}

// installCAOnPlatform 在 Windows 7~11 (32/64) 下调用 certutil 将本地 CA 导入受信任的根证书颁发机构。
func installCAOnPlatform(caPath string) error {
	cmd := exec.Command("certutil", "-user", "-addstore", "Root", caPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	cmdSys := exec.Command("certutil", "-addstore", "Root", caPath)
	if _, errSys := cmdSys.CombinedOutput(); errSys == nil {
		return nil
	}
	return fmt.Errorf("certutil install failed: %w (%s)", err, strings.TrimSpace(string(out)))
}

// uninstallCAOnPlatform 在 Windows 7~11 (32/64) 下从当前用户及系统受信任的根证书颁发机构（Root）中卸载 ech-proxy 本地 CA 证书。
func uninstallCAOnPlatform(caPath string) error {
	var thumbprint string
	if strings.TrimSpace(caPath) != "" {
		if raw, err := os.ReadFile(caPath); err == nil {
			if block, _ := pem.Decode(raw); block != nil {
				if cert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
					sum := sha1.Sum(cert.Raw)
					thumbprint = hex.EncodeToString(sum[:])
				}
			}
		}
	}

	var succeeded bool
	var lastErr error
	var lastOut string

	targets := []string{"ech-proxy local CA"}
	if thumbprint != "" {
		targets = append([]string{thumbprint}, targets...)
	}

	for _, id := range targets {
		if out, err := exec.Command("certutil", "-user", "-delstore", "Root", id).CombinedOutput(); err == nil {
			succeeded = true
		} else {
			lastErr = err
			lastOut = strings.TrimSpace(string(out))
		}
		if _, err := exec.Command("certutil", "-delstore", "Root", id).CombinedOutput(); err == nil {
			succeeded = true
		}
	}

	if succeeded {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("certutil uninstall failed: %w (%s)", lastErr, lastOut)
	}
	return nil
}

// scheduleWindowsDelayedMove 在进程即将退出时启动后台延迟替换命令，确保运行中的 .exe 退出后立即被 .new 覆盖。
func scheduleWindowsDelayedMove(stagedPath, targetExePath, backupPath string) {
	script := fmt.Sprintf(`ping 127.0.0.1 -n 2 > nul & move /Y "%s" "%s" > nul 2>&1 & del /F /Q "%s" > nul 2>&1`,
		stagedPath, targetExePath, backupPath)
	cmd := exec.Command("cmd.exe", "/C", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}