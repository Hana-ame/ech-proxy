package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// SysProxyMode 定义系统代理模式（对齐 V2rayN 的三档系统代理状态）。
type SysProxyMode string

const (
	// SysProxyPAC 自动配置系统代理（PAC 模式）：设置 AutoConfigURL 为本地 /proxy.pac，智能分流目标域名。
	SysProxyPAC SysProxyMode = "pac"
	// SysProxyGlobal 全局系统代理（HTTP/HTTPS 代理模式）：设置 ProxyServer 为 127.0.0.1:<port>，所有流量经代理转发。
	SysProxyGlobal SysProxyMode = "global"
	// SysProxyOff 清除/不改变系统代理（直连模式）。
	SysProxyOff SysProxyMode = "off"
)

// DefaultProxyBypass 是全局代理模式下默认绕过的本机与局域网地址列表（对齐 V2rayN 默认绕过规则）。
const DefaultProxyBypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// NormalizeSysProxyMode 归一化系统代理模式名称。
func NormalizeSysProxyMode(raw string) (SysProxyMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "pac", "auto":
		return SysProxyPAC, nil
	case "global", "http", "all":
		return SysProxyGlobal, nil
	case "off", "clear", "none", "direct", "disable", "disabled":
		return SysProxyOff, nil
	default:
		return "", fmt.Errorf("invalid sys-proxy mode %q (valid: pac, global, off)", raw)
	}
}

// SysProxyState 表示操作系统的当前代理配置状态。
type SysProxyState struct {
	Mode          SysProxyMode
	ProxyServer   string
	ProxyBypass   string
	AutoConfigURL string
}

// SysProxyDriver 抽象底层操作系统的系统代理读写接口（便于在非 Windows 环境进行全量单元测试）。
type SysProxyDriver interface {
	ApplyPAC(pacURL string) error
	ApplyGlobal(proxyHostPort, bypass string) error
	Clear() error
	Query() (SysProxyState, error)
}

// BuildPACURL 构造带防缓存时间戳的本地 PAC URL（参考 V2rayN 做法，强制 WinINet/浏览器立即刷新 PAC 脚本）。
func BuildPACURL(listenAddr string, global bool, ts int64) string {
	hostPort := NormalizeLoopbackHostPort(listenAddr)
	var u strings.Builder
	u.WriteString("http://")
	u.WriteString(hostPort)
	u.WriteString("/proxy.pac")
	sep := "?"
	if global {
		u.WriteString("?mode=all")
		sep = "&"
	}
	if ts > 0 {
		u.WriteString(fmt.Sprintf("%st=%d", sep, ts))
	}
	return u.String()
}

// NormalizeLoopbackHostPort 将监听地址（如 ":8443" 或 "0.0.0.0:8443"）转换为客户端可访问的 "127.0.0.1:<port>"。
func NormalizeLoopbackHostPort(listenAddr string) string {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return "127.0.0.1:8443"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "127.0.0.1:8443"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// SysProxyManager 线程安全地管理运行期系统代理模式切换与进程退出时的自动恢复。
type SysProxyManager struct {
	mu         sync.Mutex
	listenAddr string
	mode       SysProxyMode
	modified   bool
	driver     SysProxyDriver
	nowUnix    func() int64
}

// NewSysProxyManager 创建系统代理管理器。
func NewSysProxyManager(listenAddr string, driver SysProxyDriver) *SysProxyManager {
	if driver == nil {
		driver = newPlatformSysProxyDriver()
	}
	return &SysProxyManager{
		listenAddr: NormalizeLoopbackHostPort(listenAddr),
		mode:       SysProxyOff,
		driver:     driver,
		nowUnix:    func() int64 { return time.Now().Unix() },
	}
}

// Mode 返回当前生效的系统代理模式。
func (m *SysProxyManager) Mode() SysProxyMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// PACURL 返回当前监听地址对应的标准 PAC 地址（不带时间戳，供复制展示使用）。
func (m *SysProxyManager) PACURL() string {
	m.mu.Lock()
	addr := m.listenAddr
	m.mu.Unlock()
	return BuildPACURL(addr, false, 0)
}

// SetListenAddr 更新代理监听地址。
func (m *SysProxyManager) SetListenAddr(addr string) {
	m.mu.Lock()
	m.listenAddr = NormalizeLoopbackHostPort(addr)
	m.mu.Unlock()
}

// SetMode 切换系统代理模式（PAC / Global / Off），立即通知操作系统生效。
func (m *SysProxyManager) SetMode(mode SysProxyMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch mode {
	case SysProxyPAC:
		pacURL := BuildPACURL(m.listenAddr, false, m.nowUnix())
		if err := m.driver.ApplyPAC(pacURL); err != nil {
			return fmt.Errorf("apply system PAC (%s): %w", pacURL, err)
		}
		m.mode = SysProxyPAC
		m.modified = true
		log.Printf("[SysProxy] Windows/OS system proxy set to PAC mode: %s", pacURL)
		return nil

	case SysProxyGlobal:
		if err := m.driver.ApplyGlobal(m.listenAddr, DefaultProxyBypass); err != nil {
			return fmt.Errorf("apply global system proxy (%s): %w", m.listenAddr, err)
		}
		m.mode = SysProxyGlobal
		m.modified = true
		log.Printf("[SysProxy] Windows/OS system proxy set to Global HTTP/HTTPS mode: %s", m.listenAddr)
		return nil

	case SysProxyOff:
		if err := m.driver.Clear(); err != nil {
			return fmt.Errorf("clear system proxy: %w", err)
		}
		m.mode = SysProxyOff
		m.modified = false
		log.Printf("[SysProxy] Windows/OS system proxy cleared (Direct mode)")
		return nil

	default:
		return fmt.Errorf("unsupported system proxy mode: %q", mode)
	}
}

// CleanupOnExit 在程序退出时自动清除由本进程设置的系统代理，防止退出后浏览器断网。
func (m *SysProxyManager) CleanupOnExit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.modified {
		return
	}
	if err := m.driver.Clear(); err != nil {
		log.Printf("[SysProxy] WARNING: failed to clear system proxy on exit: %v", err)
	} else {
		log.Printf("[SysProxy] System proxy automatically cleared on exit")
	}
	m.mode = SysProxyOff
	m.modified = false
}

// StatusText 返回可读的当前系统代理状态描述。
func (m *SysProxyManager) StatusText() string {
	st, err := m.driver.Query()
	if err != nil {
		return fmt.Sprintf("Mode: %s (query error: %v)", m.Mode(), err)
	}
	switch st.Mode {
	case SysProxyPAC:
		return fmt.Sprintf("Mode: PAC (AutoConfigURL=%s)", st.AutoConfigURL)
	case SysProxyGlobal:
		return fmt.Sprintf("Mode: Global Proxy (ProxyServer=%s, Bypass=%s)", st.ProxyServer, st.ProxyBypass)
	default:
		return "Mode: Off (Direct)"
	}
}