package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

type SysProxyMode string

const (
	SysProxyPAC    SysProxyMode = "pac"
	SysProxyGlobal SysProxyMode = "global"
	SysProxyOff    SysProxyMode = "off"
)

const DefaultProxyBypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

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

type SysProxyState struct {
	Mode          SysProxyMode
	ProxyServer   string
	ProxyBypass   string
	AutoConfigURL string
}

type SysProxyDriver interface {
	ApplyPAC(pacURL string) error
	ApplyGlobal(proxyHostPort, bypass string) error
	Clear() error
	Query() (SysProxyState, error)
}

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

func NormalizeLoopbackHostPort(listenAddr string) string {
	return echproxy.NormalizeLoopbackHostPort(listenAddr, "127.0.0.1:8443")
}

// SysProxyManager 负责系统代理的原子替换与旧值栈（pop）恢复。
type SysProxyManager struct {
	mu         sync.Mutex
	listenAddr string
	allMode    atomic.Bool
	mode       SysProxyMode
	modified   bool
	prevStates []SysProxyState
	driver     SysProxyDriver
	nowUnix    func() int64
}

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

func (m *SysProxyManager) AllMode() bool {
	if m == nil {
		return false
	}
	return m.allMode.Load()
}

func (m *SysProxyManager) SetAllMode(all bool) {
	if m != nil {
		m.allMode.Store(all)
	}
}

func (m *SysProxyManager) Mode() SysProxyMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

func (m *SysProxyManager) PACURL() string {
	m.mu.Lock()
	addr := m.listenAddr
	m.mu.Unlock()
	return BuildPACURL(addr, m.allMode.Load(), 0)
}

func (m *SysProxyManager) SetListenAddr(addr string) {
	m.mu.Lock()
	m.listenAddr = NormalizeLoopbackHostPort(addr)
	m.mu.Unlock()
}

func (m *SysProxyManager) HistoryDepth() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.prevStates)
}

// ReplacePAC 原子替换系统 PAC 地址，并将替换前的系统代理旧值压入栈中返回。
func (m *SysProxyManager) ReplacePAC(pacURL string) (SysProxyState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	prev, _ := m.driver.Query()
	if err := m.driver.ApplyPAC(pacURL); err != nil {
		return prev, fmt.Errorf("apply system PAC (%s): %w", pacURL, err)
	}
	m.prevStates = append(m.prevStates, prev)
	m.mode = SysProxyPAC
	m.modified = true
	log.Printf("[SysProxy] Windows/OS system proxy atomically set to PAC mode: %s (pushed old mode=%s url=%q)", pacURL, prev.Mode, prev.AutoConfigURL)
	return prev, nil
}

// Pop 弹出（pop）最近一次压栈的系统代理旧值并原子恢复。
func (m *SysProxyManager) Pop() (SysProxyState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.prevStates) == 0 {
		return SysProxyState{Mode: SysProxyOff}, false, nil
	}
	idx := len(m.prevStates) - 1
	old := m.prevStates[idx]
	m.prevStates = m.prevStates[:idx]

	err := m.restoreStateLocked(old)
	m.mode = normalizeRestoredMode(old.Mode)
	m.modified = len(m.prevStates) > 0
	return old, true, err
}

// normalizeRestoredMode 把驱动返回的空 mode（未设置状态）归一为 off ——
// 某些驱动（含测试用 noop 驱动）初始状态 Mode 为空，弹出恢复后应视为“无代理”。
func normalizeRestoredMode(mode SysProxyMode) SysProxyMode {
	if mode == "" {
		return SysProxyOff
	}
	return mode
}

func (m *SysProxyManager) restoreStateLocked(st SysProxyState) error {
	switch st.Mode {
	case SysProxyPAC:
		if strings.TrimSpace(st.AutoConfigURL) != "" {
			return m.driver.ApplyPAC(st.AutoConfigURL)
		}
		return m.driver.Clear()
	case SysProxyGlobal:
		if strings.TrimSpace(st.ProxyServer) != "" {
			bypass := st.ProxyBypass
			if bypass == "" {
				bypass = DefaultProxyBypass
			}
			return m.driver.ApplyGlobal(st.ProxyServer, bypass)
		}
		return m.driver.Clear()
	default:
		return m.driver.Clear()
	}
}

func (m *SysProxyManager) SetMode(mode SysProxyMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch mode {
	case SysProxyPAC:
		prev, _ := m.driver.Query()
		pacURL := BuildPACURL(m.listenAddr, m.allMode.Load(), m.nowUnix())
		if err := m.driver.ApplyPAC(pacURL); err != nil {
			return fmt.Errorf("apply system PAC (%s): %w", pacURL, err)
		}
		m.prevStates = append(m.prevStates, prev)
		m.mode = SysProxyPAC
		m.modified = true
		log.Printf("[SysProxy] Windows/OS system proxy set to PAC mode: %s", pacURL)
		return nil

	case SysProxyGlobal:
		prev, _ := m.driver.Query()
		if err := m.driver.ApplyGlobal(m.listenAddr, DefaultProxyBypass); err != nil {
			return fmt.Errorf("apply global system proxy (%s): %w", m.listenAddr, err)
		}
		m.prevStates = append(m.prevStates, prev)
		m.mode = SysProxyGlobal
		m.modified = true
		log.Printf("[SysProxy] Windows/OS system proxy set to Global HTTP/HTTPS mode: %s", m.listenAddr)
		return nil

	case SysProxyOff:
		if err := m.driver.Clear(); err != nil {
			return fmt.Errorf("clear system proxy: %w", err)
		}
		m.prevStates = nil
		m.mode = SysProxyOff
		m.modified = false
		log.Printf("[SysProxy] Windows/OS system proxy cleared (Direct mode)")
		return nil

	default:
		return fmt.Errorf("unsupported system proxy mode: %q", mode)
	}
}

func (m *SysProxyManager) CleanupOnExit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.modified {
		return
	}
	var target SysProxyState
	if len(m.prevStates) > 0 {
		target = m.prevStates[0]
		m.prevStates = nil
	} else {
		target = SysProxyState{Mode: SysProxyOff}
	}
	if err := m.restoreStateLocked(target); err != nil {
		log.Printf("[SysProxy] WARNING: failed to restore system proxy on exit: %v", err)
	} else {
		log.Printf("[SysProxy] System proxy popped and restored on exit (mode=%s)", target.Mode)
	}
	m.mode = normalizeRestoredMode(target.Mode)
	m.modified = false
}

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