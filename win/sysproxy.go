package main

import (
	"fmt"
	"log"
	"net/url"
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
	ProxyEnable   bool
	ProxyServer   string
	ProxyBypass   string
	AutoDetect    bool
	AutoConfigURL string
	RawFlags      uint32
}

type SysProxyDriver interface {
	ApplyPAC(pacURL string) error
	ApplyGlobal(proxyHostPort, bypass string) error
	Clear() error
	Query() (SysProxyState, error)
	Restore(state SysProxyState) error
}

func BuildPACURL(listenAddr string, global bool, ts int64, fallback string) string {
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
	if strings.TrimSpace(fallback) != "" {
		u.WriteString(fmt.Sprintf("%sfallback=%s", sep, url.QueryEscape(strings.TrimSpace(fallback))))
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

func isSelfProxy(st SysProxyState, listenAddr string) bool {
	hostPort := NormalizeLoopbackHostPort(listenAddr)
	if strings.Contains(st.ProxyServer, hostPort) {
		return true
	}
	if strings.Contains(st.AutoConfigURL, hostPort) || strings.Contains(st.AutoConfigURL, "/proxy.pac") {
		return true
	}
	return false
}

// SysProxyManager 负责系统代理的管理、现场捕获与无损恢复。
type SysProxyManager struct {
	mu            sync.Mutex
	listenAddr    string
	allMode       atomic.Bool
	mode          SysProxyMode
	modified      bool
	hasOriginal   bool
	originalState SysProxyState
	prevStates    []SysProxyState
	driver        SysProxyDriver
	nowUnix       func() int64
}

func NewSysProxyManager(listenAddr string, driver SysProxyDriver) *SysProxyManager {
	if driver == nil {
		driver = newPlatformSysProxyDriver()
	}
	mgr := &SysProxyManager{
		listenAddr: NormalizeLoopbackHostPort(listenAddr),
		mode:       SysProxyOff,
		driver:     driver,
		nowUnix:    func() int64 { return time.Now().Unix() },
	}
	if initSt, err := driver.Query(); err == nil {
		if !isSelfProxy(initSt, mgr.listenAddr) {
			mgr.originalState = initSt
			mgr.hasOriginal = true
		}
	}
	return mgr
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
	defer m.mu.Unlock()
	return BuildPACURL(m.listenAddr, m.allMode.Load(), 0, m.getFallbackLocked())
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

func (m *SysProxyManager) OriginalState() (SysProxyState, bool) {
	if m == nil {
		return SysProxyState{Mode: SysProxyOff}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.originalState, m.hasOriginal
}

func (m *SysProxyManager) captureOriginalLocked(current SysProxyState) {
	if !m.hasOriginal && !isSelfProxy(current, m.listenAddr) {
		m.originalState = current
		m.hasOriginal = true
	}
}

func (m *SysProxyManager) FallbackProxy() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getFallbackLocked()
}

func (m *SysProxyManager) getFallbackLocked() string {
	if m.hasOriginal && m.originalState.ProxyEnable && strings.TrimSpace(m.originalState.ProxyServer) != "" {
		if !isSelfProxy(m.originalState, m.listenAddr) {
			return m.originalState.ProxyServer
		}
	}
	return ""
}

// ReplacePAC 原子替换系统 PAC 地址，并将替换前的系统代理旧值压入栈中返回。
func (m *SysProxyManager) ReplacePAC(pacURL string) (SysProxyState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	prev, _ := m.driver.Query()
	m.captureOriginalLocked(prev)

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
		if m.hasOriginal {
			err := m.driver.Restore(m.originalState)
			m.mode = normalizeRestoredMode(m.originalState.Mode)
			m.modified = false
			return m.originalState, true, err
		}
		return SysProxyState{Mode: SysProxyOff}, false, nil
	}
	idx := len(m.prevStates) - 1
	old := m.prevStates[idx]
	m.prevStates = m.prevStates[:idx]

	err := m.driver.Restore(old)
	m.mode = normalizeRestoredMode(old.Mode)
	m.modified = len(m.prevStates) > 0
	return old, true, err
}

func normalizeRestoredMode(mode SysProxyMode) SysProxyMode {
	if mode == "" {
		return SysProxyOff
	}
	return mode
}

func (m *SysProxyManager) SetMode(mode SysProxyMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch mode {
	case SysProxyPAC:
		prev, _ := m.driver.Query()
		m.captureOriginalLocked(prev)

		fallback := m.getFallbackLocked()
		pacURL := BuildPACURL(m.listenAddr, m.allMode.Load(), m.nowUnix(), fallback)
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
		m.captureOriginalLocked(prev)

		if err := m.driver.ApplyGlobal(m.listenAddr, DefaultProxyBypass); err != nil {
			return fmt.Errorf("apply global system proxy (%s): %w", m.listenAddr, err)
		}
		m.prevStates = append(m.prevStates, prev)
		m.mode = SysProxyGlobal
		m.modified = true
		log.Printf("[SysProxy] Windows/OS system proxy set to Global HTTP/HTTPS mode: %s", m.listenAddr)
		return nil

	case SysProxyOff:
		if m.hasOriginal {
			if err := m.driver.Restore(m.originalState); err != nil {
				return fmt.Errorf("restore original system proxy: %w", err)
			}
			log.Printf("[SysProxy] Windows/OS system proxy restored to original state (mode=%s, proxyEnable=%v, server=%s, bypass=%s, pac=%s, autoDetect=%v)",
				m.originalState.Mode, m.originalState.ProxyEnable, m.originalState.ProxyServer, m.originalState.ProxyBypass, m.originalState.AutoConfigURL, m.originalState.AutoDetect)
		} else {
			if err := m.driver.Clear(); err != nil {
				return fmt.Errorf("clear system proxy: %w", err)
			}
			log.Printf("[SysProxy] Windows/OS system proxy cleared (Direct mode)")
		}
		m.mode = SysProxyOff
		m.modified = false
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
	if m.hasOriginal {
		target = m.originalState
	} else if len(m.prevStates) > 0 {
		target = m.prevStates[0]
	} else {
		target = SysProxyState{Mode: SysProxyOff}
	}
	if err := m.driver.Restore(target); err != nil {
		log.Printf("[SysProxy] WARNING: failed to restore system proxy on exit: %v", err)
	} else {
		log.Printf("[SysProxy] System proxy restored to original state on exit (mode=%s, proxyEnable=%v, server=%s, pac=%s, autoDetect=%v)",
			target.Mode, target.ProxyEnable, target.ProxyServer, target.AutoConfigURL, target.AutoDetect)
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
		if st.AutoDetect {
			return "Mode: Auto-Detect (WPAD)"
		}
		return "Mode: Off (Direct)"
	}
}