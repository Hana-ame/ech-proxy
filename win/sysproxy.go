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

type SysProxyManager struct {
	mu         sync.Mutex
	listenAddr string
	allMode    atomic.Bool
	mode       SysProxyMode
	modified   bool
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

func (m *SysProxyManager) SetMode(mode SysProxyMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch mode {
	case SysProxyPAC:
		pacURL := BuildPACURL(m.listenAddr, m.allMode.Load(), m.nowUnix())
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