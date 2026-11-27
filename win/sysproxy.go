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
	// appliedPACURL 是最近一次真正写入系统的 PAC 地址（仅在成功 ApplyPAC 后记录）。
	// 用于「全代理热切换」：PAC 模式下的开关切换不压栈、也不改变系统代理拓扑，
	// 只需把新的 PAC URL 原子覆盖上去，避免用户每勾选一次就在恢复栈里堆一层。
	appliedPACURL    string
	explicitFallback string
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

// RefreshPAC 用「当前」的 AllMode 重新生成 PAC 地址并原子覆盖到系统代理上。
//
// 这是托盘「全代理（-all）」热开关的落地动作：
//   - 不修改系统代理模式（仍是 PAC），因此**不压栈**（不新增 prevStates），
//     否则用户在菜单里反复勾选几次，退出时的恢复栈就会被塞满一叠同样的 PAC 记录；
//   - 带上新的 t 时间戳，确保 WinHTTP / WinINET 不会命中旧 PAC 缓存而「看起来没生效；
//   - 若当前根本没在 PAC 模式（直连 / 全局代理），则直接返回 applied=false，
//     由调用方决定是否顺带打开 PAC，绝不隐式改动用户的系统代理设置。
func (m *SysProxyManager) RefreshPAC() (pacURL string, applied bool, err error) {
	if m == nil {
		return "", false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mode != SysProxyPAC {
		return BuildPACURL(m.listenAddr, m.allMode.Load(), 0, m.getFallbackLocked()), false, nil
	}
	pacURL = BuildPACURL(m.listenAddr, m.allMode.Load(), m.nowUnix(), m.getFallbackLocked())
	if err := m.driver.ApplyPAC(pacURL); err != nil {
		return pacURL, false, fmt.Errorf("refresh system PAC (%s): %w", pacURL, err)
	}
	m.appliedPACURL = pacURL
	m.modified = true
	log.Printf("[SysProxy] system PAC hot-refreshed: %s (allMode=%v)", pacURL, m.allMode.Load())
	return pacURL, true, nil
}

// ShouldRefreshPAC 判断系统上实际生效的 PAC 是否与期望（含 AllMode）不一致。
//
// 典型场景：启动时 -all 已开启、系统 PAC 却还是上一次运行残留的「白名单版」地址；
// 或用户在外部手动改过 PAC URL。启动阶段据此补一次刷新，保证菜单勾选状态与真实流量路径一致。
func (m *SysProxyManager) ShouldRefreshPAC() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode != SysProxyPAC {
		return false
	}
	wantGlobal := m.allMode.Load()
	applied := m.appliedPACURL
	if st, err := m.driver.Query(); err == nil && st.Mode == SysProxyPAC {
		applied = st.AutoConfigURL
	}
	if applied == "" {
		return true
	}
	return pacIsGlobal(applied) != wantGlobal
}

// pacIsGlobal 判断一条 PAC URL 是否是「全代理」版本（带有 mode=all 参数）。
func pacIsGlobal(pacURL string) bool {
	u, err := url.Parse(strings.TrimSpace(pacURL))
	if err != nil {
		return strings.Contains(pacURL, "mode=all") || strings.Contains(pacURL, "global=1")
	}
	q := u.Query()
	return q.Get("mode") == "all" || q.Get("global") == "1"
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

// pushPrevStateLocked 把切换前的系统代理状态压入恢复栈。
//
// 绝不能把「指向自己的代理」压栈：进程被强杀后会残留
// AutoConfigURL=http://127.0.0.1:<port>/proxy.pac，下次启动时 hasOriginal 仍为 false
// （构造时已被 isSelfProxy 过滤），若栈底又是这条残留，CleanupOnExit 就会把它写回系统代理，
// 用户正常退出后直接断网。这类残留只能丢弃，最终由 Clear() 收尾。
func (m *SysProxyManager) pushPrevStateLocked(prev SysProxyState) {
	if isSelfProxy(prev, m.listenAddr) {
		return
	}
	m.prevStates = append(m.prevStates, prev)
}

func (m *SysProxyManager) SetFallbackProxy(raw string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.explicitFallback = strings.TrimSpace(raw)
	m.mu.Unlock()
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
	if m.explicitFallback != "" {
		return m.explicitFallback
	}
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
	m.pushPrevStateLocked(prev)
	m.mode = SysProxyPAC
	m.modified = true
	m.appliedPACURL = pacURL
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
		m.pushPrevStateLocked(prev)
		m.mode = SysProxyPAC
		m.modified = true
		m.appliedPACURL = pacURL
		log.Printf("[SysProxy] Windows/OS system proxy set to PAC mode: %s", pacURL)
		return nil

	case SysProxyGlobal:
		prev, _ := m.driver.Query()
		m.captureOriginalLocked(prev)

		if err := m.driver.ApplyGlobal(m.listenAddr, DefaultProxyBypass); err != nil {
			return fmt.Errorf("apply global system proxy (%s): %w", m.listenAddr, err)
		}
		m.pushPrevStateLocked(prev)
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
		// 成功恢复/清除后立刻丢弃整个恢复栈：留着陈旧栈帧只会在下次 CleanupOnExit
		// 或 Pop 时把早已失效的状态重新写回系统代理。
		m.prevStates = nil
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
	useClear := false
	switch {
	case m.hasOriginal:
		target = m.originalState
	case len(m.prevStates) > 0 && !isSelfProxy(m.prevStates[0], m.listenAddr):
		target = m.prevStates[0]
	default:
		// 没有可信的原始状态，或栈底就是崩溃残留的自身 PAC（AutoConfigURL 指向
		// 本机 /proxy.pac）。此时把栈底写回系统代理等于让用户退出后直接断网，
		// 只能清空为直连。
		target = SysProxyState{Mode: SysProxyOff}
		useClear = true
	}
	var err error
	if useClear {
		err = m.driver.Clear()
	} else {
		err = m.driver.Restore(target)
	}
	if err != nil {
		log.Printf("[SysProxy] WARNING: failed to restore system proxy on exit: %v", err)
	} else {
		log.Printf("[SysProxy] System proxy restored to original state on exit (mode=%s, proxyEnable=%v, server=%s, pac=%s, autoDetect=%v)",
			target.Mode, target.ProxyEnable, target.ProxyServer, target.AutoConfigURL, target.AutoDetect)
	}
	m.mode = normalizeRestoredMode(target.Mode)
	m.modified = false
	m.prevStates = nil
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
