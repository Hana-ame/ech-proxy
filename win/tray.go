package main

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

const DefaultFeedbackURL = "https://chatto.4545810.xyz"

const (
	TrayCmdToggleConsole uintptr = 1001
	TrayCmdSysProxyPAC   uintptr = 1002
	TrayCmdSysProxyClear uintptr = 1004
	TrayCmdOpenFeedback  uintptr = 1005
	TrayCmdOpenPortal    uintptr = TrayCmdOpenFeedback
	TrayCmdCopyPACURL    uintptr = 1006
	TrayCmdInstallCA     uintptr = 1007
	TrayCmdExit          uintptr = 1008
	TrayCmdOpenLogs      uintptr = 1010
	TrayCmdIPModeV4      uintptr = 1011
	TrayCmdIPModeV6      uintptr = 1012
	TrayCmdIPModeDual    uintptr = 1013
	TrayCmdUninstallCA   uintptr = 1014
	TrayCmdCheckUpdate   uintptr = 1015
	TrayCmdDumpMemory    uintptr = 1016
	TrayCmdAllMode       uintptr = 1017
	TrayCmdECHHTTP3      uintptr = 1018
)

type ConsoleWindowDriver interface {
	IsVisible() bool
	SetVisible(visible bool)
	DisableCloseButton()
}

type TrayMenuItem struct {
	ID        uintptr
	Title     string
	Checked   bool
	Separator bool
}

type UpdateCheckState int

const (
	UpdateStateIdle UpdateCheckState = iota
	UpdateStateChecking
	UpdateStateUpToDate
	UpdateStateDownloaded
	UpdateStateFailed
)

type TrayController struct {
	mu              sync.Mutex
	ListenAddr      string
	FeedbackURL     string
	PortalURL       string
	CAPath          string
	LogDir          string
	IPMode          string
	SysProxy        *SysProxyManager
	AdScript        *echproxy.AdScriptManager
	Updater         *Updater
	Console         ConsoleWindowDriver
	SetIPModeFn     func(string)
	SetECHHTTP3Fn   func(bool)
	OpenURLFn       func(string)
	CopyClipboardFn func(string) error
	InstallCAFn     func(string) error
	UninstallCAFn   func(string) error
	CheckUpdateFn   func() (bool, error)
	DumpMemoryFn    func() string
	NotifyFn        func(title, msg string, isError bool)
	OnExit          func()
	OnStateChanged  func()

	updateState UpdateCheckState
	updateError string
}

func NewTrayController(listenAddr, portalURL, caPath string, sysProxy *SysProxyManager, console ConsoleWindowDriver, onExit func()) *TrayController {
	if console == nil {
		console = newPlatformConsoleDriver()
	}
	return &TrayController{
		ListenAddr:      NormalizeLoopbackHostPort(listenAddr),
		FeedbackURL:     DefaultFeedbackURL,
		PortalURL:       portalURL,
		CAPath:          caPath,
		IPMode:          echproxy.EffectiveIPMode(echproxy.GetGlobalIPMode()),
		SysProxy:        sysProxy,
		Console:         console,
		SetIPModeFn:     echproxy.SetGlobalIPMode,
		SetECHHTTP3Fn:   echproxy.SetECHHTTP3,
		OpenURLFn:       openBrowser,
		CopyClipboardFn: copyToClipboardOnPlatform,
		InstallCAFn:     installCAOnPlatform,
		UninstallCAFn:   uninstallCAOnPlatform,
		OnExit:          onExit,
	}
}

func (tc *TrayController) CurrentIPMode() string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return echproxy.EffectiveIPMode(tc.IPMode)
}

func (tc *TrayController) ECHHTTP3Enabled() bool {
	return echproxy.GetECHHTTP3()
}

func (tc *TrayController) SetECHHTTP3(enabled bool) {
	tc.mu.Lock()
	fn, notify, cb := tc.SetECHHTTP3Fn, tc.NotifyFn, tc.OnStateChanged
	tc.mu.Unlock()
	if fn != nil {
		fn(enabled)
	} else {
		echproxy.SetECHHTTP3(enabled)
	}
	if notify != nil {
		if enabled {
			notify("ech-proxy 已开启 ECH 备选 HTTP/3", "仅在 ECH 通道 HTTP/2 失败时作为备选回退（SNI 通道绝不使用）。", false)
		} else {
			notify("ech-proxy 已关闭 ECH 备选 HTTP/3", "ECH 通道已恢复纯 HTTP/2 多路连接。", false)
		}
	}
	if cb != nil {
		cb()
	}
}

func (tc *TrayController) SetIPMode(mode string) {
	norm := echproxy.EffectiveIPMode(mode)
	tc.mu.Lock()
	tc.IPMode = norm
	fn, cb := tc.SetIPModeFn, tc.OnStateChanged
	tc.mu.Unlock()
	if fn != nil {
		fn(norm)
	} else {
		echproxy.SetGlobalIPMode(norm)
	}
	if cb != nil {
		cb()
	}
}

// AllMode 返回当前「全代理」状态：系统代理管理器的 AllMode（决定 PAC 内容的 mode=all）
// 与广告/白名单管理器的 AllMode（决定 PAC 路由与 MITM 判定）任一为真即视为开启。
func (tc *TrayController) AllMode() bool {
	if tc.SysProxy != nil && tc.SysProxy.AllMode() {
		return true
	}
	tc.mu.Lock()
	ad := tc.AdScript
	tc.mu.Unlock()
	return ad != nil && ad.AllMode()
}

// SetAllMode 热开启 / 热关闭「全代理（-all）」模式，无需重启进程。
//
// 三处状态必须同时翻转，缺一都会出现「菜单勾了但流量没变」：
//  1. AdScriptManager.AllMode —— 决定 /proxy.pac 生成的是全量 PROXY 还是白名单分流；
//  2. SysProxyManager.AllMode —— 决定系统 PAC URL 上是否带 ?mode=all（URL 级兜底）；
//  3. 系统 PAC 热刷新 —— 换带新时间戳的 URL 覆盖上去，逼 WinHTTP/WinINET 立即重新拉取。
//
// 若当前处于 PAC 模式则只覆盖 PAC URL（不压栈）；若当前是直连，则顺带打开 PAC 让开关立刻见效；
// 全局 HTTP 代理模式下不介入（那是另一条拓扑，由用户自行选择菜单项）。
func (tc *TrayController) SetAllMode(all bool) error {
	tc.mu.Lock()
	ad, sp, notify, cb := tc.AdScript, tc.SysProxy, tc.NotifyFn, tc.OnStateChanged
	tc.mu.Unlock()

	ad.SetAllMode(all)
	if sp != nil {
		sp.SetAllMode(all)
	}

	var err error
	switch {
	case sp != nil && sp.Mode() == SysProxyPAC:
		_, _, err = sp.RefreshPAC()
	case sp != nil && sp.Mode() == SysProxyOff && all:
		// 只有「打开全代理」才顺带把系统代理切到 PAC。关闭全代理时若当前是直连，
		// 说明用户本来就是直连（或主动关掉了系统代理），此时再 SetMode(PAC)
		// 等于替用户把代理重新打开 —— 表现为「点了取消全代理，结果整个系统开始走代理」。
		err = sp.SetMode(SysProxyPAC)
	}

	if err != nil {
		log.Printf("[Tray] switch ALL mode (%v) failed: %v", all, err)
		if notify != nil {
			notify("ech-proxy 全代理切换失败", err.Error(), true)
		}
	} else {
		if all {
			log.Printf("[PAC] Routing scope switched to ALL mode at runtime (all domains via proxy)")
		} else {
			log.Printf("[PAC] Routing scope switched back to PAC whitelist at runtime")
		}
		if notify != nil {
			if all {
				notify("ech-proxy 已开启全代理", "所有网站流量现已全部经 ech-proxy 转发（无视 pac.txt 白名单）。", false)
			} else {
				notify("ech-proxy 已切回白名单", "仅白名单站点走代理，其余网站恢复直连。", false)
			}
		}
	}
	if cb != nil {
		cb()
	}
	return err
}

func (tc *TrayController) IsConsoleVisible() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.Console == nil {
		return true
	}
	return tc.Console.IsVisible()
}

func (tc *TrayController) SetConsoleVisible(visible bool) {
	tc.mu.Lock()
	c, cb := tc.Console, tc.OnStateChanged
	tc.mu.Unlock()
	if c != nil {
		c.SetVisible(visible)
	}
	if cb != nil {
		cb()
	}
}

func (tc *TrayController) ToggleConsole() bool {
	tc.mu.Lock()
	c, cb := tc.Console, tc.OnStateChanged
	tc.mu.Unlock()
	if c == nil {
		return true
	}
	next := !c.IsVisible()
	c.SetVisible(next)
	if cb != nil {
		cb()
	}
	return next
}

func (tc *TrayController) TooltipText() string {
	modeStr := "直连(未改系统代理)"
	if tc.SysProxy != nil {
		switch tc.SysProxy.Mode() {
		case SysProxyPAC:
			modeStr = "系统PAC自动分流"
			if tc.AllMode() {
				modeStr = "系统PAC全代理(ALL)"
			}
		case SysProxyGlobal:
			modeStr = "全局系统代理"
		}
	}
	ipStr := "v4出口"
	switch tc.CurrentIPMode() {
	case "v6":
		ipStr = "v6出口"
	case "dual":
		ipStr = "双端出口"
	}
	return fmt.Sprintf("ech-proxy [%s] - %s (%s)", tc.ListenAddr, modeStr, ipStr)
}

func (tc *TrayController) MenuItems() []TrayMenuItem {
	consoleVis := tc.IsConsoleVisible()
	curMode := SysProxyOff
	if tc.SysProxy != nil {
		curMode = tc.SysProxy.Mode()
	}
	curIPMode := tc.CurrentIPMode()
	allMode := tc.AllMode()
	feedbackURL := strings.TrimSpace(tc.FeedbackURL)
	if feedbackURL == "" {
		feedbackURL = DefaultFeedbackURL
	}
	updateTitle := "检查更新 (Check Update)"
	updateChecked := false
	tc.mu.Lock()
	st := tc.updateState
	errStr := tc.updateError
	tc.mu.Unlock()

	if tc.Updater != nil && tc.Updater.IsUpdateStaged() {
		st = UpdateStateDownloaded
	}

	switch st {
	case UpdateStateChecking:
		updateTitle = "检查更新 (正在连接/下载中，请稍候...)"
	case UpdateStateDownloaded:
		updateTitle = "检查更新 (新版本已下载，退出重开自动替换)"
		updateChecked = true
	case UpdateStateUpToDate:
		updateTitle = "检查更新 (当前已是最新版)"
	case UpdateStateFailed:
		if len(errStr) > 24 {
			errStr = errStr[:24] + "..."
		}
		if errStr != "" {
			updateTitle = fmt.Sprintf("检查更新 (失败: %s，点击重试)", errStr)
		} else {
			updateTitle = "检查更新 (检查失败，点击重试)"
		}
	}

	clearTitle := "系统代理：清除 / 禁用系统代理 (直连)"
	if tc.SysProxy != nil {
		if orig, ok := tc.SysProxy.OriginalState(); ok && (orig.Mode != SysProxyOff || orig.AutoDetect) {
			clearTitle = "系统代理：直连模式 (还原原有代理/自动检测)"
		}
	}

	return []TrayMenuItem{
		{ID: TrayCmdToggleConsole, Title: "显示 / 隐藏控制台 (双击托盘图标)", Checked: consoleVis},
		{Separator: true},
		{ID: TrayCmdSysProxyPAC, Title: "系统代理：自动配置 PAC 模式 (推荐)", Checked: curMode == SysProxyPAC},
		{ID: TrayCmdSysProxyClear, Title: clearTitle, Checked: curMode == SysProxyOff},
		{ID: TrayCmdAllMode, Title: "全代理模式：所有网站均走代理 (ALL, 即时生效)", Checked: allMode},
		{Separator: true},
		{ID: TrayCmdIPModeV4, Title: "强制 v4 出口", Checked: curIPMode == "v4"},
		{ID: TrayCmdIPModeV6, Title: "强制 v6 出口", Checked: curIPMode == "v6"},
		{ID: TrayCmdIPModeDual, Title: "双端出口", Checked: curIPMode == "dual"},
		{ID: TrayCmdECHHTTP3, Title: "ECH 备选 HTTP/3 (仅 ECH 通道, 实验)", Checked: tc.ECHHTTP3Enabled()},
		{Separator: true},
		{ID: TrayCmdInstallCA, Title: "一键安装本地 CA 根证书 (Install CA)"},
		{ID: TrayCmdUninstallCA, Title: "卸载本地 CA 根证书 (Uninstall CA)"},
		{Separator: true},
		{ID: TrayCmdCheckUpdate, Title: updateTitle, Checked: updateChecked},
		{ID: TrayCmdOpenFeedback, Title: "反馈 (" + feedbackURL + ")"},
		{ID: TrayCmdCopyPACURL, Title: "复制 PAC 地址 (Copy PAC URL)"},
		{ID: TrayCmdDumpMemory, Title: "转储内存诊断 (Dump Memory)"},
		{ID: TrayCmdOpenLogs, Title: "打开本地日志目录 (问题排查/上传日志)"},
		{Separator: true},
		{ID: TrayCmdExit, Title: "退出程序并清理系统代理 (Exit)"},
	}
}

func (tc *TrayController) HandleCommand(cmdID uintptr) bool {
	switch cmdID {
	case TrayCmdToggleConsole:
		tc.ToggleConsole()
	case TrayCmdSysProxyPAC:
		if tc.SysProxy != nil {
			_ = tc.SysProxy.SetMode(SysProxyPAC)
		}
		if tc.OnStateChanged != nil {
			tc.OnStateChanged()
		}
	case TrayCmdSysProxyClear:
		if tc.SysProxy != nil {
			_ = tc.SysProxy.SetMode(SysProxyOff)
		}
		if tc.OnStateChanged != nil {
			tc.OnStateChanged()
		}
	case TrayCmdAllMode:
		_ = tc.SetAllMode(!tc.AllMode())
	case TrayCmdIPModeV4:
		tc.SetIPMode("v4")
	case TrayCmdIPModeV6:
		tc.SetIPMode("v6")
	case TrayCmdIPModeDual:
		tc.SetIPMode("dual")
	case TrayCmdECHHTTP3:
		tc.SetECHHTTP3(!tc.ECHHTTP3Enabled())
	case TrayCmdInstallCA:
		if tc.InstallCAFn != nil && tc.CAPath != "" {
			echproxy.SafeGo("TrayInstallCA", func() { _ = tc.InstallCAFn(tc.CAPath) })
		}
	case TrayCmdUninstallCA:
		if tc.UninstallCAFn != nil {
			echproxy.SafeGo("TrayUninstallCA", func() { _ = tc.UninstallCAFn(tc.CAPath) })
		}
	case TrayCmdCheckUpdate:
		tc.mu.Lock()
		if tc.updateState == UpdateStateChecking {
			tc.mu.Unlock()
			return false
		}
		tc.updateState = UpdateStateChecking
		tc.updateError = ""
		tc.mu.Unlock()
		if tc.OnStateChanged != nil {
			tc.OnStateChanged()
		}
		echproxy.SafeGo("TrayCheckUpdate", func() {
			var staged bool
			var err error
			if tc.CheckUpdateFn != nil {
				staged, err = tc.CheckUpdateFn()
			} else if tc.Updater != nil {
				staged, err = tc.Updater.CheckAndDownloadOnce()
			}
			tc.mu.Lock()
			if err != nil {
				tc.updateState = UpdateStateFailed
				tc.updateError = err.Error()
			} else if staged {
				tc.updateState = UpdateStateDownloaded
				tc.updateError = ""
			} else {
				tc.updateState = UpdateStateUpToDate
				tc.updateError = ""
			}
			tc.mu.Unlock()

			if tc.OnStateChanged != nil {
				tc.OnStateChanged()
			}

			if tc.NotifyFn != nil {
				if err != nil {
					tc.NotifyFn("ech-proxy 检查更新失败", fmt.Sprintf("无法连接更新源: %v", err), true)
				} else if staged {
					tc.NotifyFn("ech-proxy 新版本已下载", "新版本已就绪，退出重开程序即可自动替换生效！", false)
				} else {
					tc.NotifyFn("ech-proxy 当前已是最新版", "您正在运行最新发布版本，无需更新。", false)
				}
			}
		})
	case TrayCmdOpenFeedback:
		feedbackURL := strings.TrimSpace(tc.FeedbackURL)
		if feedbackURL == "" {
			feedbackURL = DefaultFeedbackURL
		}
		if tc.OpenURLFn != nil {
			echproxy.SafeGo("TrayOpenFeedback", func() { tc.OpenURLFn(feedbackURL) })
		}
	case TrayCmdCopyPACURL:
		pacURL := ""
		if tc.SysProxy != nil {
			pacURL = tc.SysProxy.PACURL()
		} else {
			pacURL = BuildPACURL(tc.ListenAddr, false, 0, "")
		}
		if tc.CopyClipboardFn != nil {
			if err := tc.CopyClipboardFn(pacURL); err != nil {
				log.Printf("[Tray] Copy PAC URL failed (%v), PAC URL is: %s", err, pacURL)
			}
		}
	case TrayCmdDumpMemory:
		if tc.DumpMemoryFn != nil {
			echproxy.SafeGo("TrayDumpMemory", func() {
				msg := tc.DumpMemoryFn()
				if tc.NotifyFn != nil && msg != "" {
					tc.NotifyFn("内存诊断", msg, false)
				}
			})
		}
	case TrayCmdOpenLogs:
		target := tc.LogDir
		if target == "" {
			target = "http://" + tc.ListenAddr + "/debug/log"
		}
		if tc.OpenURLFn != nil {
			echproxy.SafeGo("TrayOpenLogs", func() { tc.OpenURLFn(target) })
		}
	case TrayCmdExit:
		if tc.SysProxy != nil {
			tc.SysProxy.CleanupOnExit()
		}
		if tc.Updater != nil {
			_, _ = tc.Updater.ApplyStagedUpdateOnExit()
		}
		if tc.OnExit != nil {
			tc.OnExit()
		}
		return true
	}
	return false
}
