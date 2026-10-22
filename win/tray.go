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

	return []TrayMenuItem{
		{ID: TrayCmdToggleConsole, Title: "显示 / 隐藏控制台 (双击托盘图标)", Checked: consoleVis},
		{Separator: true},
		{ID: TrayCmdSysProxyPAC, Title: "系统代理：自动配置 PAC 模式 (推荐)", Checked: curMode == SysProxyPAC},
		{ID: TrayCmdSysProxyClear, Title: "系统代理：清除 / 禁用系统代理 (直连)", Checked: curMode == SysProxyOff},
		{Separator: true},
		{ID: TrayCmdIPModeV4, Title: "强制 v4 出口", Checked: curIPMode == "v4"},
		{ID: TrayCmdIPModeV6, Title: "强制 v6 出口", Checked: curIPMode == "v6"},
		{ID: TrayCmdIPModeDual, Title: "双端出口", Checked: curIPMode == "dual"},
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
	case TrayCmdIPModeV4:
		tc.SetIPMode("v4")
	case TrayCmdIPModeV6:
		tc.SetIPMode("v6")
	case TrayCmdIPModeDual:
		tc.SetIPMode("dual")
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
		allMode := false
		if tc.SysProxy != nil {
			allMode = tc.SysProxy.AllMode()
		}
		pacURL := BuildPACURL(tc.ListenAddr, allMode, 0)
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