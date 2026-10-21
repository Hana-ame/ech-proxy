package main

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

// DefaultFeedbackURL 是托盘「反馈」菜单项打开的目标地址。
const DefaultFeedbackURL = "https://chatto.moonchan.xyz"

// 托盘右键菜单命令 ID 常量。
// 注意：
//   - 全局模式（-all）不在托盘中显示，仅能通过命令行 -all 开启；
//   - 广告相关设置（--skip-ad-script / --skip-ad-block）在托盘中隐藏，仅通过命令行控制；
//   - 托盘提供「强制 v4 出口」、「强制 v6 出口」、「双端出口」三项出口协议族实时切换；
//   - 提供「一键安装本地 CA 根证书」与「一键卸载本地 CA 根证书」选项；
//   - 提供「检查更新 / 自动下载更新」选项（后台自动检查 https://github.com/Hana-ame/ech-proxy/releases，退出后再次打开自动替换）；
//   - 原「打开门户」改为「反馈」，打开 https://chatto.moonchan.xyz。
const (
	TrayCmdToggleConsole uintptr = 1001
	TrayCmdSysProxyPAC   uintptr = 1002
	TrayCmdSysProxyClear uintptr = 1004
	TrayCmdOpenFeedback  uintptr = 1005
	TrayCmdOpenPortal    uintptr = TrayCmdOpenFeedback // 兼容别名
	TrayCmdCopyPACURL    uintptr = 1006
	TrayCmdInstallCA     uintptr = 1007
	TrayCmdExit          uintptr = 1008
	TrayCmdOpenLogs      uintptr = 1010
	TrayCmdIPModeV4      uintptr = 1011
	TrayCmdIPModeV6      uintptr = 1012
	TrayCmdIPModeDual    uintptr = 1013
	TrayCmdUninstallCA   uintptr = 1014
	TrayCmdCheckUpdate   uintptr = 1015
)

// ConsoleWindowDriver 抽象控制台窗口显隐控制接口（Windows 下由 GetConsoleWindow + ShowWindow 实现）。
type ConsoleWindowDriver interface {
	IsVisible() bool
	SetVisible(visible bool)
	DisableCloseButton()
}

// TrayMenuItem 表示托盘右键菜单中的单条菜单项状态（供 Win32 渲染与单元测试断言使用）。
type TrayMenuItem struct {
	ID        uintptr
	Title     string
	Checked   bool
	Separator bool
}

// TrayController 统一管理托盘菜单状态、控制台窗口显隐、出口协议族（v4/v6/dual）切换、CA 安装/卸载、自动检查更新、反馈页面打开与系统代理模式切换。
type TrayController struct {
	mu              sync.Mutex
	ListenAddr      string
	FeedbackURL     string
	PortalURL       string
	CAPath          string
	LogDir          string
	IPMode          string // "v4" (强制 v4 出口), "v6" (强制 v6 出口), "dual" (双端出口)
	SysProxy        *SysProxyManager
	AdScript        *echproxy.AdScriptManager // 内部持有引用（不在托盘菜单中暴露任何广告设置）
	Updater         *Updater                  // 自动更新管理器（检查 GitHub Releases 并自动下载暂存）
	Console         ConsoleWindowDriver
	SetIPModeFn     func(string)
	OpenURLFn       func(string)
	CopyClipboardFn func(string) error
	InstallCAFn     func(string) error
	UninstallCAFn   func(string) error
	CheckUpdateFn   func() (bool, error)
	OnExit          func()
	OnStateChanged  func()
}

// NewTrayController 创建托盘控制器（默认反馈地址为 https://chatto.moonchan.xyz）。
func NewTrayController(listenAddr, portalURL, caPath string, sysProxy *SysProxyManager, console ConsoleWindowDriver, onExit func()) *TrayController {
	if console == nil {
		console = newPlatformConsoleDriver()
	}
	curIPMode := echproxy.EffectiveIPMode(echproxy.GetGlobalIPMode())
	return &TrayController{
		ListenAddr:      NormalizeLoopbackHostPort(listenAddr),
		FeedbackURL:     DefaultFeedbackURL,
		PortalURL:       portalURL,
		CAPath:          caPath,
		IPMode:          curIPMode,
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

// CurrentIPMode 返回当前选中的出口协议族（"v4", "v6", "dual"）。
func (tc *TrayController) CurrentIPMode() string {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return echproxy.EffectiveIPMode(tc.IPMode)
}

// SetIPMode 切换出口协议族（"v4" / "v6" / "dual"）并通知底层传输层立即生效。
func (tc *TrayController) SetIPMode(mode string) {
	norm := echproxy.EffectiveIPMode(mode)
	tc.mu.Lock()
	tc.IPMode = norm
	fn := tc.SetIPModeFn
	cb := tc.OnStateChanged
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

// IsConsoleVisible 返回当前控制台窗口是否可见。
func (tc *TrayController) IsConsoleVisible() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.Console == nil {
		return true
	}
	return tc.Console.IsVisible()
}

// SetConsoleVisible 显式设置控制台窗口可见性。
func (tc *TrayController) SetConsoleVisible(visible bool) {
	tc.mu.Lock()
	c := tc.Console
	cb := tc.OnStateChanged
	tc.mu.Unlock()
	if c != nil {
		c.SetVisible(visible)
	}
	if cb != nil {
		cb()
	}
}

// ToggleConsole 切换控制台窗口的显示/隐藏状态，并返回切换后的可见性。
func (tc *TrayController) ToggleConsole() bool {
	tc.mu.Lock()
	c := tc.Console
	cb := tc.OnStateChanged
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

// TooltipText 生成托盘悬停提示文字（显示当前监听地址、PAC代理状态与出口 IP 模式）。
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

// MenuItems 生成当前托盘右键菜单结构及勾选状态：
//   - 不显示全局模式（全局模式仅能通过命令行 -all 开启）；
//   - 隐藏所有广告相关设置；
//   - 显示「强制 v4 出口」、「强制 v6 出口」、「双端出口」选项；
//   - 显示「一键安装本地 CA 根证书」与「卸载本地 CA 根证书」选项；
//   - 显示「检查更新」选项（当已自动下载新版本时显示已就绪提示）；
//   - 「打开门户」改为「反馈」(https://chatto.moonchan.xyz)。
func (tc *TrayController) MenuItems() []TrayMenuItem {
	consoleVis := tc.IsConsoleVisible()
	var curMode SysProxyMode = SysProxyOff
	if tc.SysProxy != nil {
		curMode = tc.SysProxy.Mode()
	}
	curIPMode := tc.CurrentIPMode()
	feedbackURL := strings.TrimSpace(tc.FeedbackURL)
	if feedbackURL == "" {
		feedbackURL = DefaultFeedbackURL
	}
	updateTitle := "检查更新 (Check Update)"
	updateStaged := tc.Updater != nil && tc.Updater.IsUpdateStaged()
	if updateStaged {
		updateTitle = "检查更新 (新版本已下载，退出重开自动替换)"
	}

	consoleLabel := "显示 / 隐藏控制台 (双击托盘图标)"
	return []TrayMenuItem{
		{ID: TrayCmdToggleConsole, Title: consoleLabel, Checked: consoleVis},
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
		{ID: TrayCmdCheckUpdate, Title: updateTitle, Checked: updateStaged},
		{ID: TrayCmdOpenFeedback, Title: "反馈 (" + feedbackURL + ")"},
		{ID: TrayCmdCopyPACURL, Title: "复制 PAC 地址 (Copy PAC URL)"},
		{ID: TrayCmdOpenLogs, Title: "打开本地日志目录 (问题排查/上传日志)"},
		{Separator: true},
		{ID: TrayCmdExit, Title: "退出程序并清理系统代理 (Exit)"},
	}
}

// HandleCommand 执行托盘菜单点击动作；若点击了“退出”则返回 true。
func (tc *TrayController) HandleCommand(cmdID uintptr) bool {
	switch cmdID {
	case TrayCmdToggleConsole:
		vis := tc.ToggleConsole()
		log.Printf("[Tray] Console window visibility toggled: visible=%v", vis)

	case TrayCmdSysProxyPAC:
		if tc.SysProxy != nil {
			if err := tc.SysProxy.SetMode(SysProxyPAC); err != nil {
				log.Printf("[Tray] Failed to set PAC mode: %v", err)
			}
		}
		if tc.OnStateChanged != nil {
			tc.OnStateChanged()
		}

	case TrayCmdSysProxyClear:
		if tc.SysProxy != nil {
			if err := tc.SysProxy.SetMode(SysProxyOff); err != nil {
				log.Printf("[Tray] Failed to clear system proxy: %v", err)
			}
		}
		if tc.OnStateChanged != nil {
			tc.OnStateChanged()
		}

	case TrayCmdIPModeV4:
		tc.SetIPMode("v4")
		log.Printf("[Tray] Egress IP mode switched to: 强制 v4 出口 (v4)")

	case TrayCmdIPModeV6:
		tc.SetIPMode("v6")
		log.Printf("[Tray] Egress IP mode switched to: 强制 v6 出口 (v6)")

	case TrayCmdIPModeDual:
		tc.SetIPMode("dual")
		log.Printf("[Tray] Egress IP mode switched to: 双端出口 (dual)")

	case TrayCmdInstallCA:
		if tc.InstallCAFn != nil && tc.CAPath != "" {
			echproxy.SafeGo("TrayInstallCA", func() {
				if err := tc.InstallCAFn(tc.CAPath); err != nil {
					log.Printf("[Tray] Install CA failed: %v", err)
				} else {
					log.Printf("[Tray] Local CA certificate installed into user Root store: %s", tc.CAPath)
				}
			})
		}

	case TrayCmdUninstallCA:
		if tc.UninstallCAFn != nil {
			echproxy.SafeGo("TrayUninstallCA", func() {
				if err := tc.UninstallCAFn(tc.CAPath); err != nil {
					log.Printf("[Tray] Uninstall CA failed: %v", err)
				} else {
					log.Printf("[Tray] Local CA certificate uninstalled from Root store")
				}
			})
		}

	case TrayCmdCheckUpdate:
		echproxy.SafeGo("TrayCheckUpdate", func() {
			if tc.CheckUpdateFn != nil {
				staged, err := tc.CheckUpdateFn()
				if err != nil {
					log.Printf("[Tray] Check update failed: %v", err)
				} else if staged {
					log.Printf("[Tray] Update downloaded and staged; exit and relaunch ech-proxy to replace")
				} else {
					log.Printf("[Tray] Already running the latest version")
				}
			} else if tc.Updater != nil {
				staged, err := tc.Updater.CheckAndDownloadOnce()
				if err != nil {
					log.Printf("[Tray] Check update failed: %v", err)
				} else if staged {
					log.Printf("[Tray] Update downloaded and staged (%s); exit and relaunch ech-proxy to replace", tc.Updater.StagedPath())
				} else {
					log.Printf("[Tray] Already running the latest version")
				}
			}
			if tc.OnStateChanged != nil {
				tc.OnStateChanged()
			}
		})

	case TrayCmdOpenFeedback:
		feedbackURL := strings.TrimSpace(tc.FeedbackURL)
		if feedbackURL == "" {
			feedbackURL = DefaultFeedbackURL
		}
		if tc.OpenURLFn != nil {
			echproxy.SafeGo("TrayOpenFeedback", func() {
				tc.OpenURLFn(feedbackURL)
			})
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
			} else {
				log.Printf("[Tray] PAC URL copied to clipboard: %s", pacURL)
			}
		}

	case TrayCmdOpenLogs:
		target := tc.LogDir
		if target == "" {
			target = "http://" + tc.ListenAddr + "/debug/log"
		}
		if tc.OpenURLFn != nil {
			echproxy.SafeGo("TrayOpenLogs", func() {
				tc.OpenURLFn(target)
			})
		}

	case TrayCmdExit:
		log.Printf("[Tray] Exit requested from system tray")
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