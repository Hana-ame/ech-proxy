package main

import (
	"fmt"
	"log"
	"sync"
)

// 托盘右键菜单命令 ID 常量（参考 V2rayN 托盘菜单布局）。
const (
	TrayCmdToggleConsole  uintptr = 1001
	TrayCmdSysProxyPAC    uintptr = 1002
	TrayCmdSysProxyGlobal uintptr = 1003
	TrayCmdSysProxyClear  uintptr = 1004
	TrayCmdOpenPortal     uintptr = 1005
	TrayCmdCopyPACURL     uintptr = 1006
	TrayCmdInstallCA      uintptr = 1007
	TrayCmdExit           uintptr = 1008
	TrayCmdFeedbackChat   uintptr = 1009
)

// feedbackChatURL 是「反馈 / 聊天」托盘菜单项打开的项目聊天/反馈页面地址。
const feedbackChatURL = "https://chatto.moonchan.xyz"

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

// TrayController 统一管理托盘菜单状态、控制台窗口显隐与系统代理模式切换。
type TrayController struct {
	mu              sync.Mutex
	ListenAddr      string
	PortalURL       string
	FeedbackURL     string
	CAPath          string
	SysProxy        *SysProxyManager
	Console         ConsoleWindowDriver
	OpenURLFn       func(string)
	CopyClipboardFn func(string) error
	InstallCAFn     func(string) error
	OnExit          func()
	OnStateChanged  func()
}

// NewTrayController 创建托盘控制器。
func NewTrayController(listenAddr, portalURL, caPath string, sysProxy *SysProxyManager, console ConsoleWindowDriver, onExit func()) *TrayController {
	if console == nil {
		console = newPlatformConsoleDriver()
	}
	return &TrayController{
		ListenAddr:      NormalizeLoopbackHostPort(listenAddr),
		PortalURL:       portalURL,
		FeedbackURL:     feedbackChatURL,
		CAPath:          caPath,
		SysProxy:        sysProxy,
		Console:         console,
		OpenURLFn:       openBrowser,
		CopyClipboardFn: copyToClipboardOnPlatform,
		InstallCAFn:     installCAOnPlatform,
		OnExit:          onExit,
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

// TooltipText 生成托盘悬停提示文字（类似 V2rayN 显示当前监听地址与系统代理状态）。
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
	return fmt.Sprintf("ech-proxy [%s] - %s", tc.ListenAddr, modeStr)
}

// MenuItems 生成当前托盘右键菜单结构及勾选状态。
func (tc *TrayController) MenuItems() []TrayMenuItem {
	consoleVis := tc.IsConsoleVisible()
	var curMode SysProxyMode = SysProxyOff
	if tc.SysProxy != nil {
		curMode = tc.SysProxy.Mode()
	}
	consoleLabel := "显示 / 隐藏控制台 (双击托盘图标)"
	return []TrayMenuItem{
		{ID: TrayCmdToggleConsole, Title: consoleLabel, Checked: consoleVis},
		{Separator: true},
		{ID: TrayCmdSysProxyPAC, Title: "系统代理：自动配置 PAC 模式 (推荐)", Checked: curMode == SysProxyPAC},
		{ID: TrayCmdSysProxyGlobal, Title: "系统代理：全局 HTTP/HTTPS 模式", Checked: curMode == SysProxyGlobal},
		{ID: TrayCmdSysProxyClear, Title: "系统代理：清除 / 禁用系统代理 (直连)", Checked: curMode == SysProxyOff},
		{Separator: true},
		{ID: TrayCmdOpenPortal, Title: "打开 Web 门户导航页 (" + tc.PortalURL + ")"},
		{ID: TrayCmdCopyPACURL, Title: "复制 PAC 地址 (Copy PAC URL)"},
		{ID: TrayCmdInstallCA, Title: "一键安装本地 CA 根证书 (Install CA)"},
		{ID: TrayCmdFeedbackChat, Title: "反馈 / 聊天 (Feedback / Chat)"},
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

	case TrayCmdSysProxyGlobal:
		if tc.SysProxy != nil {
			if err := tc.SysProxy.SetMode(SysProxyGlobal); err != nil {
				log.Printf("[Tray] Failed to set Global proxy mode: %v", err)
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

	case TrayCmdOpenPortal:
		if tc.OpenURLFn != nil && tc.PortalURL != "" {
			go tc.OpenURLFn(tc.PortalURL)
		}

	case TrayCmdFeedbackChat:
		if tc.OpenURLFn != nil && tc.FeedbackURL != "" {
			go tc.OpenURLFn(tc.FeedbackURL)
		}

	case TrayCmdCopyPACURL:
		pacURL := BuildPACURL(tc.ListenAddr, false, 0)
		if tc.CopyClipboardFn != nil {
			if err := tc.CopyClipboardFn(pacURL); err != nil {
				log.Printf("[Tray] Copy PAC URL failed (%v), PAC URL is: %s", err, pacURL)
			} else {
				log.Printf("[Tray] PAC URL copied to clipboard: %s", pacURL)
			}
		}

	case TrayCmdInstallCA:
		if tc.InstallCAFn != nil && tc.CAPath != "" {
			go func() {
				if err := tc.InstallCAFn(tc.CAPath); err != nil {
					log.Printf("[Tray] Install CA failed: %v", err)
				} else {
					log.Printf("[Tray] Local CA certificate installed into user Root store: %s", tc.CAPath)
				}
			}()
		}

	case TrayCmdExit:
		log.Printf("[Tray] Exit requested from system tray")
		if tc.SysProxy != nil {
			tc.SysProxy.CleanupOnExit()
		}
		if tc.OnExit != nil {
			tc.OnExit()
		}
		return true
	}
	return false
}
