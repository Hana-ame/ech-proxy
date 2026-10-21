//go:build windows

package main

import (
	"log"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

const (
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmCommand       = 0x0111
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmNull          = 0x0000
	wmApp           = 0x8000
	wmTrayCallback  = wmApp + 1

	nimAdd    = 0x00000000
	nimModify = 0x00000001
	nimDelete = 0x00000002

	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004

	swHide    = 0
	swShow    = 5
	swRestore = 9

	mfString       = 0x00000000
	mfChecked      = 0x00000008
	mfSeparator    = 0x00000800
	mfByCommand    = 0x00000000
	tpmRightBtn    = 0x0002
	tpmBottomAlign = 0x0020

	scClose        = 0xF060
	idiApplication = 32512

	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWindow = modkernel32.NewProc("GetConsoleWindow")
	procGetModuleHandleW = modkernel32.NewProc("GetModuleHandleW")
	procGlobalAlloc      = modkernel32.NewProc("GlobalAlloc")
	procGlobalLock       = modkernel32.NewProc("GlobalLock")
	procGlobalUnlock     = modkernel32.NewProc("GlobalUnlock")

	moduser32            = syscall.NewLazyDLL("user32.dll")
	procShowWindow       = moduser32.NewProc("ShowWindow")
	procIsWindowVisible  = moduser32.NewProc("IsWindowVisible")
	procSetForegroundWin = moduser32.NewProc("SetForegroundWindow")
	procGetSystemMenu    = moduser32.NewProc("GetSystemMenu")
	procDeleteMenu       = moduser32.NewProc("DeleteMenu")
	procRegisterClassExW = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW  = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW   = moduser32.NewProc("DefWindowProcW")
	procGetMessageW      = moduser32.NewProc("GetMessageW")
	procTranslateMessage = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW = moduser32.NewProc("DispatchMessageW")
	procPostQuitMessage  = moduser32.NewProc("PostQuitMessage")
	procPostMessageW     = moduser32.NewProc("PostMessageW")
	procCreatePopupMenu  = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW      = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu   = moduser32.NewProc("TrackPopupMenu")
	procDestroyMenu      = moduser32.NewProc("DestroyMenu")
	procGetCursorPos     = moduser32.NewProc("GetCursorPos")
	procLoadIconW        = moduser32.NewProc("LoadIconW")
	procCreateIcon       = moduser32.NewProc("CreateIcon")
	procDestroyIcon      = moduser32.NewProc("DestroyIcon")
	procOpenClipboard    = moduser32.NewProc("OpenClipboard")
	procEmptyClipboard   = moduser32.NewProc("EmptyClipboard")
	procSetClipboardData = moduser32.NewProc("SetClipboardData")
	procCloseClipboard   = moduser32.NewProc("CloseClipboard")

	modshell32           = syscall.NewLazyDLL("shell32.dll")
	procShellNotifyIconW = modshell32.NewProc("Shell_NotifyIconW")
)

type win32ConsoleDriver struct {
	mu      sync.Mutex
	visible bool
}

func newPlatformConsoleDriver() ConsoleWindowDriver {
	d := &win32ConsoleDriver{visible: true}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		v, _, _ := procIsWindowVisible.Call(hwnd)
		d.visible = v != 0
	}
	return d
}

func (d *win32ConsoleDriver) IsVisible() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		v, _, _ := procIsWindowVisible.Call(hwnd)
		d.visible = v != 0
	}
	return d.visible
}

func (d *win32ConsoleDriver) SetVisible(visible bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.visible = visible
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	if visible {
		_, _, _ = procShowWindow.Call(hwnd, swRestore)
		_, _, _ = procShowWindow.Call(hwnd, swShow)
		_, _, _ = procSetForegroundWin.Call(hwnd)
	} else {
		_, _, _ = procShowWindow.Call(hwnd, swHide)
	}
}

// DisableCloseButton 禁用控制台窗口右上角的关闭按钮 [X]，引导用户通过托盘图标隐藏控制台或安全退出（与 V2rayN 行为一致）。
func (d *win32ConsoleDriver) DisableCloseButton() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	hMenu, _, _ := procGetSystemMenu.Call(hwnd, 0)
	if hMenu != 0 {
		_, _, _ = procDeleteMenu.Call(hMenu, scClose, mfByCommand)
	}
}

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct {
	x int32
	y int32
}

type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type winGUID struct {
	data1 uint32
	data2 uint16
	data3 uint16
	data4 [8]byte
}

// notifyIconDataW 对应 Win32 <shellapi.h> 完整 NOTIFYICONDATAW 结构体（兼容 Windows 7~11 32/64 位）。
type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         winGUID
	hBalloonIcon     uintptr
}

var (
	activeTrayMu   sync.Mutex
	activeTray     *TrayController
	activeTrayHwnd uintptr
	activeTrayIcon uintptr
)

// startPlatformTray 在独立 OS 线程上启动 Win32 系统托盘消息循环，返回用于关闭托盘的 stop 函数。
func startPlatformTray(tc *TrayController) func() {
	if tc == nil {
		return func() {}
	}
	if tc.Console != nil {
		tc.Console.DisableCloseButton()
	}

	ready := make(chan struct{})
	var closeOnce sync.Once
	var readyOnce sync.Once
	markReady := func() {
		readyOnce.Do(func() {
			close(ready)
		})
	}

	go func() {
		defer echproxy.RecoverAndLog("Win32TrayLoop", func(_ any, _ []byte) {
			markReady()
		})
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		hInst, _, _ := procGetModuleHandleW.Call(0)
		className, _ := syscall.UTF16PtrFromString("ECHProxyTrayWindowClass")

		wc := wndClassExW{
			cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
			lpfnWndProc:   syscall.NewCallback(trayWndProc),
			hInstance:     hInst,
			lpszClassName: className,
		}
		_, _, _ = procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

		winName, _ := syscall.UTF16PtrFromString("ECHProxyTrayHiddenWindow")
		hwnd, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(className)),
			uintptr(unsafe.Pointer(winName)),
			0,
			0, 0, 0, 0,
			0, 0, hInst, 0,
		)
		if hwnd == 0 {
			log.Printf("[Tray] WARNING: CreateWindowExW failed, system tray unavailable")
			markReady()
			return
		}

		hIcon := createBuiltInTrayIcon(hInst)
		activeTrayMu.Lock()
		activeTray = tc
		activeTrayHwnd = hwnd
		activeTrayIcon = hIcon
		activeTrayMu.Unlock()

		tc.OnStateChanged = updateTrayTooltip
		addOrUpdateTrayIcon(hwnd, hIcon, tc.TooltipText(), true)
		log.Printf("[Tray] System tray initialized (click/double-click icon to show/hide console, right-click for PAC/Proxy menu)")
		markReady()

		var m msg
		for {
			ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
			if int32(ret) <= 0 {
				break
			}
			_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}

		removeTrayIcon(hwnd)
		if hIcon != 0 {
			_, _, _ = procDestroyIcon.Call(hIcon)
		}
	}()

	<-ready
	return func() {
		closeOnce.Do(func() {
			activeTrayMu.Lock()
			hwnd := activeTrayHwnd
			activeTrayHwnd = 0
			activeTrayMu.Unlock()
			if hwnd != 0 {
				removeTrayIcon(hwnd)
				_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
			}
		})
	}
}

func trayWndProc(hwnd uintptr, uMsg uint32, wParam, lParam uintptr) uintptr {
	defer echproxy.RecoverAndLog("trayWndProc", nil)
	switch uMsg {
	case wmTrayCallback:
		switch uint32(lParam) {
		case wmLButtonDblClk, wmLButtonUp:
			activeTrayMu.Lock()
			tc := activeTray
			activeTrayMu.Unlock()
			if tc != nil {
				tc.ToggleConsole()
			}
			return 0
		case wmRButtonUp:
			showTrayPopupMenu(hwnd)
			return 0
		}

	case wmCommand:
		cmdID := wParam & 0xFFFF
		activeTrayMu.Lock()
		tc := activeTray
		activeTrayMu.Unlock()
		if tc != nil {
			if shouldExit := tc.HandleCommand(cmdID); shouldExit {
				removeTrayIcon(hwnd)
				_, _, _ = procPostQuitMessage.Call(0)
			}
		}
		return 0

	case wmClose, wmDestroy:
		removeTrayIcon(hwnd)
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(uMsg), wParam, lParam)
	return ret
}

func showTrayPopupMenu(hwnd uintptr) {
	activeTrayMu.Lock()
	tc := activeTray
	activeTrayMu.Unlock()
	if tc == nil {
		return
	}

	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}
	defer procDestroyMenu.Call(hMenu)

	for _, item := range tc.MenuItems() {
		if item.Separator {
			_, _, _ = procAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
			continue
		}
		flags := uintptr(mfString)
		if item.Checked {
			flags |= mfChecked
		}
		titlePtr, _ := syscall.UTF16PtrFromString(item.Title)
		_, _, _ = procAppendMenuW.Call(hMenu, flags, item.ID, uintptr(unsafe.Pointer(titlePtr)))
	}

	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWin.Call(hwnd)
	_, _, _ = procTrackPopupMenu.Call(hMenu, tpmRightBtn|tpmBottomAlign, uintptr(pt.x), uintptr(pt.y), 0, hwnd, 0)
	_, _, _ = procPostMessageW.Call(hwnd, wmNull, 0, 0)
}

func updateTrayTooltip() {
	activeTrayMu.Lock()
	tc := activeTray
	hwnd := activeTrayHwnd
	hIcon := activeTrayIcon
	activeTrayMu.Unlock()
	if tc != nil && hwnd != 0 {
		addOrUpdateTrayIcon(hwnd, hIcon, tc.TooltipText(), false)
	}
}

func addOrUpdateTrayIcon(hwnd, hIcon uintptr, tip string, isAdd bool) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = wmTrayCallback
	nid.hIcon = hIcon

	utf16Tip, _ := syscall.UTF16FromString(tip)
	if len(utf16Tip) > len(nid.szTip)-1 {
		utf16Tip = utf16Tip[:len(nid.szTip)-1]
	}
	copy(nid.szTip[:], utf16Tip)

	action := uintptr(nimModify)
	if isAdd {
		action = nimAdd
	}
	_, _, _ = procShellNotifyIconW.Call(action, uintptr(unsafe.Pointer(&nid)))
}

func removeTrayIcon(hwnd uintptr) {
	if hwnd == 0 {
		return
	}
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
}

// createBuiltInTrayIcon 使用纯内存位图生成 16x16 亮青色“E”字盾牌托盘图标，无需携带外部 .ico 文件。
func createBuiltInTrayIcon(hInst uintptr) uintptr {
	// 16x16 单色 AND 掩码（全 0 表示不透明）与 16x16x4 BGRA XOR 像素阵列
	var andMask [32]byte
	var xorBits [16 * 16 * 4]byte

	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			idx := (y*16 + x) * 4
			// 圆角外框留透明
			if (x == 0 || x == 15) && (y == 0 || y == 15) {
				andMask[y*2+x/8] |= 1 << (7 - uint(x%8))
				continue
			}
			// 背景深蓝黑 (#171A21)
			b, g, r, a := byte(0x21), byte(0x1A), byte(0x17), byte(0xFF)
			// 绘制亮青色 (#5CE1E6) 边框与中间的字母 "E"
			isBorder := x == 1 || x == 14 || y == 1 || y == 14
			isLetterE := (x >= 4 && x <= 5 && y >= 4 && y <= 11) ||
				(x >= 4 && x <= 11 && (y == 4 || y == 7 || y == 11))
			if isBorder || isLetterE {
				b, g, r, a = 0xE6, 0xE1, 0x5C, 0xFF
			}
			xorBits[idx+0] = b
			xorBits[idx+1] = g
			xorBits[idx+2] = r
			xorBits[idx+3] = a
		}
	}

	hIcon, _, _ := procCreateIcon.Call(
		hInst,
		16, 16,
		1, 32,
		uintptr(unsafe.Pointer(&andMask[0])),
		uintptr(unsafe.Pointer(&xorBits[0])),
	)
	if hIcon != 0 {
		return hIcon
	}
	fallback, _, _ := procLoadIconW.Call(0, idiApplication)
	return fallback
}

// copyToClipboardOnPlatform 将文本写入 Windows 系统剪贴板。
func copyToClipboardOnPlatform(text string) error {
	r, _, err := procOpenClipboard.Call(0)
	if r == 0 {
		return err
	}
	defer procCloseClipboard.Call()
	_, _, _ = procEmptyClipboard.Call()

	utf16Buf, err := syscall.UTF16FromString(text)
	if err != nil {
		return err
	}
	sizeBytes := uintptr(len(utf16Buf) * 2)
	hMem, _, err := procGlobalAlloc.Call(gmemMoveable, sizeBytes)
	if hMem == 0 {
		return err
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return err
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(utf16Buf))
	copy(dst, utf16Buf)
	_, _, _ = procGlobalUnlock.Call(hMem)

	if res, _, cerr := procSetClipboardData.Call(cfUnicodeText, hMem); res == 0 {
		return cerr
	}
	return nil
}