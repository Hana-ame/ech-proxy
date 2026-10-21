package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

const exeSuffix443 = ".443.exe"

// filenameIs443 判断可执行文件名是否精确以 ".443.exe" 结尾（不区分大小写）。
func filenameIs443(name string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(name)), exeSuffix443)
}

func exeNameIs443() bool {
	return len(os.Args) > 0 && filenameIs443(os.Args[0])
}

// CLICommand 表示解析后的命令行操作与运行参数。
type CLICommand struct {
	Action       string       // "run", "check", "hosts-print", "hosts-apply", "hosts-clean", "ca-status", "ca-export", "ca-install", "pac", "sysproxy-pac", "sysproxy-global", "sysproxy-clear", "sysproxy-status", "version"
	Mode         string       // "smart" (默认), "local" (443), "portal" (8443), "http"
	Addr         string
	FallbackAddr string
	LocalProxy   bool
	HTTPMode     bool
	DataDir      string
	ConfigURL    string
	IPMode       string
	BootstrapIP  string
	NoBrowser    bool
	Verbose      bool
	AllowConnect bool
	ConnectMode  string
	HostsFile    string
	CAExportPath string
	SysProxy     SysProxyMode // 启动时自动设置的系统代理模式："pac"（smart 模式默认）、"global"、"off"
	EnableTray   bool         // 是否启用系统托盘（默认开启，支持双击隐藏/显示控制台与右键切换 PAC）
	HideConsole  bool         // 启动后是否自动隐藏控制台窗口到系统托盘
	Auth         *echproxy.AuthConfig
}

// parseCLIArgs 解析子命令与命令行标志（统一支持新一代子命令与传统旗舰参数）。
func parseCLIArgs(progName string, args []string, getenv func(string) string) (CLICommand, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	is443 := filenameIs443(progName)
	action := "run"
	subMode := ""

	// 识别前置子命令（如 ech-proxy check / hosts / ca / pac / sysproxy / local / portal / version）
	restArgs := args
	if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
		switch strings.ToLower(restArgs[0]) {
		case "run", "serve", "start", "proxy":
			action = "run"
			restArgs = restArgs[1:]
		case "local", "443":
			action = "run"
			subMode = "local"
			restArgs = restArgs[1:]
		case "portal", "8443":
			action = "run"
			subMode = "portal"
			restArgs = restArgs[1:]
		case "check", "validate":
			action = "check"
			restArgs = restArgs[1:]
		case "pac":
			action = "pac"
			restArgs = restArgs[1:]
		case "version":
			action = "version"
			restArgs = restArgs[1:]
		case "hosts":
			action = "hosts-print"
			restArgs = restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "print", "show":
					action = "hosts-print"
					restArgs = restArgs[1:]
				case "apply", "install", "sync":
					action = "hosts-apply"
					restArgs = restArgs[1:]
				case "clean", "remove", "uninstall":
					action = "hosts-clean"
					restArgs = restArgs[1:]
				}
			}
		case "ca", "cert":
			action = "ca-status"
			restArgs = restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "status", "path":
					action = "ca-status"
					restArgs = restArgs[1:]
				case "export":
					action = "ca-export"
					restArgs = restArgs[1:]
				case "install", "trust":
					action = "ca-install"
					restArgs = restArgs[1:]
				}
			}
		case "sysproxy":
			action = "sysproxy-status"
			restArgs = restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "pac", "auto":
					action = "sysproxy-pac"
					restArgs = restArgs[1:]
				case "global", "http", "all":
					action = "sysproxy-global"
					restArgs = restArgs[1:]
				case "clear", "off", "disable", "direct":
					action = "sysproxy-clear"
					restArgs = restArgs[1:]
				case "status", "show":
					action = "sysproxy-status"
					restArgs = restArgs[1:]
				}
			}
		}
	}

	defaultLocal := is443 || subMode == "local"
	defaultAddr := "127.0.0.1:8443"
	if defaultLocal {
		defaultAddr = "127.0.0.1:443"
	}

	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	modeFlag := fs.String("mode", subMode, "运行模式：smart（默认，集成自动 PAC/托盘/CONNECT/门户）、local（443 透明反代）、portal（8443 门户）、http（明文）")
	addr := fs.String("addr", defaultAddr, "监听地址（默认 127.0.0.1:8443，443 模式为 127.0.0.1:443）")
	localProxy := fs.Bool("local", defaultLocal, "启用 443 本地透明反向代理模式（自签名 CA + 按需签发原域名证书 + 自动 SNI/ECH）")
	dataDir := fs.String("data-dir", getenv("ECH_PROXY_DATA_DIR"), "本地 CA 与叶子证书存储目录（默认：程序所在目录）")
	configURL := fs.String("config", getenv("ECH_PROXY_CONFIG"), "upstream.json 配置文件路径或 URL（留空使用默认远程地址）")
	ipMode := fs.String("ip-mode", getenv("IP_MODE"), "锁定上游出口协议族：v4 或 v6（留空由系统自动选择）")
	localIP := fs.String("local-ip", getenv("LOCALIP"), "DoH 引导 IP（可选）")
	httpMode := fs.Bool("http", false, "以纯 HTTP 明文模式运行（与 -local 互斥）")
	noBrowser := fs.Bool("no-browser", false, "启动时不自动打开浏览器")
	verbose := fs.Bool("v", false, "输出逐请求详细调试日志")

	// 系统托盘、控制台显隐与自动设置 Windows PAC 参数（参考 V2rayN）
	sysProxyFlag := fs.String("sys-proxy", getenv("ECH_PROXY_SYS_PROXY"), "启动时自动配置系统代理模式：pac（默认自动配置 PAC）、global（全局代理）、off（不修改系统代理）")
	noTray := fs.Bool("no-tray", false, "禁用系统托盘图标")
	hideConsole := fs.Bool("hide-console", false, "启动后自动隐藏控制台窗口到系统托盘（双击托盘图标可随时恢复显示）")

	// 工具与安全标志
	checkConfig := fs.Bool("check-config", false, "校验 upstream.json 配置文件并退出（0=正常，1=配置错误，2=读取失败）")
	hostsPrint := fs.Bool("hosts-print", false, "打印本地 443 模式所需的完整 hosts 规则块并退出")
	hostsApply := fs.Bool("hosts-apply", false, "将 ech-proxy 受管域名规则自动写入系统 hosts 文件并退出（需管理员/root 权限）")
	hostsClean := fs.Bool("hosts-clean", false, "从系统 hosts 文件中清理 ech-proxy 受管规则块并退出")
	hostsFile := fs.String("hosts-file", "", "自定义 hosts 文件路径（默认使用系统 hosts 路径）")
	caExport := fs.String("ca-export", "", "导出本地自签 CA 根证书到指定文件路径并退出")
	caInstall := fs.Bool("ca-install", false, "将本地自签 CA 根证书一键安装到当前用户受信任根证书库并退出")
	allowConnect := fs.Bool("allow-connect", true, "启用 HTTP CONNECT 正向代理支持（默认在回环地址开启）")
	connectMode := fs.String("connect-mode", echproxy.ConnectModeAuto, "CONNECT 代理模式：auto/mitm（默认，支持 ECH/SNI 转发）或 tunnel（纯 TCP 透传）")
	token := fs.String("token", getenv("ECH_PROXY_TOKEN"), "代理访问鉴权 Bearer Token（可选）")
	user := fs.String("user", getenv("ECH_PROXY_USER"), "代理访问 BasicAuth 用户名（可选）")
	pass := fs.String("pass", getenv("ECH_PROXY_PASS"), "代理访问 BasicAuth 密码（可选）")

	if err := fs.Parse(restArgs); err != nil {
		return CLICommand{}, err
	}

	// 根据标志覆盖 Action
	switch {
	case *checkConfig:
		action = "check"
	case *hostsApply:
		action = "hosts-apply"
	case *hostsClean:
		action = "hosts-clean"
	case *hostsPrint:
		action = "hosts-print"
	case *caInstall:
		action = "ca-install"
	case *caExport != "":
		action = "ca-export"
	}
	if action == "ca-export" && *caExport == "" && fs.NArg() > 0 {
		*caExport = fs.Arg(0)
	}

	resolvedMode := strings.ToLower(strings.TrimSpace(*modeFlag))
	switch resolvedMode {
	case "local", "443":
		*localProxy = true
		if *addr == "127.0.0.1:8443" {
			*addr = "127.0.0.1:443"
		}
	case "http":
		*httpMode = true
	case "portal", "8443":
		*localProxy = false
	case "", "smart", "auto":
		if *localProxy {
			resolvedMode = "local"
		} else if *httpMode {
			resolvedMode = "http"
		} else {
			resolvedMode = "smart"
		}
	default:
		return CLICommand{}, fmt.Errorf("unknown -mode %q (valid: smart, local, portal, http)", *modeFlag)
	}

	if *localProxy && *httpMode {
		return CLICommand{}, fmt.Errorf("-local 与 -http 互斥：443 本地反代模式必须启用 TLS")
	}
	if *localProxy && *addr == "127.0.0.1:8443" && !flagWasPassed(fs, "addr") {
		*addr = "127.0.0.1:443"
	}

	// 解析启动时的系统代理策略：
	// - smart 模式默认自动启用系统 PAC（SysProxyPAC），开箱即用无需手动配置浏览器；
	// - local (443 hosts) 模式默认不修改系统代理（SysProxyOff），除非用户显式指定 -sys-proxy。
	var sysProxyMode SysProxyMode
	if strings.TrimSpace(*sysProxyFlag) != "" {
		m, err := NormalizeSysProxyMode(*sysProxyFlag)
		if err != nil {
			return CLICommand{}, err
		}
		sysProxyMode = m
	} else if *localProxy {
		sysProxyMode = SysProxyOff
	} else {
		sysProxyMode = SysProxyPAC
	}

	fallbackAddr := ""
	if *localProxy && strings.HasSuffix(*addr, ":443") {
		fallbackAddr = "127.0.0.1:8443"
	}

	return CLICommand{
		Action:       action,
		Mode:         resolvedMode,
		Addr:         *addr,
		FallbackAddr: fallbackAddr,
		LocalProxy:   *localProxy,
		HTTPMode:     *httpMode,
		DataDir:      *dataDir,
		ConfigURL:    *configURL,
		IPMode:       *ipMode,
		BootstrapIP:  *localIP,
		NoBrowser:    *noBrowser,
		Verbose:      *verbose,
		AllowConnect: *allowConnect,
		ConnectMode:  *connectMode,
		HostsFile:    *hostsFile,
		CAExportPath: *caExport,
		SysProxy:     sysProxyMode,
		EnableTray:   !*noTray,
		HideConsole:  *hideConsole,
		Auth: &echproxy.AuthConfig{
			Token:    strings.TrimSpace(*token),
			Username: strings.TrimSpace(*user),
			Password: strings.TrimSpace(*pass),
		},
	}, nil
}

func flagWasPassed(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// runToolAction 执行非长驻服务的 CLI 工具型子命令（check / hosts / ca / pac / sysproxy / version），返回退出码。
func runToolAction(cmd CLICommand, out io.Writer) int {
	switch cmd.Action {
	case "version":
		fmt.Fprintf(out, "ech-proxy %s\n", echproxy.BuildVersionInfo())
		return 0

	case "check":
		src := cmd.ConfigURL
		if src == "" {
			src = echproxy.DefaultUpstreamConfigURL
		}
		buf, err := echproxy.FetchBytes(src)
		if err != nil {
			fmt.Fprintf(out, "ERROR: cannot load config %q: %v\n", src, err)
			return 2
		}
		issues, err := echproxy.ValidateConfig(buf)
		if err != nil {
			fmt.Fprintf(out, "ERROR: invalid JSON in %q: %v\n", src, err)
			return 1
		}
		cfg, _ := echproxy.ParseConfig(buf)
		entryCount := 0
		if cfg != nil {
			entryCount = len(cfg.Upstreams)
		}
		fmt.Fprintf(out, "Config: %s\nEntries: %d\n%s\n", src, entryCount, echproxy.FormatConfigIssues(issues))
		if echproxy.ConfigHasErrors(issues) {
			return 1
		}
		return 0

	case "hosts-print":
		cfg, _ := echproxy.LoadConfig(cmd.ConfigURL)
		fmt.Fprint(out, echproxy.GenerateHostsBlock(cfg, "127.0.0.1"))
		return 0

	case "hosts-apply":
		cfg, err := echproxy.LoadConfig(cmd.ConfigURL)
		if err != nil {
			fmt.Fprintf(out, "WARNING: failed to load remote config (%v), using built-in Pixiv/CDN domain list\n", err)
		}
		targetPath := cmd.HostsFile
		if targetPath == "" {
			targetPath = echproxy.DefaultSystemHostsPath()
		}
		if err := echproxy.ApplyHostsBlock(targetPath, "127.0.0.1", cfg); err != nil {
			fmt.Fprintf(out, "ERROR: failed to update %s (please run as Administrator / sudo): %v\n", targetPath, err)
			return 1
		}
		fmt.Fprintf(out, "Successfully updated managed hosts block in %s\n", targetPath)
		return 0

	case "hosts-clean":
		targetPath := cmd.HostsFile
		if targetPath == "" {
			targetPath = echproxy.DefaultSystemHostsPath()
		}
		if err := echproxy.RemoveHostsBlock(targetPath); err != nil {
			fmt.Fprintf(out, "ERROR: failed to clean %s (please run as Administrator / sudo): %v\n", targetPath, err)
			return 1
		}
		fmt.Fprintf(out, "Successfully removed ech-proxy managed block from %s\n", targetPath)
		return 0

	case "ca-status", "ca-export", "ca-install":
		dataDir := cmd.DataDir
		if dataDir == "" {
			dataDir, _ = echproxy.DefaultDataDir()
		}
		st, err := echproxy.NewCertStore(dataDir)
		if err != nil {
			fmt.Fprintf(out, "ERROR: initialize CA store in %q: %v\n", dataDir, err)
			return 1
		}
		if cmd.Action == "ca-install" {
			if err := installCAOnPlatform(st.CAPath()); err != nil {
				fmt.Fprintf(out, "ERROR: %v\n", err)
				return 1
			}
			fmt.Fprintf(out, "Successfully installed local CA certificate into user Root store: %s\n", st.CAPath())
			return 0
		}
		if cmd.Action == "ca-export" && cmd.CAExportPath != "" {
			pemBytes, err := st.CAPEM()
			if err != nil {
				fmt.Fprintf(out, "ERROR: export CA: %v\n", err)
				return 1
			}
			if err := os.WriteFile(cmd.CAExportPath, pemBytes, 0o644); err != nil {
				fmt.Fprintf(out, "ERROR: write CA to %q: %v\n", cmd.CAExportPath, err)
				return 1
			}
			fmt.Fprintf(out, "CA certificate exported to %s (valid until %s)\n", cmd.CAExportPath, st.CAValidUntil().Format("2006-01-02"))
			return 0
		}
		fmt.Fprintf(out, "CA Path: %s\nValid Until: %s\n", st.CAPath(), st.CAValidUntil().Format("2006-01-02"))
		return 0

	case "pac":
		cfg, _ := echproxy.LoadConfig(cmd.ConfigURL)
		fmt.Fprint(out, echproxy.GeneratePAC(cfg, cmd.Addr, false))
		return 0

	case "sysproxy-pac":
		mgr := NewSysProxyManager(cmd.Addr, nil)
		if err := mgr.SetMode(SysProxyPAC); err != nil {
			fmt.Fprintf(out, "ERROR: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "System proxy set to PAC mode: %s\n", mgr.PACURL())
		return 0

	case "sysproxy-global":
		mgr := NewSysProxyManager(cmd.Addr, nil)
		if err := mgr.SetMode(SysProxyGlobal); err != nil {
			fmt.Fprintf(out, "ERROR: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "System proxy set to Global mode: %s\n", NormalizeLoopbackHostPort(cmd.Addr))
		return 0

	case "sysproxy-clear":
		mgr := NewSysProxyManager(cmd.Addr, nil)
		if err := mgr.SetMode(SysProxyOff); err != nil {
			fmt.Fprintf(out, "ERROR: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "System proxy cleared (Direct mode)\n")
		return 0

	case "sysproxy-status":
		mgr := NewSysProxyManager(cmd.Addr, nil)
		fmt.Fprintf(out, "%s\n", mgr.StatusText())
		return 0
	}
	return -1
}

func main() {
	progName := "ech-proxy"
	if len(os.Args) > 0 {
		progName = os.Args[0]
	}
	cmd, err := parseCLIArgs(progName, os.Args[1:], os.Getenv)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if code := runToolAction(cmd, os.Stdout); code >= 0 {
		os.Exit(code)
	}

	echproxy.Debug = cmd.Verbose

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:         cmd.Addr,
		FallbackAddr: cmd.FallbackAddr,
		HTTPMode:     cmd.HTTPMode,
		ConfigURL:    cmd.ConfigURL,
		BootstrapIP:  cmd.BootstrapIP,
		IPMode:       cmd.IPMode,
		LocalProxy:   cmd.LocalProxy,
		DataDir:      cmd.DataDir,
		AllowConnect: cmd.AllowConnect,
		ConnectMode:  cmd.ConnectMode,
		Auth:         cmd.Auth,
	})
	if err != nil {
		log.Fatalf("Proxy server initialization failed: %v", err)
	}

	actualListenAddr := fmt.Sprintf("127.0.0.1:%d", srv.Port)
	scheme := "https"
	if cmd.HTTPMode {
		scheme = "http"
	}
	portalURL := fmt.Sprintf("%s://l.moonchan.xyz:%d", scheme, srv.Port)
	caPath := ""
	if srv.CertStore != nil {
		caPath = srv.CertStore.CAPath()
	}

	// 1. 初始化系统代理管理器（参考 V2rayN，启动时自动为 Windows 配置 PAC，退出时自动清理）
	sysProxyMgr := NewSysProxyManager(actualListenAddr, nil)
	if cmd.SysProxy != SysProxyOff {
		if err := sysProxyMgr.SetMode(cmd.SysProxy); err != nil {
			log.Printf("WARNING: Failed to set system proxy (%s): %v", cmd.SysProxy, err)
		}
	}
	defer sysProxyMgr.CleanupOnExit()

	srv.PrintBanner(cmd.BootstrapIP)
	fmt.Printf("  System Proxy: %s\n", sysProxyMgr.StatusText())
	if cmd.EnableTray {
		fmt.Printf("  System Tray: Enabled (double-click tray icon to show/hide console, right-click for PAC/Global menu)\n")
	}
	fmt.Printf("=================\n")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 2. 启动系统托盘与控制台显隐控制器
	var stopTray = func() {}
	if cmd.EnableTray {
		trayCtrl := NewTrayController(actualListenAddr, portalURL, caPath, sysProxyMgr, nil, func() {
			stop()
		})
		stopTray = startPlatformTray(trayCtrl)
		if cmd.HideConsole {
			trayCtrl.SetConsoleVisible(false)
		}
	}
	defer stopTray()

	if !cmd.NoBrowser && !cmd.LocalProxy {
		go openBrowser(portalURL)
	}

	go func() {
		<-ctx.Done()
		log.Printf("Shutting down gracefully (cleaning up system proxy & tray)...")
		sysProxyMgr.CleanupOnExit()
		stopTray()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err == nil {
		go func() { _ = cmd.Wait() }()
	}
}