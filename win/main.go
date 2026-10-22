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

const (
	exeSuffix443  = ".443.exe"
	exeSuffix8443 = ".8443.exe"
)

func filenameIs443(name string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(name)), exeSuffix443)
}

func filenameIs8443(name string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(name)), exeSuffix8443)
}

func exeNameIs443() bool {
	return len(os.Args) > 0 && filenameIs443(os.Args[0])
}

func FlagOverviewText() string {
	return `=== ech-proxy 命令行 Flag 一览 ===
  三种运行方案（高内聚、完全解耦）:
    ech-proxy.exe       [默认主流 PAC 方案] 本地 CA MITM + DoH/SNI/ECH/Fragment + pac.txt（默认 8443，自适应任意端口；8443 方案在后台静默兼容运行）
    .*.443.exe          [443 方案] 只与 listen 443 有关，仅监听 443 端口（本地 CA + SNI/ECH），其余功能一律不运行
    *.8443.exe          [8443 方案] 公网真实证书门户反代（加载 certs/l.moonchan.xyz/ 与 upstream.json，静默非阻塞兼容）

  出口与路由模式 Flag:
    -4                  强制 v4 出口 (IPv4 only，默认)
    -6                  强制 v6 出口 (IPv6 only)
    -dual               双端出口 (IPv4 + IPv6 双栈)
    -all                开启全局模式（无视 pac.txt 白名单，所有网站均通过 ech-proxy 代理）

  远程配置 Flag:
    -whitelist-url      自定义 pac.txt 代理白名单地址（默认 https://4545810.xyz/pac.txt）

  CA 证书与自动更新子命令 / Flag:
    ca install          一键安装本地 CA 根证书 (-ca-install)
    ca uninstall        一键卸载本地 CA 根证书 (-ca-uninstall)
    update              立即检查并下载最新 Release 更新 (-update / --check-update)

  其他参数:
    -addr <host:port>   监听地址（PAC 方案默认 127.0.0.1:8443，支持任意非 443 端口）
    -hide-console       启动后隐藏控制台窗口到系统托盘
    -no-tray            禁用系统托盘图标
    -local-ip <ip>      指定首选 DoH 引导 IP
    -v                  输出逐请求详细调试日志
`
}

type CLICommand struct {
	Action           string
	Mode             string
	AllMode          bool
	Addr             string
	FallbackAddr     string
	LocalProxy       bool
	PortalMode       bool
	HTTPMode         bool
	DataDir          string
	ConfigURL        string
	IPMode           string
	BootstrapIP      string
	NoBrowser        bool
	Verbose          bool
	AllowConnect     bool
	ConnectMode      string
	HostsFile        string
	CAExportPath     string
	SysProxy         SysProxyMode
	EnableTray       bool
	HideConsole      bool
	NoAdScript       bool
	SkipAdScript     bool
	SkipAdBlock      bool
	AdScriptURL      string
	WhitelistURL     string
	AdultSitesURL    string
	BlocklistURL     string
	AdScriptInterval time.Duration
	NoAutoUpdate     bool
	LogDir           string
	LogFile          string
	NoLogFile        bool
	Auth             *echproxy.AuthConfig
}

func envBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseCLIArgs(progName string, args []string, getenv func(string) string) (CLICommand, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	is443 := filenameIs443(progName)
	is8443 := filenameIs8443(progName)
	action := "run"
	subMode := ""
	subAll := false

	restArgs := args
	if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
		switch strings.ToLower(restArgs[0]) {
		case "run", "serve", "start", "proxy":
			restArgs = restArgs[1:]
		case "help", "flags":
			action, restArgs = "help", restArgs[1:]
		case "update", "upgrade", "self-update":
			action, restArgs = "update", restArgs[1:]
		case "all":
			subAll, restArgs = true, restArgs[1:]
		case "local", "443":
			if !is443 {
				return CLICommand{}, fmt.Errorf("文件名 %q 不匹配 .*.443.exe：禁止开启 443 方案", filepath.Base(progName))
			}
			subMode, restArgs = "local", restArgs[1:]
		case "portal", "8443":
			if !is8443 {
				return CLICommand{}, fmt.Errorf("文件名 %q 不包含 .8443.exe：显式 portal 子命令要求文件名为 *.8443.exe（默认二进制已在后台静默兼容运行 8443 方案）", filepath.Base(progName))
			}
			subMode, restArgs = "portal", restArgs[1:]
		case "check", "validate":
			action, restArgs = "check", restArgs[1:]
		case "pac":
			action, restArgs = "pac", restArgs[1:]
		case "version":
			action, restArgs = "version", restArgs[1:]
		case "hosts":
			action, restArgs = "hosts-print", restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "print", "show":
					action, restArgs = "hosts-print", restArgs[1:]
				case "apply", "install", "sync":
					action, restArgs = "hosts-apply", restArgs[1:]
				case "clean", "remove", "uninstall":
					action, restArgs = "hosts-clean", restArgs[1:]
				}
			}
		case "ca", "cert":
			action, restArgs = "ca-status", restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "status", "path":
					action, restArgs = "ca-status", restArgs[1:]
				case "export":
					action, restArgs = "ca-export", restArgs[1:]
				case "install", "trust":
					action, restArgs = "ca-install", restArgs[1:]
				case "uninstall", "remove", "delete", "clean", "untrust":
					action, restArgs = "ca-uninstall", restArgs[1:]
				}
			}
		case "sysproxy":
			action, restArgs = "sysproxy-status", restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "pac", "auto":
					action, restArgs = "sysproxy-pac", restArgs[1:]
				case "global", "http", "all":
					action, restArgs = "sysproxy-global", restArgs[1:]
				case "clear", "off", "disable", "direct":
					action, restArgs = "sysproxy-clear", restArgs[1:]
				case "status", "show":
					action, restArgs = "sysproxy-status", restArgs[1:]
				}
			}
		case "logs", "log":
			action, restArgs = "logs-path", restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "path", "status", "dir":
					action, restArgs = "logs-path", restArgs[1:]
				case "tail", "show", "cat", "print":
					action, restArgs = "logs-tail", restArgs[1:]
				case "crash":
					action, restArgs = "logs-crash", restArgs[1:]
				case "clean", "clear":
					action, restArgs = "logs-clean", restArgs[1:]
				}
			}
		}
	}

	defaultAddr := "127.0.0.1:8443"
	if is443 {
		defaultAddr = "127.0.0.1:443"
	}

	defaultInterval := echproxy.DefaultAdScriptInterval
	if envInt := strings.TrimSpace(getenv("ECH_PROXY_AD_SCRIPT_INTERVAL")); envInt != "" {
		if d, err := time.ParseDuration(envInt); err == nil && d > 0 {
			defaultInterval = d
		}
	}

	defaultIPModeEnv := strings.TrimSpace(getenv("IP_MODE"))
	if defaultIPModeEnv == "" {
		defaultIPModeEnv = strings.TrimSpace(getenv("ECH_PROXY_IPMODE"))
	}
	if defaultIPModeEnv == "" {
		defaultIPModeEnv = "ipv4"
	}

	defaultWhitelistEnv := strings.TrimSpace(getenv("ECH_PROXY_WHITELIST_URL"))
	if defaultWhitelistEnv == "" {
		defaultWhitelistEnv = strings.TrimSpace(getenv("ECH_PROXY_ADULT_DOMAINS_URL"))
	}

	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	flag4 := fs.Bool("4", false, "强制 v4 出口")
	flag6 := fs.Bool("6", false, "强制 v6 出口")
	flagDual := fs.Bool("dual", false, "双端出口")
	allFlag := fs.Bool("all", subAll || envBool(getenv("ECH_PROXY_ALL")), "全局模式")
	skipAdScript := fs.Bool("skip-ad-script", envBool(getenv("ECH_PROXY_SKIP_AD_SCRIPT")) || envBool(getenv("ECH_PROXY_NO_AD_SCRIPT")), "跳过脚本注入步骤")
	skipAdBlock := fs.Bool("skip-ad-block", envBool(getenv("ECH_PROXY_SKIP_AD_BLOCK")), "跳过内容过滤步骤")

	modeFlag := fs.String("mode", subMode, "运行模式")
	addr := fs.String("addr", defaultAddr, "监听地址")
	localProxy := fs.Bool("local", is443, "启用 443 模式")
	dataDir := fs.String("data-dir", getenv("ECH_PROXY_DATA_DIR"), "数据目录")
	configURL := fs.String("config", getenv("ECH_PROXY_CONFIG"), "upstream.json 地址")
	ipModeFlag := fs.String("ipmode", defaultIPModeEnv, "出口协议族")
	ipModeDash := fs.String("ip-mode", "", "出口协议族别名")
	localIP := fs.String("local-ip", getenv("LOCALIP"), "DoH 引导 IP")
	httpMode := fs.Bool("http", false, "HTTP 明文模式")
	noBrowser := fs.Bool("no-browser", false, "不自动打开浏览器")
	verbose := fs.Bool("v", false, "详细日志")
	sysProxyFlag := fs.String("sys-proxy", getenv("ECH_PROXY_SYS_PROXY"), "系统代理模式")
	noTray := fs.Bool("no-tray", false, "禁用托盘")
	hideConsole := fs.Bool("hide-console", false, "隐藏控制台")
	whitelistURL := fs.String("whitelist-url", defaultWhitelistEnv, "pac.txt 地址")
	adultSitesURL := fs.String("adult-sites-url", getenv("ECH_PROXY_ADULT_SITES_URL"), "自定义站点清单地址")
	adultDomainsAlias := fs.String("adult-domains-url", "", "pac.txt 别名")
	blocklistURL := fs.String("blocklist-url", getenv("ECH_PROXY_BLOCKLIST_URL"), "自定义补充规则地址")
	noAdScriptAlias := fs.Bool("no-ad-script", false, "--skip-ad-script 别名")
	disableScriptAlias := fs.Bool("disable-ad-script", false, "--skip-ad-script 别名")
	adScriptURL := fs.String("ad-script-url", getenv("ECH_PROXY_AD_SCRIPT_URL"), "自定义脚本地址")
	adScriptInterval := fs.Duration("ad-script-interval", defaultInterval, "自动更新间隔")
	updateNow := fs.Bool("update", false, "立即更新")
	checkUpdateAlias := fs.Bool("check-update", false, "立即更新")
	noAutoUpdate := fs.Bool("no-auto-update", envBool(getenv("ECH_PROXY_NO_AUTO_UPDATE")), "禁用自动更新")
	logDir := fs.String("log-dir", getenv("ECH_PROXY_LOG_DIR"), "日志目录")
	logFile := fs.String("log-file", getenv("ECH_PROXY_LOG_FILE"), "日志文件")
	noLogFile := fs.Bool("no-log-file", envBool(getenv("ECH_PROXY_NO_LOG_FILE")), "禁用日志文件")
	checkConfig := fs.Bool("check-config", false, "校验配置")
	hostsPrint := fs.Bool("hosts-print", false, "打印 hosts")
	hostsApply := fs.Bool("hosts-apply", false, "写入 hosts")
	hostsClean := fs.Bool("hosts-clean", false, "清理 hosts")
	hostsFile := fs.String("hosts-file", "", "hosts 路径")
	caExport := fs.String("ca-export", "", "导出 CA")
	caInstall := fs.Bool("ca-install", false, "安装 CA")
	caUninstall := fs.Bool("ca-uninstall", false, "卸载 CA")
	allowConnect := fs.Bool("allow-connect", true, "允许 CONNECT")
	connectMode := fs.String("connect-mode", echproxy.ConnectModeAuto, "CONNECT 模式")
	token := fs.String("token", getenv("ECH_PROXY_TOKEN"), "Token")
	user := fs.String("user", getenv("ECH_PROXY_USER"), "User")
	pass := fs.String("pass", getenv("ECH_PROXY_PASS"), "Pass")

	if err := fs.Parse(restArgs); err != nil {
		if err == flag.ErrHelp {
			return CLICommand{Action: "help"}, nil
		}
		return CLICommand{}, err
	}

	switch {
	case *updateNow || *checkUpdateAlias:
		action = "update"
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
	case *caUninstall:
		action = "ca-uninstall"
	case *caExport != "":
		action = "ca-export"
	}
	if action == "ca-export" && *caExport == "" && fs.NArg() > 0 {
		*caExport = fs.Arg(0)
	}

	allMode := *allFlag
	portalMode := is8443
	resolvedMode := strings.ToLower(strings.TrimSpace(*modeFlag))
	switch resolvedMode {
	case "all", "global":
		allMode, resolvedMode = true, "smart"
	case "local", "443":
		if !is443 {
			return CLICommand{}, fmt.Errorf("文件名 %q 不匹配 .*.443.exe：禁止开启 443 方案", filepath.Base(progName))
		}
		*localProxy = true
		if *addr == "127.0.0.1:8443" {
			*addr = "127.0.0.1:443"
		}
	case "http":
		*httpMode = true
	case "portal", "8443":
		if !is8443 {
			return CLICommand{}, fmt.Errorf("文件名 %q 不包含 .8443.exe：8443 方案要求文件名为 *.8443.exe", filepath.Base(progName))
		}
		*localProxy, portalMode = false, true
	case "", "smart", "auto", "whitelist":
		if is443 {
			*localProxy, resolvedMode = true, "local"
		} else if is8443 {
			*localProxy, portalMode, resolvedMode = false, true, "portal"
		} else if *httpMode {
			resolvedMode = "http"
		} else {
			resolvedMode = "smart"
		}
	default:
		return CLICommand{}, fmt.Errorf("unknown -mode %q", *modeFlag)
	}

	if !is443 {
		if *localProxy || flagWasPassed(fs, "local") {
			return CLICommand{}, fmt.Errorf("文件名 %q 不匹配 .*.443.exe：禁止运行 443 方案代码", filepath.Base(progName))
		}
		if echproxy.IsPort443(*addr) {
			return CLICommand{}, fmt.Errorf("文件名 %q 不匹配 .*.443.exe：禁止监听 443 端口 (%s)", filepath.Base(progName), *addr)
		}
		*localProxy = false
	} else {
		// 在命名为 .*.443.exe 的时候，只有 443 方案（listen 443）会被开启，其他都不会运行
		*localProxy = true
		portalMode = false
		if !echproxy.IsPort443(*addr) {
			return CLICommand{}, fmt.Errorf("443 方案 (.*.443.exe) 只与 listen 443 有关，禁止监听非 443 端口 (%s)", *addr)
		}
	}
	if *localProxy && *httpMode {
		return CLICommand{}, fmt.Errorf("-local 与 -http 互斥")
	}

	shorthandCount := 0
	for _, b := range []bool{*flag4, *flag6, *flagDual} {
		if b {
			shorthandCount++
		}
	}
	if shorthandCount > 1 {
		return CLICommand{}, fmt.Errorf("-4, -6, -dual 互斥")
	}
	rawIPMode := strings.TrimSpace(*ipModeFlag)
	if flagWasPassed(fs, "ip-mode") || strings.TrimSpace(*ipModeDash) != "" {
		rawIPMode = strings.TrimSpace(*ipModeDash)
	}
	switch {
	case *flag4:
		rawIPMode = "v4"
	case *flag6:
		rawIPMode = "v6"
	case *flagDual:
		rawIPMode = "dual"
	}
	normalizedIPMode, ipErr := echproxy.ValidateIPMode(rawIPMode)
	if ipErr != nil {
		return CLICommand{}, ipErr
	}

	var sysProxyMode SysProxyMode
	if *localProxy {
		// 443 方案下其他功能一律不运行
		sysProxyMode = SysProxyOff
	} else if strings.TrimSpace(*sysProxyFlag) != "" {
		m, err := NormalizeSysProxyMode(*sysProxyFlag)
		if err != nil {
			return CLICommand{}, err
		}
		sysProxyMode = m
	} else if portalMode {
		sysProxyMode = SysProxyOff
	} else {
		sysProxyMode = SysProxyPAC
	}

	resolvedWhitelistURL := strings.TrimSpace(*whitelistURL)
	if resolvedWhitelistURL == "" {
		resolvedWhitelistURL = strings.TrimSpace(*adultDomainsAlias)
	}
	// 443 方案只和 listen 443 有关系，绝不设置 FallbackAddr 到 8443
	fallbackAddr := ""
	resolvedSkipAdScript := *skipAdScript || *noAdScriptAlias || *disableScriptAlias

	enableTray := !*noTray && !*localProxy
	noAutoUpd := *noAutoUpdate || *localProxy
	allowConn := *allowConnect && !*localProxy

	return CLICommand{
		Action:           action,
		Mode:             resolvedMode,
		AllMode:          allMode && !*localProxy,
		Addr:             *addr,
		FallbackAddr:     fallbackAddr,
		LocalProxy:       *localProxy,
		PortalMode:       portalMode,
		HTTPMode:         *httpMode,
		DataDir:          *dataDir,
		ConfigURL:        *configURL,
		IPMode:           normalizedIPMode,
		BootstrapIP:      *localIP,
		NoBrowser:        *noBrowser || *localProxy,
		Verbose:          *verbose,
		AllowConnect:     allowConn,
		ConnectMode:      *connectMode,
		HostsFile:        *hostsFile,
		CAExportPath:     *caExport,
		SysProxy:         sysProxyMode,
		EnableTray:       enableTray,
		HideConsole:      *hideConsole,
		NoAdScript:       resolvedSkipAdScript,
		SkipAdScript:     resolvedSkipAdScript,
		SkipAdBlock:      *skipAdBlock,
		AdScriptURL:      strings.TrimSpace(*adScriptURL),
		WhitelistURL:     resolvedWhitelistURL,
		AdultSitesURL:    strings.TrimSpace(*adultSitesURL),
		BlocklistURL:     strings.TrimSpace(*blocklistURL),
		AdScriptInterval: *adScriptInterval,
		NoAutoUpdate:     noAutoUpd,
		LogDir:           strings.TrimSpace(*logDir),
		LogFile:          strings.TrimSpace(*logFile),
		NoLogFile:        *noLogFile,
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

func resolveLogDir(cmd CLICommand) string {
	if cmd.LogFile != "" {
		return filepath.Dir(cmd.LogFile)
	}
	if cmd.LogDir != "" {
		return cmd.LogDir
	}
	dataDir := cmd.DataDir
	if dataDir == "" {
		dataDir, _ = echproxy.DefaultDataDir()
	}
	return echproxy.DefaultLogDir(dataDir)
}

func runToolAction(cmd CLICommand, out io.Writer) int {
	switch cmd.Action {
	case "help":
		fmt.Fprint(out, FlagOverviewText())
		return 0
	case "version":
		fmt.Fprintf(out, "ech-proxy %s\n", echproxy.BuildVersionInfo())
		return 0
	case "update":
		upd := NewUpdater(UpdaterOptions{})
		staged, err := upd.CheckAndDownloadOnce()
		if err != nil {
			fmt.Fprintf(out, "ERROR: update check failed: %v\n", err)
			return 1
		}
		if staged {
			fmt.Fprintf(out, "Update downloaded and verified (%s -> %s); will replace on exit.\n", upd.AssetName(), upd.StagedPath())
			_, _ = upd.ApplyStagedUpdateOnExit()
		} else {
			fmt.Fprintf(out, "Already up to date (%s).\n", upd.AssetName())
		}
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
		cfg, _ := echproxy.LoadConfig(cmd.ConfigURL)
		targetPath := cmd.HostsFile
		if targetPath == "" {
			targetPath = echproxy.DefaultSystemHostsPath()
		}
		if err := echproxy.ApplyHostsBlock(targetPath, "127.0.0.1", cfg); err != nil {
			fmt.Fprintf(out, "ERROR: failed to update %s: %v\n", targetPath, err)
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
			fmt.Fprintf(out, "ERROR: failed to clean %s: %v\n", targetPath, err)
			return 1
		}
		fmt.Fprintf(out, "Successfully removed ech-proxy managed block from %s\n", targetPath)
		return 0
	case "ca-status", "ca-export", "ca-install", "ca-uninstall":
		dataDir := cmd.DataDir
		if dataDir == "" {
			dataDir, _ = echproxy.DefaultDataDir()
		}
		if cmd.Action == "ca-uninstall" {
			if err := uninstallCAOnPlatform(filepath.Join(dataDir, "ca", "ca.pem")); err != nil {
				fmt.Fprintf(out, "ERROR: %v\n", err)
				return 1
			}
			fmt.Fprintf(out, "Successfully uninstalled local CA certificate from Root store\n")
			return 0
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
			fmt.Fprintf(out, "Successfully installed local CA certificate: %s\n", st.CAPath())
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
			fmt.Fprintf(out, "CA certificate exported to %s\n", cmd.CAExportPath)
			return 0
		}
		fmt.Fprintf(out, "CA Path: %s\nValid Until: %s\n", st.CAPath(), st.CAValidUntil().Format("2006-01-02"))
		return 0
	case "pac":
		var wl []string
		wlURL := cmd.WhitelistURL
		if wlURL == "" {
			wlURL = echproxy.DefaultWhitelistURL
		}
		if raw, err := echproxy.FetchBytes(wlURL); err == nil {
			wl, _ = echproxy.ParseDomainList(raw)
		}
		fmt.Fprint(out, echproxy.GeneratePAC(nil, cmd.Addr, cmd.AllMode, wl))
		return 0
	case "sysproxy-pac":
		mgr := NewSysProxyManager(cmd.Addr, nil)
		mgr.SetAllMode(cmd.AllMode)
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
	case "logs-path":
		dir := resolveLogDir(cmd)
		logFile := cmd.LogFile
		if logFile == "" {
			logFile = filepath.Join(dir, "ech-proxy.log")
		}
		fmt.Fprintf(out, "Log Dir:    %s\nLog File:   %s\nCrash File: %s\n", dir, logFile, filepath.Join(dir, "crash-latest.log"))
		return 0
	case "logs-tail":
		dir := resolveLogDir(cmd)
		logFile := cmd.LogFile
		if logFile == "" {
			logFile = filepath.Join(dir, "ech-proxy.log")
		}
		data, err := os.ReadFile(logFile)
		if err != nil {
			fmt.Fprintf(out, "ERROR: cannot read log file %s: %v\n", logFile, err)
			return 1
		}
		lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
		if len(lines) > 100 {
			lines = lines[len(lines)-100:]
		}
		fmt.Fprintln(out, strings.Join(lines, "\n"))
		return 0
	case "logs-crash":
		dir := resolveLogDir(cmd)
		data, err := os.ReadFile(filepath.Join(dir, "crash-latest.log"))
		if err != nil {
			fmt.Fprintf(out, "No crash log found\n")
			return 0
		}
		fmt.Fprint(out, string(data))
		return 0
	case "logs-clean":
		dir := resolveLogDir(cmd)
		if err := echproxy.CleanLogs(dir); err != nil {
			fmt.Fprintf(out, "ERROR: failed to clean logs: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "Cleaned log files in %s\n", dir)
		return 0
	}
	return -1
}

func main() {
	var (
		logMgr      *echproxy.Logger
		sysProxyMgr *SysProxyManager
		updater     *Updater
	)
	defer echproxy.RecoverAndLog("main", func(_ any, _ []byte) {
		if sysProxyMgr != nil {
			sysProxyMgr.CleanupOnExit()
		}
		if updater != nil {
			_, _ = updater.ApplyStagedUpdateOnExit()
		}
		if logMgr != nil {
			logMgr.Sync()
			_ = logMgr.Close()
		}
		os.Exit(1)
	})

	progName := "ech-proxy"
	if len(os.Args) > 0 {
		progName = os.Args[0]
	}
	if !filenameIs443(progName) {
		_, _ = ApplyPendingUpdateOnStartup("")
	}

	cmd, err := parseCLIArgs(progName, os.Args[1:], os.Getenv)
	if err != nil {
		echproxy.RecordFatalError("CLI-ParseArgs", err)
		fmt.Fprintln(os.Stderr, FlagOverviewText())
		os.Exit(2)
	}
	if code := runToolAction(cmd, os.Stdout); code >= 0 {
		os.Exit(code)
	}

	logDir := resolveLogDir(cmd)
	if mgr, logErr := echproxy.InitLogger(echproxy.LoggerOptions{
		LogDir:      logDir,
		LogFile:     cmd.LogFile,
		DisableFile: cmd.NoLogFile,
		ConsoleOut:  os.Stderr,
	}); logErr == nil {
		logMgr = mgr
		defer logMgr.Close()
		logMgr.WriteStartupHeader(echproxy.BuildVersionInfo(), os.Args, map[string]string{
			"Mode":       cmd.Mode,
			"AllMode":    fmt.Sprintf("%v", cmd.AllMode),
			"IPMode":     echproxy.FormatIPMode(cmd.IPMode),
			"ListenAddr": cmd.Addr,
		})
	}

	echproxy.Debug = cmd.Verbose

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:             cmd.Addr,
		FallbackAddr:     cmd.FallbackAddr,
		HTTPMode:         cmd.HTTPMode,
		PortalMode:       cmd.PortalMode,
		ConfigURL:        cmd.ConfigURL,
		BootstrapIP:      cmd.BootstrapIP,
		IPMode:           cmd.IPMode,
		AllMode:          cmd.AllMode,
		LocalProxy:       cmd.LocalProxy,
		DataDir:          cmd.DataDir,
		AllowConnect:     cmd.AllowConnect,
		ConnectMode:      cmd.ConnectMode,
		Auth:             cmd.Auth,
		NoAdScript:       cmd.SkipAdScript,
		SkipAdScript:     cmd.SkipAdScript,
		SkipAdBlock:      cmd.SkipAdBlock,
		AdScriptURL:      cmd.AdScriptURL,
		WhitelistURL:     cmd.WhitelistURL,
		AdultSitesURL:    cmd.AdultSitesURL,
		BlocklistURL:     cmd.BlocklistURL,
		AdScriptInterval: cmd.AdScriptInterval,
		Logger:           logMgr,
	})
	if err != nil {
		echproxy.RecordFatalError("NewServer", err)
		if logMgr != nil {
			logMgr.Sync()
			_ = logMgr.Close()
		}
		os.Exit(1)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 在 .*.443.exe 下（cmd.LocalProxy == true），只有 443 方案开启，系统代理、更新器、托盘等一律不运行
	if !cmd.LocalProxy {
		sysProxyMgr = NewSysProxyManager(actualListenAddr, nil)
		sysProxyMgr.SetAllMode(cmd.AllMode)
		if cmd.SysProxy != SysProxyOff {
			if err := sysProxyMgr.SetMode(cmd.SysProxy); err != nil {
				log.Printf("WARNING: Failed to set system proxy (%s): %v", cmd.SysProxy, err)
			}
		}
		defer sysProxyMgr.CleanupOnExit()

		updater = NewUpdater(UpdaterOptions{})
		if !cmd.NoAutoUpdate && !cmd.PortalMode {
			updater.StartAutoCheck(ctx)
		}
		defer func() {
			if _, uerr := updater.ApplyStagedUpdateOnExit(); uerr != nil {
				log.Printf("WARNING: Failed to apply staged update on exit: %v", uerr)
			}
		}()
	}

	srv.PrintBanner(cmd.BootstrapIP)
	if sysProxyMgr != nil {
		fmt.Printf("  System Proxy: %s\n", sysProxyMgr.StatusText())
	}
	fmt.Printf("=================\n")

	var stopTray = func() {}
	if cmd.EnableTray && !cmd.LocalProxy {
		trayCtrl := NewTrayController(actualListenAddr, portalURL, caPath, sysProxyMgr, nil, func() {
			stop()
		})
		trayCtrl.AdScript = srv.AdScript
		trayCtrl.IPMode = srv.GetIPMode()
		trayCtrl.SetIPModeFn = func(m string) { srv.SetIPMode(m) }
		trayCtrl.NotifyFn = showNotificationOnPlatform
		if updater != nil {
			trayCtrl.Updater = updater
			trayCtrl.CheckUpdateFn = updater.CheckAndDownloadOnce
			updater.onStateChanged = func() {
				if trayCtrl.OnStateChanged != nil {
					trayCtrl.OnStateChanged()
				}
			}
		}
		if logMgr != nil {
			trayCtrl.LogDir = logMgr.LogDir()
		}
		stopTray = startPlatformTray(trayCtrl)
		if cmd.HideConsole {
			trayCtrl.SetConsoleVisible(false)
		}
	}
	defer stopTray()

	if cmd.PortalMode && !cmd.NoBrowser && !cmd.LocalProxy {
		echproxy.SafeGo("OpenBrowser", func() { openBrowser(portalURL) })
	}

	echproxy.SafeGo("ShutdownWatcher", func() {
		<-ctx.Done()
		if sysProxyMgr != nil {
			sysProxyMgr.CleanupOnExit()
		}
		stopTray()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		if updater != nil {
			_, _ = updater.ApplyStagedUpdateOnExit()
		}
		if logMgr != nil {
			logMgr.Sync()
		}
	})

	if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
		echproxy.RecordFatalError("Serve", err)
		if sysProxyMgr != nil {
			sysProxyMgr.CleanupOnExit()
		}
		if updater != nil {
			_, _ = updater.ApplyStagedUpdateOnExit()
		}
		if logMgr != nil {
			logMgr.Sync()
			_ = logMgr.Close()
		}
		os.Exit(1)
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
		echproxy.SafeGo("WaitBrowser", func() { _ = cmd.Wait() })
	}
}