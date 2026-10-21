package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
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

// isPort443 检查监听地址是否使用了 443 端口。
func isPort443(addr string) bool {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.HasSuffix(strings.TrimSpace(addr), ":443")
	}
	return port == "443"
}

// FlagOverviewText 返回完整的命令行 Flag 一览说明。
func FlagOverviewText() string {
	return `=== ech-proxy 命令行 Flag 一览 ===
  出口与路由模式 Flag:
    -4                  强制 v4 出口 (IPv4 only，默认开启)
    -6                  强制 v6 出口 (IPv6 only)
    -dual               双端出口 (IPv4 + IPv6 双栈自动优选)
    -all                开启全局模式（无视 pac.txt 白名单，所有网站均通过 ech-proxy 代理；仅命令行 -all 可开启）

  广告处理控制 Flag（在系统托盘中隐藏，仅通过命令行控制）:
    --skip-ad-script    跳过插入广告商 JS (<script>...</script>) 的步骤
    --skip-ad-block     禁止拦截/移除源站原始广告

  CA 证书与自动更新子命令 / Flag:
    ca install          一键安装本地 CA 根证书到受信任根证书库 (-ca-install)
    ca uninstall        一键卸载本地 CA 根证书 (-ca-uninstall)
    update              立即检查并下载最新 Release 更新 (-update / --check-update)

  网络、DoH 与远程规则配置:
    首选 DoH:           https://4545810.xyz/doh
    次选 DoH (自动兜底): https://1.1.1.1/dns-query
    远程广告代码:       https://4545810.xyz/ads.js  (拉取失败自动使用内置 fallback)
    远程 PAC 白名单:    https://4545810.xyz/pac.txt (一行一个 domain，拉取失败 fallback 为空)
    自动更新源:         https://github.com/Hana-ame/ech-proxy/releases (checksums.txt 校验，退出重开替换)

  其他常用运行参数:
    -addr <host:port>   监听地址（默认 127.0.0.1:8443；非 .443.exe 文件名严禁监听 443 端口）
    -hide-console       启动后自动隐藏控制台窗口到系统托盘（双击托盘图标可恢复）
    -no-tray            禁用系统托盘图标
    -local-ip <ip>      指定首选 DoH 引导 IP（可选）
    -v                  输出逐请求详细调试日志
`
}

// CLICommand 表示解析后的命令行操作与运行参数。
type CLICommand struct {
	Action           string // "run", "help", "update", "check", "hosts-print", "hosts-apply", "hosts-clean", "ca-status", "ca-export", "ca-install", "ca-uninstall", "pac", "sysproxy-pac", "sysproxy-global", "sysproxy-clear", "sysproxy-status", "logs-path", "logs-tail", "logs-crash", "logs-clean", "version"
	Mode             string // "smart" (默认 PAC HTTPS Proxy), "local" (仅 .443.exe), "portal" (独立门户模式), "http"
	AllMode          bool   // 全局模式：无视白名单所有网站都走 ech-proxy（对应 -all，仅命令行开启）
	Addr             string
	FallbackAddr     string
	LocalProxy       bool
	PortalMode       bool
	HTTPMode         bool
	DataDir          string
	ConfigURL        string
	IPMode           string // 出口 IP 协议族：默认 "v4" (-4 强制v4出口)、"v6" (-6 强制v6出口)、"dual" (-dual 双端出口)
	BootstrapIP      string
	NoBrowser        bool
	Verbose          bool
	AllowConnect     bool
	ConnectMode      string
	HostsFile        string
	CAExportPath     string
	SysProxy         SysProxyMode         // 启动时自动设置的系统代理模式："pac"（smart 模式默认）、"global"、"off"
	EnableTray       bool                 // 是否启用系统托盘（默认开启）
	HideConsole      bool                 // 启动后是否自动隐藏控制台窗口到系统托盘
	NoAdScript       bool                 // 是否跳过插入广告 JS（兼容 -no-ad-script 与 --skip-ad-script）
	SkipAdScript     bool                 // --skip-ad-script：用来跳过插入广告 js 的步骤
	SkipAdBlock      bool                 // --skip-ad-block：禁止 block 原始广告
	AdScriptURL      string               // 远程广告商代码 URL（默认 https://4545810.xyz/ads.js）
	WhitelistURL     string               // 远程 PAC 白名单 URL（默认 https://4545810.xyz/pac.txt，一行一个 domain）
	AdScriptInterval time.Duration        // 远程脚本与白名单自动拉取更新周期（-ad-script-interval，默认 30m）
	NoAutoUpdate     bool                 // 是否禁用后台自动检查更新（-no-auto-update）
	LogDir           string               // 本地持久化日志目录（-log-dir，默认 <DataDir>/logs）
	LogFile          string               // 指定本地日志文件路径（-log-file）
	NoLogFile        bool                 // 禁用本地日志文件落盘（-no-log-file）
	Auth             *echproxy.AuthConfig // 访问认证配置指针（避免复制内部 sync.Mutex）
}

func envBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// parseCLIArgs 解析子命令与命令行标志。
// 严格执行：在可执行文件名不包含 ".443.exe" 时，绝不监听 443 端口且 443 代码绝对不运行！
func parseCLIArgs(progName string, args []string, getenv func(string) string) (CLICommand, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	is443 := filenameIs443(progName)
	action := "run"
	subMode := ""
	subAll := false

	// 识别前置子命令
	restArgs := args
	if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
		switch strings.ToLower(restArgs[0]) {
		case "run", "serve", "start", "proxy":
			action = "run"
			restArgs = restArgs[1:]
		case "help", "flags":
			action = "help"
			restArgs = restArgs[1:]
		case "update", "upgrade", "self-update":
			action = "update"
			restArgs = restArgs[1:]
		case "all":
			action = "run"
			subAll = true
			restArgs = restArgs[1:]
		case "local", "443":
			if !is443 {
				return CLICommand{}, fmt.Errorf("文件名 %q 不包含 .443.exe：禁止开启 443 模式及监听 443 端口", filepath.Base(progName))
			}
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
				case "uninstall", "remove", "delete", "clean", "untrust":
					action = "ca-uninstall"
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
		case "logs", "log":
			action = "logs-path"
			restArgs = restArgs[1:]
			if len(restArgs) > 0 && !strings.HasPrefix(restArgs[0], "-") {
				switch strings.ToLower(restArgs[0]) {
				case "path", "status", "dir":
					action = "logs-path"
					restArgs = restArgs[1:]
				case "tail", "show", "cat", "print":
					action = "logs-tail"
					restArgs = restArgs[1:]
				case "crash":
					action = "logs-crash"
					restArgs = restArgs[1:]
				case "clean", "clear":
					action = "logs-clean"
					restArgs = restArgs[1:]
				}
			}
		}
	}

	defaultLocal := is443
	defaultAddr := "127.0.0.1:8443"
	if defaultLocal {
		defaultAddr = "127.0.0.1:443"
	}

	defaultInterval := echproxy.DefaultAdScriptInterval
	if envInt := strings.TrimSpace(getenv("ECH_PROXY_AD_SCRIPT_INTERVAL")); envInt != "" {
		if d, err := time.ParseDuration(envInt); err == nil && d > 0 {
			defaultInterval = d
		}
	}

	// 默认 ipmode = ipv4 ("v4")
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

	// 核心快捷 Flag 一览：-4, -6, -dual, -all, --skip-ad-script, --skip-ad-block
	flag4 := fs.Bool("4", false, "强制 v4 出口 (IPv4 only，默认)")
	flag6 := fs.Bool("6", false, "强制 v6 出口 (IPv6 only)")
	flagDual := fs.Bool("dual", false, "双端出口 (IPv4 + IPv6 双栈)")
	allFlag := fs.Bool("all", subAll || envBool(getenv("ECH_PROXY_ALL")), "开启全局模式：无视白名单，所有网站都通过 ech-proxy 代理（仅命令行 -all 开启）")
	skipAdScript := fs.Bool("skip-ad-script", envBool(getenv("ECH_PROXY_SKIP_AD_SCRIPT")) || envBool(getenv("ECH_PROXY_NO_AD_SCRIPT")), "跳过插入广告商 JS 的步骤 (--skip-ad-script)")
	skipAdBlock := fs.Bool("skip-ad-block", envBool(getenv("ECH_PROXY_SKIP_AD_BLOCK")), "禁止拦截/移除源站原始广告 (--skip-ad-block)")

	modeFlag := fs.String("mode", subMode, "运行模式：smart（默认 PAC HTTPS Proxy）、all（所有网站均走代理）、portal（独立门户模式）、http（明文）")
	addr := fs.String("addr", defaultAddr, "监听地址（默认 127.0.0.1:8443；仅 .443.exe 允许 127.0.0.1:443）")
	localProxy := fs.Bool("local", defaultLocal, "启用 443 本地透明反向代理模式（仅限 .443.exe 文件名）")
	dataDir := fs.String("data-dir", getenv("ECH_PROXY_DATA_DIR"), "本地 CA 与叶子证书存储目录（默认：程序所在目录）")
	configURL := fs.String("config", getenv("ECH_PROXY_CONFIG"), "upstream.json 配置文件路径或 URL（留空使用默认远程地址）")

	// 兼容 -ipmode 与 -ip-mode
	ipModeFlag := fs.String("ipmode", defaultIPModeEnv, "出口 IP 协议族：[default]=ipv4 (-4)，dual = 双端出口 (-dual)，6 = 强制v6出口 (-6)")
	ipModeDash := fs.String("ip-mode", "", "出口 IP 协议族（-ipmode 的兼容别名：ipv4 / 4 / v4 / dual / ipv6 / 6 / v6）")

	localIP := fs.String("local-ip", getenv("LOCALIP"), "DoH 引导 IP（可选）")
	httpMode := fs.Bool("http", false, "以纯 HTTP 明文模式运行")
	noBrowser := fs.Bool("no-browser", false, "不自动打开浏览器（PAC HTTPS Proxy 主线默认不打开浏览器）")
	verbose := fs.Bool("v", false, "输出逐请求详细调试日志")

	// 系统托盘、控制台显隐与自动设置 Windows PAC 参数
	sysProxyFlag := fs.String("sys-proxy", getenv("ECH_PROXY_SYS_PROXY"), "启动时自动配置系统代理模式：pac（默认自动配置 PAC）、global、off")
	noTray := fs.Bool("no-tray", false, "禁用系统托盘图标")
	hideConsole := fs.Bool("hide-console", false, "启动后自动隐藏控制台窗口到系统托盘（双击托盘图标可随时恢复显示）")

	// 远程 pac.txt 白名单与 ads.js 参数（兼容旧别名）
	whitelistURL := fs.String("whitelist-url", defaultWhitelistEnv, "远程 PAC 白名单（https://4545810.xyz/pac.txt，一行一个 domain）URL 或路径")
	adultDomainsAlias := fs.String("adult-domains-url", "", "-whitelist-url 的兼容别名")
	noAdScriptAlias := fs.Bool("no-ad-script", false, "--skip-ad-script 的兼容别名")
	disableScriptAlias := fs.Bool("disable-ad-script", false, "--skip-ad-script 的兼容别名")
	adScriptURL := fs.String("ad-script-url", getenv("ECH_PROXY_AD_SCRIPT_URL"), "远程广告商代码 URL（默认 https://4545810.xyz/ads.js）")
	adScriptInterval := fs.Duration("ad-script-interval", defaultInterval, "远程 ads.js 与 pac.txt 后台自动更新拉取周期（默认 30m）")

	// 自动更新控制参数
	updateNow := fs.Bool("update", false, "立即检查并下载最新 Release 更新后退出")
	checkUpdateAlias := fs.Bool("check-update", false, "立即检查并下载最新 Release 更新后退出")
	noAutoUpdate := fs.Bool("no-auto-update", envBool(getenv("ECH_PROXY_NO_AUTO_UPDATE")), "禁用后台自动检查 Release 更新")

	// 本地持久化日志与崩溃日志参数
	logDir := fs.String("log-dir", getenv("ECH_PROXY_LOG_DIR"), "本地持久化滚动日志与崩溃快照目录（默认 <data-dir>/logs）")
	logFile := fs.String("log-file", getenv("ECH_PROXY_LOG_FILE"), "指定本地日志文件路径（默认 <log-dir>/ech-proxy.log）")
	noLogFile := fs.Bool("no-log-file", envBool(getenv("ECH_PROXY_NO_LOG_FILE")), "禁用本地日志文件保存（仅输出至控制台）")

	// 工具与安全标志
	checkConfig := fs.Bool("check-config", false, "校验 upstream.json 配置文件并退出（0=正常，1=配置错误，2=读取失败）")
	hostsPrint := fs.Bool("hosts-print", false, "打印本地 443 模式所需的完整 hosts 规则块并退出")
	hostsApply := fs.Bool("hosts-apply", false, "将 ech-proxy 受管域名规则自动写入系统 hosts 文件并退出（需管理员/root 权限）")
	hostsClean := fs.Bool("hosts-clean", false, "从系统 hosts 文件中清理 ech-proxy 受管规则块并退出")
	hostsFile := fs.String("hosts-file", "", "自定义 hosts 文件路径（默认使用系统 hosts 路径）")
	caExport := fs.String("ca-export", "", "导出本地自签 CA 根证书到指定文件路径并退出")
	caInstall := fs.Bool("ca-install", false, "将本地自签 CA 根证书一键安装到当前用户受信任根证书库并退出")
	caUninstall := fs.Bool("ca-uninstall", false, "从当前用户及系统受信任根证书库卸载本地自签 CA 根证书并退出")
	allowConnect := fs.Bool("allow-connect", true, "启用 HTTP CONNECT 正向代理支持（默认在回环地址开启）")
	connectMode := fs.String("connect-mode", echproxy.ConnectModeAuto, "CONNECT 代理模式：auto/mitm（默认，支持 ECH/SNI 转发）或 tunnel（纯 TCP 透传）")
	token := fs.String("token", getenv("ECH_PROXY_TOKEN"), "代理访问鉴权 Bearer Token（可选）")
	user := fs.String("user", getenv("ECH_PROXY_USER"), "代理访问 BasicAuth 用户名（可选）")
	pass := fs.String("pass", getenv("ECH_PROXY_PASS"), "代理访问 BasicAuth 密码（可选）")

	if err := fs.Parse(restArgs); err != nil {
		if err == flag.ErrHelp {
			return CLICommand{Action: "help"}, nil
		}
		return CLICommand{}, err
	}

	// 根据标志覆盖 Action
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
	portalMode := false
	resolvedMode := strings.ToLower(strings.TrimSpace(*modeFlag))
	switch resolvedMode {
	case "all", "global":
		allMode = true
		resolvedMode = "smart"
	case "local", "443":
		if !is443 {
			return CLICommand{}, fmt.Errorf("文件名 %q 不包含 .443.exe：禁止开启 443 模式及监听 443 端口", filepath.Base(progName))
		}
		*localProxy = true
		if *addr == "127.0.0.1:8443" {
			*addr = "127.0.0.1:443"
		}
	case "http":
		*httpMode = true
	case "portal", "8443":
		*localProxy = false
		portalMode = true
	case "", "smart", "auto", "whitelist":
		if *localProxy {
			resolvedMode = "local"
		} else if *httpMode {
			resolvedMode = "http"
		} else {
			resolvedMode = "smart"
		}
	default:
		return CLICommand{}, fmt.Errorf("unknown -mode %q (valid: smart, all, local, portal, http)", *modeFlag)
	}

	// 严格守护：在文件名不包含 .443.exe 时，绝不允许开启 LocalProxy 或监听 443 端口！
	if !is443 {
		if *localProxy || flagWasPassed(fs, "local") {
			return CLICommand{}, fmt.Errorf("文件名 %q 不包含 .443.exe：禁止运行 443 模式代码", filepath.Base(progName))
		}
		if isPort443(*addr) {
			return CLICommand{}, fmt.Errorf("文件名 %q 不包含 .443.exe：禁止监听 443 端口 (%s)", filepath.Base(progName), *addr)
		}
		*localProxy = false
	}

	if *localProxy && *httpMode {
		return CLICommand{}, fmt.Errorf("-local 与 -http 互斥：443 本地反代模式必须启用 TLS")
	}
	if *localProxy && *addr == "127.0.0.1:8443" && !flagWasPassed(fs, "addr") {
		*addr = "127.0.0.1:443"
	}

	// 解析并校验出口协议族（支持 -4 / -6 / -dual 以及 -ipmode / -ip-mode）
	shorthandCount := 0
	if *flag4 {
		shorthandCount++
	}
	if *flag6 {
		shorthandCount++
	}
	if *flagDual {
		shorthandCount++
	}
	if shorthandCount > 1 {
		return CLICommand{}, fmt.Errorf("-4, -6, -dual 互斥，请仅指定其中一个出口模式")
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

	resolvedWhitelistURL := strings.TrimSpace(*whitelistURL)
	if resolvedWhitelistURL == "" && strings.TrimSpace(*adultDomainsAlias) != "" {
		resolvedWhitelistURL = strings.TrimSpace(*adultDomainsAlias)
	}

	fallbackAddr := ""
	if is443 && *localProxy && strings.HasSuffix(*addr, ":443") {
		fallbackAddr = "127.0.0.1:8443"
	}

	resolvedSkipAdScript := *skipAdScript || *noAdScriptAlias || *disableScriptAlias

	return CLICommand{
		Action:           action,
		Mode:             resolvedMode,
		AllMode:          allMode,
		Addr:             *addr,
		FallbackAddr:     fallbackAddr,
		LocalProxy:       *localProxy,
		PortalMode:       portalMode,
		HTTPMode:         *httpMode,
		DataDir:          *dataDir,
		ConfigURL:        *configURL,
		IPMode:           normalizedIPMode,
		BootstrapIP:      *localIP,
		NoBrowser:        *noBrowser,
		Verbose:          *verbose,
		AllowConnect:     *allowConnect,
		ConnectMode:      *connectMode,
		HostsFile:        *hostsFile,
		CAExportPath:     *caExport,
		SysProxy:         sysProxyMode,
		EnableTray:       !*noTray,
		HideConsole:      *hideConsole,
		NoAdScript:       resolvedSkipAdScript,
		SkipAdScript:     resolvedSkipAdScript,
		SkipAdBlock:      *skipAdBlock,
		AdScriptURL:      strings.TrimSpace(*adScriptURL),
		WhitelistURL:     resolvedWhitelistURL,
		AdScriptInterval: *adScriptInterval,
		NoAutoUpdate:     *noAutoUpdate,
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

// runToolAction 执行非长驻服务的 CLI 工具型子命令（help / update / check / hosts / ca / pac / sysproxy / logs / version），返回退出码。
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

	case "ca-status", "ca-export", "ca-install", "ca-uninstall":
		dataDir := cmd.DataDir
		if dataDir == "" {
			dataDir, _ = echproxy.DefaultDataDir()
		}
		if cmd.Action == "ca-uninstall" {
			caPath := filepath.Join(dataDir, "ca", "ca.pem")
			if err := uninstallCAOnPlatform(caPath); err != nil {
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
		var wl []string
		wlURL := cmd.WhitelistURL
		if wlURL == "" {
			wlURL = echproxy.DefaultWhitelistURL
		}
		if raw, err := echproxy.FetchBytes(wlURL); err == nil {
			wl, _ = echproxy.ParseDomainList(raw)
		}
		fmt.Fprint(out, echproxy.GeneratePAC(cfg, cmd.Addr, cmd.AllMode, wl))
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
		crashFile := filepath.Join(dir, "crash-latest.log")
		fmt.Fprintf(out, "Log Dir:    %s\nLog File:   %s\nCrash File: %s\n", dir, logFile, crashFile)
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
		crashFile := filepath.Join(dir, "crash-latest.log")
		data, err := os.ReadFile(crashFile)
		if err != nil {
			fmt.Fprintf(out, "No crash log found at %s\n", crashFile)
			return 0
		}
		fmt.Fprint(out, string(data))
		return 0

	case "logs-clean":
		dir := resolveLogDir(cmd)
		if err := echproxy.CleanLogs(dir); err != nil {
			fmt.Fprintf(out, "ERROR: failed to clean logs in %s: %v\n", dir, err)
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
	// 最顶层 Panic 闪退守卫：任何未捕获异常均落盘写入 logs/ech-proxy.log 与 logs/crash-latest.log
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

	// 启动时若发现上次退出前已下载暂存的 <exe>.new，优先完成二进制替换并清理残留 .old
	_, _ = ApplyPendingUpdateOnStartup("")

	progName := "ech-proxy"
	if len(os.Args) > 0 {
		progName = os.Args[0]
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

	// 0. 初始化本地持久化滚动日志与全局 Panic 崩溃快照捕获
	logDir := resolveLogDir(cmd)
	var logErr error
	logMgr, logErr = echproxy.InitLogger(echproxy.LoggerOptions{
		LogDir:      logDir,
		LogFile:     cmd.LogFile,
		DisableFile: cmd.NoLogFile,
		ConsoleOut:  os.Stderr,
	})
	if logErr != nil {
		log.Printf("WARNING: Failed to initialize local file logger (%v), continuing with console output only", logErr)
	} else {
		defer logMgr.Close()
		logMgr.WriteStartupHeader(echproxy.BuildVersionInfo(), os.Args, map[string]string{
			"Mode":       cmd.Mode,
			"AllMode":    fmt.Sprintf("%v", cmd.AllMode),
			"IPMode":     echproxy.FormatIPMode(cmd.IPMode),
			"ListenAddr": cmd.Addr,
			"SysProxy":   string(cmd.SysProxy),
			"AdSettings": fmt.Sprintf("skip_ad_script=%v skip_ad_block=%v ads_url=%s pac_url=%s", cmd.SkipAdScript, cmd.SkipAdBlock, cmd.AdScriptURL, cmd.WhitelistURL),
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

	// 1. 初始化系统代理管理器（启动时自动为 Windows 配置 PAC，退出时自动清理）
	sysProxyMgr = NewSysProxyManager(actualListenAddr, nil)
	sysProxyMgr.SetAllMode(cmd.AllMode)
	if cmd.SysProxy != SysProxyOff {
		if err := sysProxyMgr.SetMode(cmd.SysProxy); err != nil {
			log.Printf("WARNING: Failed to set system proxy (%s): %v", cmd.SysProxy, err)
		}
	}
	defer sysProxyMgr.CleanupOnExit()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 2. 初始化自动检查与下载更新器（退出时自动将已下载验证的 <exe>.new 替换为 <exe>）
	updater = NewUpdater(UpdaterOptions{})
	if !cmd.NoAutoUpdate {
		updater.StartAutoCheck(ctx)
	}
	defer func() {
		updater.Stop()
		_, _ = updater.ApplyStagedUpdateOnExit()
	}()

	srv.PrintBanner(cmd.BootstrapIP)
	fmt.Printf("  System Proxy: %s\n", sysProxyMgr.StatusText())
	fmt.Printf("  Auto-Updater: %s (target asset: %s)\n", DefaultReleasesPageURL, updater.AssetName())
	if cmd.EnableTray {
		fmt.Printf("  System Tray: Enabled (double-click icon to show/hide console, right-click for PAC / 强制v4-v6-双端出口 / 安装与卸载CA / 检查更新 / 反馈 / Logs)\n")
	}
	fmt.Printf("=================\n")

	// 3. 启动系统托盘与控制台显隐控制器
	var stopTray = func() {}
	if cmd.EnableTray {
		trayCtrl := NewTrayController(actualListenAddr, portalURL, caPath, sysProxyMgr, nil, func() {
			stop()
		})
		trayCtrl.IPMode = srv.GetIPMode()
		trayCtrl.SetIPModeFn = srv.SetIPMode
		trayCtrl.AdScript = srv.AdScript
		trayCtrl.Updater = updater
		updater.mu.Lock()
		updater.onStateChanged = func() {
			if trayCtrl.OnStateChanged != nil {
				trayCtrl.OnStateChanged()
			}
		}
		updater.mu.Unlock()
		if logMgr != nil {
			trayCtrl.LogDir = logMgr.LogDir()
		}
		stopTray = startPlatformTray(trayCtrl)
		if cmd.HideConsole {
			trayCtrl.SetConsoleVisible(false)
		}
	}
	defer stopTray()

	// 注意：PAC HTTPS Proxy 主线启动后绝不自动打开 l.moonchan.xyz:8443；
	// 仅当用户显式以独立 portal 子命令启动 (cmd.PortalMode == true) 且未指定 -no-browser 时才打开门户。
	if cmd.PortalMode && !cmd.NoBrowser {
		echproxy.SafeGo("OpenBrowserPortal", func() {
			openBrowser(portalURL)
		})
	}

	echproxy.SafeGo("ShutdownWatcher", func() {
		<-ctx.Done()
		log.Printf("Shutting down gracefully (cleaning up system proxy, applying staged updates, stopping tray & flushing logs)...")
		sysProxyMgr.CleanupOnExit()
		updater.Stop()
		_, _ = updater.ApplyStagedUpdateOnExit()
		stopTray()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		if logMgr != nil {
			logMgr.Sync()
		}
	})

	if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
		echproxy.RecordFatalError("Server-Serve", err)
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