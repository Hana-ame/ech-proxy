package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Hana-ame/ech-proxy/apifwd"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8443", "listen address")
	httpMode := flag.Bool("http", false, "run in HTTP mode (no TLS, local proxy)")
	verbose := flag.Bool("v", false, "verbose per-request logging")
	flag.Parse()

	// 每请求日志开关: 远程部署默认静默, 排查问题时 -v 打开。
	echproxy.Debug = *verbose

	localIP := os.Getenv("LOCALIP")
	if localIP != "" {
		log.Printf("使用自定义 DoH 接入 IP: %s", localIP)
		cloudflare_ech.SetDoHConfig("moonchan.xyz", localIP)
	}

	ipMode := os.Getenv("IP_MODE")
	if ipMode != "" {
		cloudflare_ech.SetIPMode(ipMode)
	}
	v4ok, v6ok := cloudflare_ech.CheckDualStack(context.Background())
	if v4ok || v6ok {
		suffix := ""
		if ipMode != "" {
			suffix = " (强制 " + ipMode + ")"
		}
		log.Printf("IP 栈检测: IPv4=%v IPv6=%v%s", v4ok, v6ok, suffix)
	} else {
		log.Printf("IP 栈检测失败（DNS 不可达）")
	}

	log.Printf("正在初始化 ECH 客户端...")
	if err := cloudflare_ech.InitDefault(); err != nil {
		log.Fatalf("ECH 客户端初始化失败: %v", err)
	}
	log.Printf("ECH 客户端就绪")

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(apifwd.CORSMiddleware())

	// 配置单一来源: 无论 TLS 还是 --http 模式, 都从 GitHub 拉取同一份
	// upstream.json (避免 embeddedConfig 与仓库配置双份漂移)。
	proxyBase := "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/%s?proxy_host=raw.githubusercontent.com"
	upstreamConfigURL := fmt.Sprintf(proxyBase, "certs/l.moonchan.xyz/upstream.json")

	log.Printf("正在加载上游配置: %s", upstreamConfigURL)
	cfg, err := echproxy.LoadConfig(upstreamConfigURL)
	if err != nil {
		log.Fatalf("加载上游配置失败: %v", err)
	}
	upstreamCfg := cfg.Upstreams
	log.Printf("上游配置加载成功: %d 条规则", len(upstreamCfg))

	var tlsCert *tls.Certificate

	if !*httpMode {
		// TLS 模式额外拉取证书: 证书 URL 与上游路由都写死在 repo 的
		// upstream.json 配置里, 证书续期后只需更新该配置指向的 URL。
		log.Printf("正在拉取证书: %s", cfg.CertPath)
		certPEM, err := echproxy.FetchBytes(cfg.CertPath)
		if err != nil {
			log.Fatalf("拉取证书失败: %v", err)
		}
		log.Printf("正在拉取密钥: %s", cfg.KeyPath)
		keyPEM, err := echproxy.FetchBytes(cfg.KeyPath)
		if err != nil {
			log.Fatalf("拉取密钥失败: %v", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("解析证书密钥失败: %v", err)
		}
		tlsCert = &cert
	}

	// 分流路由（桌面版与 Android 版共用 echproxy.SetupRouter）
	echproxy.SetupRouter(r, cfg)

	// 入口域名统一拼上监听端口显示: 与浏览器实际访问地址完全一致
	// (列表页链接同样按请求 Host 拼端口, 两处口径对齐)。
	listenPort := ""
	if _, p, err := net.SplitHostPort(*addr); err == nil {
		listenPort = p
	}

	fmt.Printf("=== ECH Proxy ===\n")
	fmt.Printf("  模式: %s\n", map[bool]string{true: "HTTP (本地代理)", false: "TLS (远程)"}[*httpMode])
	fmt.Printf("  监听: %s\n", *addr)
	if localIP != "" {
		fmt.Printf("  DoH IP: %s\n", localIP)
	}
	var domains []string
	for host := range upstreamCfg {
		domains = append(domains, host)
	}
	sort.Strings(domains)
	for _, d := range domains {
		uc := upstreamCfg[d]
		entry := d
		if listenPort != "" {
			entry += ":" + listenPort
		}
		fmt.Printf("  域名: %s -> %s (%s)", entry, uc.Host, echproxy.ModeName(uc.Mode))
		if uc.Referer != "" {
			fmt.Printf(" (referer: %s)", uc.Referer)
		}
		// 通配入口一并显示: iwara-* → *.iwara.tv, 让 banner 反映真实覆盖范围。
		if w := uc.Wildcard; w != nil {
			we := w.Prefix + "*" + w.EntrySuffix
			if listenPort != "" {
				we += ":" + listenPort
			}
			fmt.Printf(" [+通配 %s -> *%s]", we, w.UpstreamSuffix)
		}
		fmt.Println()
	}
	fmt.Printf("=================\n")

	// 优雅关闭: Ctrl+C / SIGTERM 时先停接新连接, 在途请求最多等 5s。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second, // 防慢客户端占住连接头不读
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		log.Printf("收到退出信号, 正在优雅关闭 (最多等 5s)...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	// 监听成功即自动打开浏览器访问列表入口 (PC 使用场景):
	// TLS 模式 https://l.moonchan.xyz:8443, --http 本地模式 http://。
	// headless 服务器没有浏览器时 openBrowser 仅记日志, 不影响服务。
	if listenPort != "" {
		scheme := "https"
		if *httpMode {
			scheme = "http"
		}
		go openBrowser(scheme + "://l.moonchan.xyz:" + listenPort)
	}

	if *httpMode {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("启动失败: %v", err)
		}
		return
	}

	srv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
		log.Fatalf("启动失败: %v", err)
	}
}

// openBrowser 调系统默认浏览器打开 url。
// Windows 走 rundll32 (ShellExecute), 避开 cmd start 的引号转义;
// macOS 用 open, 其余平台用 xdg-open。失败只记日志, 不影响代理服务。
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
	if err := cmd.Start(); err != nil {
		log.Printf("打开浏览器失败 (%s): %v", url, err)
		return
	}
	log.Printf("正在打开浏览器: %s", url)
	// Wait 回收子进程避免僵尸, 挂 goroutine 不阻塞主流程。
	go func() { _ = cmd.Wait() }()
}
