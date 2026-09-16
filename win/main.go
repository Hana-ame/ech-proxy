package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8443", "listen address")
	httpMode := flag.Bool("http", false, "run in HTTP mode (no TLS, local proxy)")
	verbose := flag.Bool("v", false, "verbose per-request logging")
	flag.Parse()

	// 每请求日志开关: 远程部署默认静默, 排查问题时 -v 打开
	echproxy.Debug = *verbose

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:        *addr,
		HTTPMode:    *httpMode,
		BootstrapIP: os.Getenv("LOCALIP"),
		IPMode:      os.Getenv("IP_MODE"),
	})
	if err != nil {
		log.Fatalf("代理服务器初始化失败: %v", err)
	}

	printBanner(srv.Config, *addr, *httpMode, srv.Port, os.Getenv("LOCALIP"))

	// 监听成功即自动打开浏览器访问列表入口 (PC 使用场景)
	scheme := "https"
	if *httpMode {
		scheme = "http"
	}
	go openBrowser(fmt.Sprintf("%s://l.moonchan.xyz:%d", scheme, srv.Port))

	// 优雅关闭: Ctrl+C / SIGTERM 时先停接新连接, 在途请求最多等 5s
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("收到退出信号, 正在优雅关闭 (最多等 5s)...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("启动失败: %v", err)
	}
}

func printBanner(cfg *echproxy.Config, addr string, httpMode bool, port uint16, localIP string) {
	listenPort := fmt.Sprintf("%d", port)
	fmt.Printf("=== ECH Proxy ===\n")
	fmt.Printf("  模式: %s\n", map[bool]string{true: "HTTP (本地代理)", false: "TLS (远程)"}[httpMode])
	fmt.Printf("  监听: %s\n", addr)
	if localIP != "" {
		fmt.Printf("  DoH IP: %s\n", localIP)
	}
	upstreamCfg := cfg.Upstreams
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
		if len(uc.Headers) > 0 {
			fmt.Printf(" (headers: %d)", len(uc.Headers))
		}
		if len(uc.ResponseHeaders) > 0 {
			fmt.Printf(" (resp_headers: %d)", len(uc.ResponseHeaders))
		}
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
	if err := cmd.Start(); err != nil {
		log.Printf("打开浏览器失败 (%s): %v", url, err)
		return
	}
	log.Printf("正在打开浏览器: %s", url)
	go func() { _ = cmd.Wait() }()
}
