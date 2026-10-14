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

func main() {
	is443 := exeNameIs443()
	defaultAddr := "127.0.0.1:8443"
	if is443 {
		defaultAddr = "127.0.0.1:443"
	}

	addr := flag.String("addr", defaultAddr, "监听地址（文件名以 .443.exe 结尾时默认为 127.0.0.1:443，否则为 127.0.0.1:8443）")
	localProxy := flag.Bool("local", is443, "启用 443 本地透明反向代理模式（自签名 CA + 按需签发原域名证书）")
	dataDir := flag.String("data-dir", os.Getenv("ECH_PROXY_DATA_DIR"), "本地 CA 与叶子证书存储目录（默认：程序所在目录）")
	configURL := flag.String("config", "", "upstream.json 配置文件路径或 URL（留空使用默认远程地址）")
	ipMode := flag.String("ip-mode", os.Getenv("IP_MODE"), "锁定上游出口协议族：v4 或 v6（留空由系统自动选择）")
	localIP := flag.String("local-ip", os.Getenv("LOCALIP"), "DoH 引导 IP（可选）")
	httpMode := flag.Bool("http", false, "以纯 HTTP 明文模式运行（与 -local 互斥）")
	noBrowser := flag.Bool("no-browser", false, "启动时不自动打开浏览器")
	verbose := flag.Bool("v", false, "输出逐请求详细调试日志")
	flag.Parse()

	if *localProxy && *httpMode {
		log.Fatal("-local 与 -http 互斥：443 本地反代模式必须启用 TLS")
	}

	echproxy.Debug = *verbose

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:        *addr,
		HTTPMode:    *httpMode,
		ConfigURL:   *configURL,
		BootstrapIP: *localIP,
		IPMode:      *ipMode,
		LocalProxy:  *localProxy,
		DataDir:     *dataDir,
	})
	if err != nil {
		log.Fatalf("Proxy server initialization failed: %v", err)
	}

	srv.PrintBanner(*localIP)

	// 8443 门户模式下自动打开浏览器展示导航页；443 本地模式静默运行
	if !*noBrowser && !*localProxy {
		scheme := "https"
		if *httpMode {
			scheme = "http"
		}
		go openBrowser(fmt.Sprintf("%s://l.moonchan.xyz:%d", scheme, srv.Port))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("Shutting down gracefully (up to 5s)...")
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
