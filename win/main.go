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
	"syscall"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	httpMode := flag.Bool("http", false, "run in HTTP mode (no TLS, local proxy)")
	verbose := flag.Bool("v", false, "verbose per-request logging")
	noBrowser := flag.Bool("no-browser", false, "do not auto-open browser on startup")
	flag.Parse()

	// Per-request logging switch: silent by default in remote deployment, enable with -v for troubleshooting
	echproxy.Debug = *verbose

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:        *addr,
		HTTPMode:    *httpMode,
		BootstrapIP: os.Getenv("LOCALIP"),
		IPMode:      os.Getenv("IP_MODE"),
	})
	if err != nil {
		log.Fatalf("Proxy server initialization failed: %v", err)
	}

	srv.PrintBanner(os.Getenv("LOCALIP"))

	// Automatically open browser to entry list once listening successfully (PC usage)
	if !*noBrowser {
		scheme := "https"
		if *httpMode {
			scheme = "http"
		}
		go openBrowser(fmt.Sprintf("%s://l.moonchan.xyz:%d", scheme, srv.Port))
	}

	// Graceful shutdown: on Ctrl+C / SIGTERM stop accepting new connections, wait up to 5s for in-flight requests
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Printf("Received termination signal, shutting down gracefully (up to 5s)...")
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
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to open browser (%s): %v", url, err)
		return
	}
	log.Printf("Opening browser: %s", url)
	go func() { _ = cmd.Wait() }()
}
