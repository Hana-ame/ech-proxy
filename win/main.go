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
	configURL := flag.String("config", "", "upstream config URL (empty for default remote)")
	ipMode := flag.String("ip-mode", os.Getenv("IP_MODE"),
		"force upstream egress IP family: v4 or v6; empty lets the OS decide")
	localIP := flag.String("local-ip", os.Getenv("LOCALIP"),
		"DoH bootstrap IP; empty bootstraps through the hostname")
	checkConfig := flag.String("check-config", "",
		"validate the config at this URL or path, print the report and exit (0 if no errors)")
	allowConnect := flag.Bool("allow-connect", false,
		"enable the HTTP CONNECT tunnel handler (off by default: tunnels are not restricted to configured upstreams)")
	flag.Parse()

	if *checkConfig != "" {
		os.Exit(runCheckConfig(*checkConfig))
	}

	// Per-request logging switch: silent by default in remote deployment, enable with -v for troubleshooting
	echproxy.Debug = *verbose

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:         *addr,
		HTTPMode:     *httpMode,
		ConfigURL:    *configURL,
		BootstrapIP:  *localIP,
		IPMode:       *ipMode,
		AllowConnect: *allowConnect,
	})
	if err != nil {
		log.Fatalf("Proxy server initialization failed: %v", err)
	}

	srv.PrintBanner(*localIP)

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

// runCheckConfig validates a configuration without binding a port or touching
// the network beyond fetching it. Exit code is 0 when no errors were found, 1
// when there were errors, 2 when the config could not be loaded at all — so
// this is usable directly from CI or a pre-deploy hook.
//
// It goes through ParseConfig rather than LoadConfig on purpose: LoadConfig
// logs the report itself, which would print everything twice here.
func runCheckConfig(target string) int {
	fmt.Printf("Checking config: %s\n", target)
	buf, err := echproxy.FetchBytes(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: could not fetch config: %v\n", err)
		return 2
	}
	cfg, err := echproxy.ParseConfig(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: could not parse config: %v\n", err)
		return 2
	}
	issues := echproxy.Validate(cfg)
	fmt.Printf("Entries: %d\n", len(cfg.Upstreams))
	if len(issues) == 0 {
		fmt.Println("OK: no issues found")
		return 0
	}
	fmt.Print(echproxy.FormatIssues(issues))
	if echproxy.HasErrors(issues) {
		return 1
	}
	return 0
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
