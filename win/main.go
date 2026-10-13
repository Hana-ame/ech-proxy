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

// exeSuffix443 is the exact filename suffix that selects the 443 build.
const exeSuffix443 = ".443.exe"

// filenameIs443 reports whether a filename marks the build as the 443 listener.
//
// The rule is an exact suffix match on ".443.exe", NOT a substring test: the
// user must rename the binary so it ends with .443.exe (for example
// ech-proxy.443.exe) to get port 443. A name that merely mentions .443 in the
// middle (ech-proxy.443.beta.exe) is not the 443 build and keeps the default
// 8443 port, so a renamed intermediate build cannot silently bind a privileged
// port. The comparison is case-insensitive because Windows filenames are.
func filenameIs443(name string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(name)), exeSuffix443)
}

// exeNameIs443 applies filenameIs443 to the running executable.
//
// The 443 build is not just a port: it also enables local reverse proxy mode,
// because serving a real hostname (pixiv.net) on port 443 requires TLS
// termination with a locally trusted CA. See README "Local reverse proxy mode".
func exeNameIs443() bool {
	if len(os.Args) < 1 {
		return false
	}
	return filenameIs443(os.Args[0])
}

func main() {
	four443 := exeNameIs443()
	addr := flag.String("addr",
		func() string {
			if four443 {
				return "127.0.0.1:443"
			}
			return "127.0.0.1:8443"
		}(),
		"listen address (default from the executable filename: a \".443.exe\" suffix uses 127.0.0.1:443)")
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
	proxyToken := flag.String("proxy-token", os.Getenv("ECH_PROXY_TOKEN"),
		"bearer token required for CONNECT tunnels; empty means unauthenticated")
	proxyUser := flag.String("proxy-user", os.Getenv("ECH_PROXY_USER"),
		"HTTP basic auth username for CONNECT tunnels (ignored when -proxy-token is set)")
	proxyPass := flag.String("proxy-pass", os.Getenv("ECH_PROXY_PASS"),
		"HTTP basic auth password for CONNECT tunnels")
	allowLoopback := flag.Bool("allow-loopback-targets", false,
		"permit CONNECT tunnels to loopback and private addresses (off by default: blocks SSRF into the local network)")
	allowPrivate := flag.Bool("allow-private-targets", false,
		"permit CONNECT tunnels to RFC1918 private ranges")
	localProxy := flag.Bool("local", four443,
		"local reverse proxy mode: terminate TLS with a self-generated CA and forward each Host through sni/ech (auto-enabled by a \".443.exe\" filename suffix)")
	dataDir := flag.String("data-dir", os.Getenv("ECH_PROXY_DATA_DIR"),
		"directory for the local CA and issued certificates (default: the directory holding this executable, "+
			"falling back to the platform user config dir/ech-proxy if that directory is not writable)")
	flag.Parse()

	if *checkConfig != "" {
		os.Exit(runCheckConfig(*checkConfig))
	}

	// Per-request logging switch: silent by default in remote deployment, enable with -v for troubleshooting
	echproxy.Debug = *verbose

	// Tunnel security: authentication and destination validation.
	//
	// A CONNECT tunnel is an open forward proxy unless a credential is
	// required, so enabling -allow-connect without -proxy-token leaves every
	// process that can reach the listener able to reach anything the host can.
	// The warning is printed rather than enforced, because refusing to start
	// would break existing single-user desktop use.
	echproxy.ConfigureTunnelAuth(
		echproxy.NewProxyAuth(echproxy.AuthConfig{
			Token:    *proxyToken,
			Username: *proxyUser,
			Password: *proxyPass,
		}),
		echproxy.NewRateLimiter(10, 5*time.Minute),
	)
	destGuard := echproxy.NewDestinationGuard(echproxy.DestinationGuardConfig{
		AllowLoopback: *allowLoopback,
		AllowPrivate:  *allowPrivate,
	})

	if *allowConnect && *proxyToken == "" && *proxyUser == "" {
		log.Printf("WARNING: -allow-connect is on with no -proxy-token; the tunnel is an open forward proxy")
	}

	// Local reverse proxy mode mandates TLS: the whole point is presenting a
	// certificate the browser already trusts for the redirected hostname.
	if *localProxy && *httpMode {
		log.Fatal("-local and -http are mutually exclusive: local proxy mode terminates TLS")
	}

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:         *addr,
		HTTPMode:     *httpMode,
		ConfigURL:    *configURL,
		BootstrapIP:  *localIP,
		IPMode:       *ipMode,
		AllowConnect: *allowConnect,
		DestGuard:    destGuard,
		LocalProxy:   *localProxy,
		DataDir:      *dataDir,
	})
	if err != nil {
		log.Fatalf("Proxy server initialization failed: %v", err)
	}

	srv.PrintBanner(*localIP)

	// Automatically open browser to entry list once listening successfully (PC usage).
	// Skipped in local proxy mode: the portal is for l.moonchan.xyz entries, and
	// the local proxy listens on the same port the user's redirected hostnames
	// already target, so opening a browser here would just hit the proxy itself.
	if !*noBrowser && !*localProxy {
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
