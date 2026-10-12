package echproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/gin-gonic/gin"
)

// DefaultUpstreamConfigURL is the default remote upstream configuration address (global single source of truth).
const DefaultUpstreamConfigURL = "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/upstream.json?proxy_host=raw.githubusercontent.com"

// dohHost is the DNS-over-HTTPS hostname used for ECH bootstrapping.
const dohHost = "moonchan.xyz"

// defaultListenAddr is the fallback listen address when none is specified.
const defaultListenAddr = "127.0.0.1:8443"

// ServerOptions encapsulates parameters required to start the ECH proxy server.
type ServerOptions struct {
	Addr            string // Listen address, defaults to "127.0.0.1:8443"
	AllowRandomPort bool   // Fall back to random available port if Addr is busy (mobile/Android scenario)
	HTTPMode        bool   // Force HTTP mode (do not enable TLS)
	ConfigURL       string // Remote upstream.json URL, defaults to DefaultUpstreamConfigURL if empty
	BootstrapIP     string // DoH bootstrap IP (optional)
	IPMode          string // "v4" / "v6" preference (optional)
	// AllowConnect enables the HTTP CONNECT tunnel handler. It is off by
	// default: a tunnel is an open forward proxy, which is a meaningfully
	// different security posture from the host-restricted reverse proxy this
	// project normally runs. Enabling it is an explicit operator decision.
	AllowConnect bool
	// DestGuard validates CONNECT tunnel destinations. When nil, NewServer
	// installs the default guard, which blocks loopback, private, link-local
	// and cloud-metadata addresses.
	DestGuard DestinationChecker
	// LocalProxy switches to local reverse proxy mode: the proxy terminates TLS
	// with a locally generated self-signed CA and forwards each incoming Host
	// to the same-named upstream. Used when the user points real hostnames
	// (pixiv.net, account.pixiv.net) at 127.0.0.1 and runs the proxy on port
	// 443. See README "Local reverse proxy mode".
	//
	// In this mode:
	//   - the TLS material is self-generated and persisted under DataDir, never
	//     downloaded;
	//   - ECH/DoH bootstrap is skipped (upstreams use mode "direct");
	//   - TLS is mandatory (HTTPMode is ignored).
	LocalProxy bool
	// DataDir is where the local CA and issued leaf certificates live. Empty
	// falls back to DefaultDataDir(). Only used when LocalProxy is set.
	DataDir string
}

// Server represents a running ECH proxy server instance.
type Server struct {
	Options    ServerOptions
	Config     *Config
	TLSCert    *tls.Certificate
	CertStore  *CertStore // non-nil in LocalProxy mode: self-signed CA + issued leaves
	Engine     *gin.Engine
	HTTPServer *http.Server
	Listener   net.Listener
	Port       uint16
	IsTLS      bool
}

// InitECH initializes the underlying Cloudflare ECH and DoH client.
func InitECH(bootstrapIP, ipMode string) error {
	if bootstrapIP != "" {
		log.Printf("ECH: DoH=%s, bootstrapIP=%s", dohHost, bootstrapIP)
		cloudflare_ech.SetDoHConfig(dohHost, bootstrapIP)
	} else {
		log.Printf("ECH: DoH=https://%s/doh", dohHost)
		cloudflare_ech.SetDohURL("https://" + dohHost + "/doh")
	}

	if ipMode != "" {
		cloudflare_ech.SetIPMode(ipMode)
	}

	// CheckDualStack reports the probe hostname's published record families, not the local stack,
	// so this line cannot tell you which family the upstream egress will use. dialTCP logs the
	// actual egress address instead (see ech/client.go).
	v4ok, v6ok := cloudflare_ech.CheckDualStack(context.Background())
	if v4ok || v6ok {
		suffix := ""
		if ipMode != "" {
			suffix = " (forced " + ipMode + ")"
		}
		log.Printf("Upstream DNS records (moonchan.xyz): A=%v AAAA=%v%s", v4ok, v6ok, suffix)
	} else {
		log.Printf("Upstream DNS probe failed (DNS unreachable)")
	}

	log.Printf("Initializing ECH client...")
	if err := cloudflare_ech.InitDefault(); err != nil {
		return fmt.Errorf("ECH client initialization failed: %w", err)
	}
	log.Printf("ECH client ready")
	return nil
}

// retryInitECH retries ECH bootstrap in the background after a startup failure
// in local proxy mode. The first minutes matter most: a user who just launched
// ech-proxy.443.exe and opened pixiv expects it to work, so the early retries
// are tighter than the 5-minute operation timeout used elsewhere.
func retryInitECH(bootstrapIP, ipMode string) {
	waits := []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	for i, wait := range waits {
		time.Sleep(wait)
		if err := InitECH(bootstrapIP, ipMode); err == nil {
			log.Printf("ECH client recovered after %d failed attempt(s)", i+1)
			return
		} else if i+1 < len(waits) {
			log.Printf("ECH retry %d/%d failed: %v (next in %s)", i+1, len(waits), err, waits[i+1])
		}
	}
	log.Printf("ECH client still unavailable after %d retries; sni/ech upstreams will keep failing", len(waits))
}

// LoadTLSCert dynamically fetches and parses TLS certificate and key pair from CertPath and KeyPath in config.
func LoadTLSCert(cfg *Config) (*tls.Certificate, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("missing cert_path or key_path in config")
	}
	log.Printf("Fetching TLS certificate: %s", cfg.CertPath)
	certPEM, err := FetchBytes(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate: %w", err)
	}
	log.Printf("Fetching TLS key: %s", cfg.KeyPath)
	keyPEM, err := FetchBytes(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate key pair: %w", err)
	}
	log.Printf("TLS certificate loaded successfully")
	return &cert, nil
}

// NewEngine creates and configures a standard Gin engine with Recovery and SetupRouter.
func NewEngine(cfg *Config, allowConnect bool) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	SetupRouter(r, cfg, allowConnect)
	return r
}

// newEngineWithGuard is NewEngine with an explicit destination checker, so a
// caller can tighten or relax the tunnel policy without a global.
func newEngineWithGuard(cfg *Config, allowConnect bool, guard DestinationChecker) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	setupRouterWithGuard(r, cfg, allowConnect, guard)
	return r
}

// NewServer completes full initialization sequence and binds listening port according to given ServerOptions.
func NewServer(opts ServerOptions) (*Server, error) {
	// 1. Initialize the ECH network client.
	//
	// Local proxy mode still needs it: only l.moonchan.xyz keeps the original
	// direct path, every other incoming hostname (pixiv.net and its
	// subdomains) is forwarded through sni/ech like the remote deployment does.
	// Without the ECH client those upstreams would fail on the first request.
	//
	// The difference is that failure is not fatal here. A remote deployment
	// cannot serve anything without ECH, but the local proxy still terminates
	// TLS and can serve any direct-mode upstream even when moonchan.xyz is
	// unreachable — for example while the DoH endpoint is jittering. So it is
	// retried in the background and the caller is told what it can and cannot
	// do.
	if opts.LocalProxy {
		log.Printf("Local reverse proxy mode: TLS via self-generated CA (not downloaded); non-l.moonchan.xyz hosts forward via sni/ech")
		if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
			log.Printf("WARNING: ECH initialization failed; sni/ech upstreams will fail until it succeeds: %v", err)
			go retryInitECH(opts.BootstrapIP, opts.IPMode)
		}
	} else if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
		return nil, err
	}

	// 2. Load remote upstream configuration
	configURL := opts.ConfigURL
	if configURL == "" {
		configURL = DefaultUpstreamConfigURL
	}
	log.Printf("Loading upstream config: %s", configURL)
	cfg, err := LoadConfig(configURL)
	if err != nil {
		return nil, fmt.Errorf("failed to load upstream config: %w", err)
	}
	log.Printf("Upstream config loaded successfully: %d rules", len(cfg.Upstreams))

	// 3. TLS material: a self-generated CA in local mode, the configured
	// certificate pair otherwise.
	var (
		tlsCert   *tls.Certificate
		certStore *CertStore
	)
	switch {
	case opts.LocalProxy:
		dataDir := opts.DataDir
		if dataDir == "" {
			dd, derr := DefaultDataDir()
			if derr != nil {
				return nil, derr
			}
			dataDir = dd
		}
		store, serr := NewCertStore(dataDir)
		if serr != nil {
			return nil, fmt.Errorf("failed to initialize certificate store: %w", serr)
		}
		certStore = store
	case !opts.HTTPMode && cfg.CertPath != "" && cfg.KeyPath != "":
		cert, ferr := LoadTLSCert(cfg)
		if ferr != nil {
			if !opts.AllowRandomPort {
				// Desktop version strictly errors
				return nil, ferr
			}
			log.Printf("Failed to load certificate, degrading: %v", ferr)
		} else {
			tlsCert = cert
		}
	}

	// 4. Build unified Gin router engine
	guard := opts.DestGuard
	if guard == nil && opts.AllowConnect {
		guard = NewDestinationGuard(DestinationGuardConfig{})
	}
	engine := newEngineWithGuard(cfg, opts.AllowConnect, guard)

	// 5. Bind network listener
	addr := opts.Addr
	if addr == "" {
		addr = defaultListenAddr
	}
	network := "tcp"
	if strings.HasPrefix(addr, "127.0.0.1") {
		network = "tcp4"
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		if opts.AllowRandomPort {
			log.Printf("Address %s is busy or unavailable, trying random port...", addr)
			ln, err = net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, fmt.Errorf("random port listener failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
		}
	}

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 6. Build http.Server
	srv := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	isTLS := false
	if opts.LocalProxy {
		// Local mode terminates TLS for whatever SNI the client presents, so the
		// certificate is chosen per connection from the self-signed CA. The
		// first SNI seen for a domain triggers a one-time leaf issuance (RSA key
		// generation plus an atomic write), which is what the user asked for:
		// certificates are generated locally and persisted, never downloaded.
		isTLS = true
		store := certStore
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return store.CertificateFor(hello.ServerName)
			},
		}
	} else if !opts.HTTPMode && tlsCert != nil {
		isTLS = true
		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return &Server{
		Options:    opts,
		Config:     cfg,
		TLSCert:    tlsCert,
		CertStore:  certStore,
		Engine:     engine,
		HTTPServer: srv,
		Listener:   ln,
		Port:       port,
		IsTLS:      isTLS,
	}, nil
}

// Serve starts providing HTTP/HTTPS service (blocking call).
func (s *Server) Serve() error {
	if s.IsTLS {
		tlsLn := tls.NewListener(s.Listener, s.HTTPServer.TLSConfig)
		return s.HTTPServer.Serve(tlsLn)
	}
	return s.HTTPServer.Serve(s.Listener)
}

// ServeAsync starts providing service in a background goroutine.
func (s *Server) ServeAsync() error {
	go func() {
		if err := s.Serve(); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.HTTPServer != nil {
		return s.HTTPServer.Shutdown(ctx)
	}
	return nil
}

// Close immediately closes the server.
func (s *Server) Close() error {
	if s.HTTPServer != nil {
		return s.HTTPServer.Close()
	}
	return nil
}

// PrintBanner prints the startup banner following the upstream write order recorded in orderedmap (strictly adhering to config order without custom sorting).
func (s *Server) PrintBanner(localIP string) {
	listenPort := fmt.Sprintf("%d", s.Port)
	fmt.Printf("=== ECH Proxy ===\n")
	switch {
	case s.Options.LocalProxy:
		fmt.Printf("  Mode: Local Reverse Proxy (TLS, self-generated CA)\n")
	case s.Options.HTTPMode:
		fmt.Printf("  Mode: HTTP (Local Proxy)\n")
	default:
		fmt.Printf("  Mode: TLS (Remote)\n")
	}
	fmt.Printf("  Listening: %s\n", s.Options.Addr)
	if s.Options.LocalProxy && s.CertStore != nil {
		fmt.Printf("  CA: %s (valid until %s)\n",
			s.CertStore.CAPath(), s.CertStore.CAValidUntil().Format("2006-01-02"))
		fmt.Printf("  Data dir: %s\n", s.CertStore.DataDir)
		fmt.Printf("  Install the CA into the system trust store to trust these domains, then set\n")
		fmt.Printf("  the hosts entries to 127.0.0.1. See README \"Local reverse proxy mode\".\n")
	}
	if localIP != "" {
		fmt.Printf("  DoH IP: %s\n", localIP)
	}
	if s.Options.IPMode != "" {
		fmt.Printf("  IP Mode: %s (upstream egress family pinned)\n", s.Options.IPMode)
	} else {
		fmt.Printf("  IP Mode: auto (upstream egress family OS-decided)\n")
	}

	upstreamCfg := s.Config.Upstreams
	domains := s.Config.UpstreamOrder
	if len(domains) == 0 {
		for host := range upstreamCfg {
			domains = append(domains, host)
		}
	}

	for _, d := range domains {
		uc, ok := upstreamCfg[d]
		if !ok {
			continue
		}
		entry := d
		if listenPort != "" {
			entry += ":" + listenPort
		}
		fmt.Printf("  Domain: %s -> %s (%s)", entry, uc.Host, ModeName(uc.Mode))
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
			fmt.Printf(" [+wildcard %s -> *%s]", we, w.UpstreamSuffix)
		}
		fmt.Println()
	}
	fmt.Printf("=================\n")
}
