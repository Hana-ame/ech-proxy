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
}

// Server represents a running ECH proxy server instance.
type Server struct {
	Options    ServerOptions
	Config     *Config
	TLSCert    *tls.Certificate
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

// NewEngine creates and configures a standard Gin engine with Recovery, CORS, and SetupRouter.
func NewEngine(cfg *Config) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(CORSMiddleware())
	SetupRouter(r, cfg)
	return r
}

// NewServer completes full initialization sequence and binds listening port according to given ServerOptions.
func NewServer(opts ServerOptions) (*Server, error) {
	// 1. Initialize ECH network client
	if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
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

	// 3. Fetch TLS certificate if not in HTTP mode
	var tlsCert *tls.Certificate
	if !opts.HTTPMode && cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, err := LoadTLSCert(cfg)
		if err != nil {
			if !opts.AllowRandomPort {
				// Desktop version strictly errors
				return nil, err
			}
			log.Printf("Failed to load certificate, degrading: %v", err)
		} else {
			tlsCert = cert
		}
	}

	// 4. Build unified Gin router engine
	engine := NewEngine(cfg)

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
	if !opts.HTTPMode && tlsCert != nil {
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
	fmt.Printf("  Mode: %s\n", map[bool]string{true: "HTTP (Local Proxy)", false: "TLS (Remote)"}[s.Options.HTTPMode])
	fmt.Printf("  Listening: %s\n", s.Options.Addr)
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
