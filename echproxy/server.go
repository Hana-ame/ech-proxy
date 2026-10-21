// Package echproxy 以高内聚、低耦合的工程化架构组装三种完全解耦的运行方案，最大化复用底层核心模块（netdial, ech, certstore, rewrite, cookie, logger）：
//  1. PAC 方案（默认主线 mainstream）：默认监听 8443（端口占用或指定其他端口亦全功能无感运行），复用本地自签 CA (certstore, 存于 <dataDir>/ca/) + DoH/SNI/ECH/Fragment + 证书核对 (ech) + CONNECT MITM (connect)，独享 pac.txt、on.txt、block.json 与 ads.js (rewrite.AdScriptManager)，与 upstream.json 及 certs/ 路径完全解耦；
//  2. 443 方案（仅当文件名匹配 .*.443.exe 时开启）：只和 listen 443 有关，仅监听 443 端口，复用本地自签 CA (certstore) + DoH/SNI/ECH/Fragment + 证书核对 (ech)，其余模块一律不运行；
//  3. 8443 方案（真实公网证书下发的门户代理）：仅与 upstream.json 及 certs/l.moonchan.xyz/ 路径有关，在后台静默非阻塞运行以保持兼容性，即使报错也不影响任何其他功能且绝不阻塞其他代码。
package echproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/certstore"
	"github.com/Hana-ame/ech-proxy/echproxy/config"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

type (
	Config          = config.Config
	UpstreamConfig  = config.UpstreamConfig
	UpstreamMap     = config.UpstreamMap
	WildcardRule    = config.WildcardRule
	ValidationIssue = config.ValidationIssue
	CertStore       = certstore.Store
	AdScriptManager = rewrite.AdScriptManager
	AdScriptOptions = rewrite.AdScriptOptions
	BlocklistRules  = rewrite.BlocklistRules
	Logger          = logger.Manager
	LoggerOptions   = logger.Options
)

var (
	ParseConfig               = config.Parse
	LoadConfig                = config.Load
	ValidateConfig            = config.Validate
	FormatConfigIssues        = config.FormatIssues
	ConfigHasErrors           = config.HasErrors
	GenerateHostsBlock        = config.GenerateHostsBlock
	ApplyHostsBlock           = config.ApplyHostsBlock
	RemoveHostsBlock          = config.RemoveHostsBlock
	DefaultSystemHostsPath    = config.DefaultSystemHostsPath
	GeneratePAC               = config.GeneratePAC
	FetchBytes                = netdial.FetchBytes
	CleanHost                 = netdial.CleanHost
	ExtractPort               = netdial.ExtractPort
	IsPort443                 = netdial.IsPort443
	NormalizeLoopbackHostPort = netdial.NormalizeLoopbackHostPort
	ValidateIPMode            = netdial.ValidateIPMode
	NormalizeIPMode           = netdial.NormalizeIPMode
	EffectiveIPMode           = netdial.EffectiveIPMode
	FormatIPMode              = netdial.FormatIPMode
	DefaultIPMode             = netdial.DefaultIPMode
	NewCertStore              = certstore.NewStore
	DefaultDataDir            = certstore.DefaultDataDir
	MatchWildcardForTest      = config.MatchWildcard
	DefaultUpstreamConfigURL  = config.DefaultConfigURL

	NewAdScriptManager      = rewrite.NewAdScriptManager
	ParseDomainList         = rewrite.ParseDomainList
	ParseDomainListJSON     = rewrite.ParseDomainListJSON
	ParseBlocklist          = rewrite.ParseBlocklist
	ParseOnSwitch           = rewrite.ParseOnSwitch
	BuildAdScriptTags       = rewrite.BuildAdScriptTags
	SplitAdScriptBlocks     = rewrite.SplitAdScriptBlocks
	MatchDomainInList       = rewrite.MatchDomainInList
	ContainsAdultAdInHTML   = rewrite.ContainsAdultAdInHTML
	DefaultAdScriptURL      = rewrite.DefaultAdScriptURL
	DefaultWhitelistURL     = rewrite.DefaultWhitelistURL
	DefaultAdultSitesURL    = rewrite.DefaultAdultSitesURL
	DefaultBlocklistURL     = rewrite.DefaultBlocklistURL
	DefaultOnURL            = rewrite.DefaultOnURL
	DefaultOnRetryCount     = rewrite.DefaultOnRetryCount
	DefaultAdScriptInterval = rewrite.DefaultAdScriptUpdateInterval
	DefaultPrimaryDoHURL    = cloudflare_ech.DefaultPrimaryDoHURL
	DefaultSecondaryDoHURL  = cloudflare_ech.DefaultSecondaryDoHURL
	DefaultDoHHost          = cloudflare_ech.DefaultDoHHost
	SetGlobalIPMode         = cloudflare_ech.SetIPMode
	GetGlobalIPMode         = cloudflare_ech.GetIPMode
	InitLogger              = logger.Init
	NewLogger               = logger.NewManager
	DefaultLogger           = logger.Default
	EnsureDefaultLogger     = logger.EnsureDefault
	DefaultLogDir           = logger.DefaultLogDir
	RecordFatalError        = logger.RecordFatalError
	RecoverAndLog           = logger.RecoverAndLog
	SafeGo                  = logger.SafeGo
	CleanLogs               = logger.CleanLogs
)

const (
	// DoH 主机名统一引用 ech 包（源自 netdial.DefaultSiteHost）的唯一 true source。
	defaultListenAddr = "127.0.0.1:8443"
)

type ServerOptions struct {
	Addr                string
	AllowRandomPort     bool
	FallbackAddr        string
	HTTPMode            bool
	PortalMode          bool // true: 8443 方案（加载 upstream.json 与真实公网证书）
	ConfigURL           string
	BootstrapIP         string
	IPMode              string
	AllMode             bool
	LocalProxy          bool // true: 443 方案（仅 .*.443.exe，只监听 443 端口，其余一律不运行）
	DataDir             string
	AllowConnect        bool
	DisableConnect      bool
	ConnectMode         string
	AllowPrivateConnect bool
	PerPeerMaxTunnels   int
	GlobalMaxTunnels    int
	TunnelIdleTimeout   time.Duration
	Auth                *AuthConfig
	NoAdScript          bool
	SkipAdScript        bool
	SkipAdBlock         bool
	AdScriptURL         string
	WhitelistURL        string
	AdultSitesURL       string
	BlocklistURL        string
	OnURL               string
	OnRetries           int
	AdScriptInterval    time.Duration
	Logger              *logger.Manager
}

type Server struct {
	mu         sync.RWMutex
	Options    ServerOptions
	Config     *config.Config
	TLSCert    *tls.Certificate
	CertStore  *certstore.Store
	Engine     *gin.Engine
	HTTPServer *http.Server
	Listener   net.Listener
	Port       uint16
	IsTLS      bool
	Auth       *AuthConfig
	Limiter    *TunnelLimiter
	AdScript   *rewrite.AdScriptManager
	Logger     *logger.Manager
	bgCancel   context.CancelFunc
}

func InitECH(bootstrapIP, ipMode string) error {
	if bootstrapIP != "" {
		cloudflare_ech.SetDoHConfig(DefaultDoHHost, bootstrapIP)
	} else {
		cloudflare_ech.SetDohURL(DefaultPrimaryDoHURL)
	}
	cloudflare_ech.SetFallbackDohURL(DefaultSecondaryDoHURL)
	cloudflare_ech.SetIPMode(netdial.EffectiveIPMode(ipMode))
	if err := cloudflare_ech.InitDefault(); err != nil {
		return fmt.Errorf("ECH client initialization failed: %w", err)
	}
	return nil
}

func retryInitECH(bootstrapIP, ipMode string) {
	for _, wait := range []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute} {
		time.Sleep(wait)
		if InitECH(bootstrapIP, ipMode) == nil {
			return
		}
	}
}

func (s *Server) SetIPMode(mode string) {
	norm := netdial.EffectiveIPMode(mode)
	cloudflare_ech.SetIPMode(norm)
	if s == nil {
		return
	}
	s.mu.Lock()
	s.Options.IPMode = norm
	s.mu.Unlock()
	log.Printf("[IPMode] Switched global egress IP mode to: %s", netdial.FormatIPMode(norm))
}

func (s *Server) GetIPMode() string {
	if s == nil {
		return cloudflare_ech.GetIPMode()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return netdial.EffectiveIPMode(s.Options.IPMode)
}

func NewServer(opts ServerOptions) (*Server, error) {
	addr := strings.TrimSpace(opts.Addr)
	if addr == "" {
		if opts.LocalProxy {
			addr = "127.0.0.1:443"
		} else {
			addr = defaultListenAddr
		}
	}
	if opts.LocalProxy {
		// 443 方案只和 listen 443 有关，禁止监听其他端口或回退到 8443
		if !netdial.IsPort443(addr) {
			return nil, errors.New("443 scheme only supports listening on port 443")
		}
		opts.FallbackAddr = ""
		opts.AllowRandomPort = false
		opts.PortalMode = false
		opts.AllowConnect = false
		opts.DisableConnect = true
	} else {
		if netdial.IsPort443(addr) {
			return nil, errors.New("port 443 is strictly disabled when executable filename does not end with .443.exe")
		}
		opts.FallbackAddr = ""
	}
	opts.Addr = addr
	opts.IPMode = netdial.EffectiveIPMode(opts.IPMode)

	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir, _ = certstore.DefaultDataDir()
	}
	cacheDir := ""
	if dataDir != "" {
		cacheDir = filepath.Join(dataDir, "cache")
	}
	logMgr := opts.Logger
	if logMgr == nil {
		logMgr = logger.Default()
	}

	// 1. 初始化公共传输层 DoH / ECH / SNI / Fragment（后台非阻塞初始化，绝不阻塞启动）
	SafeGo("InitECH", func() {
		if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
			retryInitECH(opts.BootstrapIP, opts.IPMode)
		}
	})

	// 2. 初始化本地自签 CA 证书模块（存于 <dataDir>/ca/，与 certs/ 路径完全解耦）
	var store *certstore.Store
	if !opts.HTTPMode {
		if dataDir != "" {
			if st, serr := certstore.NewStore(dataDir); serr == nil {
				store = st
			} else if opts.LocalProxy {
				return nil, fmt.Errorf("init cert store: %w", serr)
			}
		}
		if store == nil && !opts.PortalMode {
			return nil, errors.New("TLS mode requires local CA store")
		}
	}

	// 3. 绑定监听端口：
	//    - 443 方案严格只监听 443 端口；
	//    - PAC 方案默认 8443，若端口被占用自动切换可用端口。
	allowPortFallback := !opts.LocalProxy && (opts.AllowRandomPort || !opts.PortalMode)
	ln, actualAddr, err := listenWithFallback(opts.Addr, opts.FallbackAddr, allowPortFallback)
	if err != nil {
		return nil, err
	}
	opts.Addr = actualAddr
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	bgCtx, bgCancel := context.WithCancel(context.Background())

	// 4. 443 方案分支：在命名为 .*.443.exe 时，只有 443 方案开启，其他（PAC、8443、CONNECT 等）一律不运行
	if opts.LocalProxy {
		cfg := &config.Config{Upstreams: config.UpstreamMap{}}
		engine := New443Engine(store, opts.Auth)
		httpSrv := &http.Server{
			Handler:           engine,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if store != nil {
			httpSrv.ErrorLog = certstore.NewTLSAlertFilterLogger(store.CAPath())
			httpSrv.TLSConfig = store.TLSConfig(nil)
		}
		return &Server{
			Options:    opts,
			Config:     cfg,
			CertStore:  store,
			Engine:     engine,
			HTTPServer: httpSrv,
			Listener:   ln,
			Port:       port,
			IsTLS:      !opts.HTTPMode,
			Auth:       opts.Auth,
			Logger:     logMgr,
			bgCancel:   bgCancel,
		}, nil
	}

	// 5. PAC 主线方案：启动独有的 pac.txt、on.txt、block.json 与 ads.js 管理器（与 upstream.json 及 certs/ 完全解耦）
	var adScript *rewrite.AdScriptManager
	if !opts.PortalMode {
		skipAdScript := opts.NoAdScript || opts.SkipAdScript
		adScript = rewrite.NewAdScriptManager(rewrite.AdScriptOptions{
			Enabled:        !skipAdScript,
			SkipAdScript:   skipAdScript,
			SkipAdBlock:    opts.SkipAdBlock,
			AllMode:        opts.AllMode,
			ScriptURL:      strings.TrimSpace(opts.AdScriptURL),
			WhitelistURL:   strings.TrimSpace(opts.WhitelistURL),
			AdultSitesURL:  strings.TrimSpace(opts.AdultSitesURL),
			BlocklistURL:   strings.TrimSpace(opts.BlocklistURL),
			OnURL:          strings.TrimSpace(opts.OnURL),
			OnRetries:      opts.OnRetries,
			UpdateInterval: opts.AdScriptInterval,
			CacheDir:       cacheDir,
		})
		adScript.StartAutoUpdate(bgCtx)
	}

	// 6. 8443 方案（upstream.json + certs/l.moonchan.xyz/ 真实证书）：
	//    单纯在后台静默非阻塞运行，即使报错也不影响其他功能，仅作兼容性保留，绝不阻塞主线代码。
	cfg := &config.Config{Upstreams: config.UpstreamMap{}}
	if opts.ConfigURL != "" && isLocalFile(opts.ConfigURL) {
		if raw, rerr := os.ReadFile(strings.TrimSpace(strings.TrimPrefix(opts.ConfigURL, "file://"))); rerr == nil {
			if parsed, perr := config.Parse(raw); perr == nil && parsed != nil {
				cfg.ReplaceFrom(parsed)
				seedCookiesFromConfig(cfg)
			}
		}
	}

	auth := opts.Auth
	limiter := NewTunnelLimiter(opts.PerPeerMaxTunnels, opts.GlobalMaxTunnels)

	engine := NewEngineWithOptions(EngineOptions{
		Config:    cfg,
		CertStore: store,
		Auth:      auth,
		Limiter:   limiter,
		AdScript:  adScript,
		Logger:    logMgr,
		AllMode:   opts.AllMode,
		IPMode:    opts.IPMode,
		Port:      port,
	})

	connectEnabled := opts.AllowConnect || (!opts.DisableConnect && (strings.HasPrefix(actualAddr, "127.0.0.1:") || strings.HasPrefix(actualAddr, "localhost:")))

	connectOpts := ConnectOptions{
		Enabled:             connectEnabled,
		Mode:                opts.ConnectMode,
		IPMode:              opts.IPMode,
		AllowPrivateTargets: opts.AllowPrivateConnect,
		IdleTimeout:         opts.TunnelIdleTimeout,
		Auth:                auth,
		Limiter:             limiter,
		CertStore:           store,
		Config:              cfg,
		AdScript:            adScript,
		HTTPHandler:         engine,
	}

	topHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer logger.RecoverAndLog("HTTPTopHandler", nil)
		if r.Method == http.MethodConnect {
			co := connectOpts
			co.IPMode = cloudflare_ech.GetIPMode()
			if store != nil {
				co.PortalCert = store.PortalCert()
			}
			handleHTTPConnect(w, r, co)
			return
		}
		engine.ServeHTTP(w, r)
	})

	httpSrv := &http.Server{
		Handler:           topHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if store != nil {
		httpSrv.ErrorLog = certstore.NewTLSAlertFilterLogger(store.CAPath())
	}

	isTLS := !opts.HTTPMode
	if isTLS && store != nil {
		httpSrv.TLSConfig = store.TLSConfig(nil)
	}

	srv := &Server{
		Options:    opts,
		Config:     cfg,
		CertStore:  store,
		Engine:     engine,
		HTTPServer: httpSrv,
		Listener:   ln,
		Port:       port,
		IsTLS:      isTLS,
		Auth:       auth,
		Limiter:    limiter,
		AdScript:   adScript,
		Logger:     logMgr,
		bgCancel:   bgCancel,
	}

	// 后台静默加载 8443 方案的 upstream.json 与真实证书（绝不阻塞任何其他代码，报错静默忽略）
	SafeGo("8443-SilentCompatLoader", func() {
		select {
		case <-bgCtx.Done():
			return
		default:
		}
		loaded, lerr := config.Load(opts.ConfigURL)
		if lerr != nil || loaded == nil {
			return
		}
		select {
		case <-bgCtx.Done():
			return
		default:
		}
		cfg.ReplaceFrom(loaded)
		seedCookiesFromConfig(cfg)
		if loaded.CertPath != "" && loaded.KeyPath != "" && !opts.HTTPMode {
			if pc, cerr := certstore.LoadRemoteCert(loaded.CertPath, loaded.KeyPath); cerr == nil && pc != nil {
				srv.mu.Lock()
				srv.TLSCert = pc
				srv.mu.Unlock()
				if store != nil {
					store.SetPortalCert(pc)
				}
			}
		}
	})

	return srv, nil
}

func isLocalFile(p string) bool {
	p = strings.TrimSpace(strings.TrimPrefix(p, "file://"))
	if p == "" || strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func listenWithFallback(primaryAddr, fallbackAddr string, allowOtherPort bool) (net.Listener, string, error) {
	network := "tcp"
	if strings.HasPrefix(primaryAddr, "127.0.0.1") {
		network = "tcp4"
	}
	if ln, err := net.Listen(network, primaryAddr); err == nil {
		return ln, ln.Addr().String(), nil
	} else {
		var candidates []string
		if fallbackAddr != "" && fallbackAddr != primaryAddr {
			candidates = append(candidates, fallbackAddr)
		}
		if allowOtherPort && strings.HasSuffix(primaryAddr, ":8443") {
			candidates = append(candidates, "127.0.0.1:8444", "127.0.0.1:18443")
		}
		for _, cand := range candidates {
			fbNet := "tcp"
			if strings.HasPrefix(cand, "127.0.0.1") {
				fbNet = "tcp4"
			}
			if ln2, err2 := net.Listen(fbNet, cand); err2 == nil {
				log.Printf("WARNING: Port %s busy (%v); switched to %s", primaryAddr, err, ln2.Addr().String())
				return ln2, ln2.Addr().String(), nil
			}
		}
		if allowOtherPort {
			if ln3, err3 := net.Listen("tcp4", "127.0.0.1:0"); err3 == nil {
				log.Printf("WARNING: Port %s busy (%v); switched to %s", primaryAddr, err, ln3.Addr().String())
				return ln3, ln3.Addr().String(), nil
			}
		}
		return nil, primaryAddr, fmt.Errorf("listen on %s: %w", primaryAddr, err)
	}
}

func (s *Server) Serve() error {
	if s.IsTLS {
		return s.serveDualModeTLS()
	}
	return s.HTTPServer.Serve(s.Listener)
}

func (s *Server) serveDualModeTLS() error {
	tlsChan := &chanListener{addr: s.Listener.Addr(), ch: make(chan net.Conn, 128), done: make(chan struct{})}
	plainChan := &chanListener{addr: s.Listener.Addr(), ch: make(chan net.Conn, 128), done: make(chan struct{})}

	SafeGo("serveDualModeTLS-TLS", func() {
		_ = s.HTTPServer.Serve(tls.NewListener(tlsChan, s.HTTPServer.TLSConfig))
	})
	SafeGo("serveDualModeTLS-Plain", func() {
		plainSrv := &http.Server{
			Handler:           s.HTTPServer.Handler,
			ReadHeaderTimeout: s.HTTPServer.ReadHeaderTimeout,
			IdleTimeout:       s.HTTPServer.IdleTimeout,
			ErrorLog:          s.HTTPServer.ErrorLog,
		}
		_ = plainSrv.Serve(plainChan)
	})

	for {
		rawConn, err := s.Listener.Accept()
		if err != nil {
			tlsChan.Close()
			plainChan.Close()
			if errors.Is(err, net.ErrClosed) {
				return http.ErrServerClosed
			}
			return err
		}
		SafeGo("serveDualModeTLS-AcceptConn", func() {
			_ = rawConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReaderSize(rawConn, 4096)
			first, perr := br.Peek(1)
			_ = rawConn.SetReadDeadline(time.Time{})
			if perr != nil {
				_ = rawConn.Close()
				return
			}
			wrapped := &bufferedConn{Conn: rawConn, r: br}
			target := plainChan
			if first[0] == 0x16 {
				target = tlsChan
			}
			select {
			case target.ch <- wrapped:
			case <-target.done:
				_ = rawConn.Close()
			}
		})
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

func (s *Server) ServeAsync() error {
	SafeGo("ServeAsync", func() {
		if err := s.Serve(); err != nil && err != http.ErrServerClosed {
			RecordFatalError("ServeAsync", err)
		}
	})
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.bgCancel != nil {
		s.bgCancel()
	}
	if s.AdScript != nil {
		s.AdScript.Stop()
	}
	if s.Listener != nil {
		_ = s.Listener.Close()
	}
	if s.HTTPServer != nil {
		return s.HTTPServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) Close() error {
	if s.bgCancel != nil {
		s.bgCancel()
	}
	if s.AdScript != nil {
		s.AdScript.Stop()
	}
	if s.Listener != nil {
		_ = s.Listener.Close()
	}
	if s.HTTPServer != nil {
		return s.HTTPServer.Close()
	}
	return nil
}

func BuildVersionInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var rev, t, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 8 {
				rev = s.Value[:8]
			} else {
				rev = s.Value
			}
		case "vcs.time":
			t = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return info.GoVersion
	}
	return fmt.Sprintf("%s%s (%s, %s)", rev, dirty, t, info.GoVersion)
}

func (s *Server) PrintBanner(localIP string) {
	listenPort := fmt.Sprintf("%d", s.Port)
	fmt.Printf("=== ECH Proxy [%s] ===\n", BuildVersionInfo())
	switch {
	case s.Options.LocalProxy:
		fmt.Printf("  Scheme: 443 Local Transparent Proxy (.*.443.exe only)\n")
	case s.Options.PortalMode:
		fmt.Printf("  Scheme: 8443 Real-Cert Portal Proxy (Silent Compatibility / Mobile App)\n")
	default:
		fmt.Printf("  Scheme: PAC HTTPS MITM Proxy [Mainstream] (Local CA + DoH/SNI/ECH/Fragment + pac.txt + on.txt + block.json + ads.js)\n")
	}
	fmt.Printf("  Listening: %s\n", s.Options.Addr)
	if !s.Options.LocalProxy && !s.Options.PortalMode {
		if s.Options.AllMode {
			fmt.Printf("  Routing Scope: ALL Mode (-all)\n")
		} else {
			fmt.Printf("  Routing Scope: PAC Whitelist (%s)\n", DefaultWhitelistURL)
		}
		pacSuffix := ""
		if s.Options.AllMode {
			pacSuffix = "?mode=all"
		}
		fmt.Printf("  PAC URL: http://127.0.0.1:%s/proxy.pac%s\n", listenPort, pacSuffix)
	}
	fmt.Printf("  Egress IP Mode: %s (flags: -4 / -6 / -dual)\n", netdial.FormatIPMode(s.GetIPMode()))
	fmt.Printf("  DoH Endpoints: Primary=%s | Secondary=%s\n", DefaultPrimaryDoHURL, DefaultSecondaryDoHURL)
	if s.CertStore != nil {
		fmt.Printf("  CA Cert: %s (http://127.0.0.1:%s/ca.pem)\n", s.CertStore.CAPath(), listenPort)
	}
	fmt.Printf("=================\n")
}