// Package echproxy 组装各语义子模块（config, certstore, ech, rewrite, cookie, netdial, logger）：
//   - 主线模式：PAC HTTPS 正向代理（Smart MITM ECH/SNI/Fragment 终结，使用本地生成的自签名 CA，独立于门户模式）；
//   - 支持远程 PAC 白名单（https://4545810.xyz/pac.txt，一行一个 domain）：白名单 = 去掉原有广告 + 插入广告商代码 (https://4545810.xyz/ads.js) + 通过 PAC 代理，其他直接 DIRECT；
//   - 支持全局模式（仅通过命令行 -all 开启）：无视名单，所有网站均通过 ech-proxy 代理；
//   - 支持出口协议族选择（-4 强制 v4 出口、-6 强制 v6 出口、-dual 双端出口，以及托盘菜单实时切换）；
//   - 支持首选 DoH (https://4545810.xyz/doh) 与次选 DoH (https://1.1.1.1/dns-query) 自动故障切换；
//   - 443 本地透明反代代码严格隔离：仅当可执行文件名包含 .443.exe (LocalProxy=true) 时才监听 443 端口并运行 443 逻辑。
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

// 导出常用类型与函数别名，保持与桌面端/Android 端调用方的完全兼容。
type (
	Config          = config.Config
	UpstreamConfig  = config.UpstreamConfig
	UpstreamMap     = config.UpstreamMap
	WildcardRule    = config.WildcardRule
	ValidationIssue = config.ValidationIssue
	CertStore       = certstore.Store
	AdScriptManager = rewrite.AdScriptManager
	AdScriptOptions = rewrite.AdScriptOptions
	Logger          = logger.Manager
	LoggerOptions   = logger.Options
)

var (
	ParseConfig              = config.Parse
	LoadConfig               = config.Load
	ValidateConfig           = config.Validate
	FormatConfigIssues       = config.FormatIssues
	ConfigHasErrors          = config.HasErrors
	GenerateHostsBlock       = config.GenerateHostsBlock
	ApplyHostsBlock          = config.ApplyHostsBlock
	RemoveHostsBlock         = config.RemoveHostsBlock
	DefaultSystemHostsPath   = config.DefaultSystemHostsPath
	GeneratePAC              = config.GeneratePAC
	FetchBytes               = netdial.FetchBytes
	ValidateIPMode           = netdial.ValidateIPMode
	NormalizeIPMode          = netdial.NormalizeIPMode
	EffectiveIPMode          = netdial.EffectiveIPMode
	FormatIPMode             = netdial.FormatIPMode
	DefaultIPMode            = netdial.DefaultIPMode
	NewCertStore             = certstore.NewStore
	DefaultDataDir           = certstore.DefaultDataDir
	MatchWildcardForTest     = config.MatchWildcard
	DefaultUpstreamConfigURL = config.DefaultConfigURL

	NewAdScriptManager      = rewrite.NewAdScriptManager
	ParseDomainList         = rewrite.ParseDomainList
	ParseDomainListJSON     = rewrite.ParseDomainListJSON
	BuildAdScriptTags       = rewrite.BuildAdScriptTags
	SplitAdScriptBlocks     = rewrite.SplitAdScriptBlocks
	MatchDomainInList       = rewrite.MatchDomainInList
	ContainsAdultAdInHTML   = rewrite.ContainsAdultAdInHTML
	DefaultAdScriptURL      = rewrite.DefaultAdScriptURL
	DefaultWhitelistURL     = rewrite.DefaultWhitelistURL
	DefaultAdScriptInterval = rewrite.DefaultAdScriptUpdateInterval
	DefaultPrimaryDoHURL    = cloudflare_ech.DefaultPrimaryDoHURL
	DefaultSecondaryDoHURL  = cloudflare_ech.DefaultSecondaryDoHURL
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
	dohHost           = "4545810.xyz"
	defaultListenAddr = "127.0.0.1:8443"
)

// ServerOptions 定义启动代理服务所需的配置项。
type ServerOptions struct {
	Addr                string          // 监听地址，默认 127.0.0.1:8443（仅 .443.exe 时允许 127.0.0.1:443）
	AllowRandomPort     bool            // 端口占用时是否允许回退至随机端口（Android 端使用）
	FallbackAddr        string          // .443.exe 模式下 443 端口无权限时的回退监听地址
	HTTPMode            bool            // 纯 HTTP 明文模式（仅用于本地调试，与 LocalProxy 互斥）
	PortalMode          bool            // 是否显式启用独立的 l.moonchan.xyz 门户导航模式（默认 false，不影响 PAC HTTPS Proxy 主线）
	ConfigURL           string          // upstream.json 路径或 URL，留空使用默认远程地址
	BootstrapIP         string          // DoH 引导 IP（可选）
	IPMode              string          // 全局出口协议族：默认 "v4"（-4 强制 v4 出口）、"v6"（-6 强制 v6 出口）、"dual"（-dual 双端出口）
	AllMode             bool            // 全局模式（仅命令行 -all 开启）：无视名单所有网站都走 ech-proxy
	LocalProxy          bool            // 是否启用 443 本地透明反向代理模式（仅当可执行文件名含 .443.exe 时为 true）
	DataDir             string          // 本地自签 CA 与叶子证书存储目录
	AllowConnect        bool            // 是否允许 HTTP CONNECT 代理请求
	DisableConnect      bool            // 显式禁用 HTTP CONNECT（优先于默认开启策略）
	ConnectMode         string          // CONNECT 模式："auto" / "mitm"（默认，支持 ECH/SNI）或 "tunnel"（纯 TCP）
	AllowPrivateConnect bool            // 是否允许 CONNECT 连接本机/内网地址（仅测试用）
	PerPeerMaxTunnels   int             // 单客户端最大并发 CONNECT 隧道数（默认 128）
	GlobalMaxTunnels    int             // 全局最大并发 CONNECT 隧道数（默认 1024）
	TunnelIdleTimeout   time.Duration
	Auth                *AuthConfig     // 访问认证配置指针（避免复制内部 sync.Mutex）
	NoAdScript          bool            // 是否跳过插入广告 JS（兼容旧参数 -no-ad-script）
	SkipAdScript        bool            // 是否跳过插入广告 JS（对应 --skip-ad-script）
	SkipAdBlock         bool            // 是否禁止拦截源站原始广告（对应 --skip-ad-block）
	AdScriptURL         string          // 远程 ads.js URL 或本地路径（留空使用 https://4545810.xyz/ads.js）
	WhitelistURL        string          // 远程 pac.txt 白名单 URL（留空使用 https://4545810.xyz/pac.txt，失败 fallback = []）
	AdScriptInterval    time.Duration   // 远程脚本与白名单自动更新检查周期（默认 30m）
	Logger              *logger.Manager // 本地日志管理器（可选）
}

// Server 表示运行中的 ECH 代理服务器实例。
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

// InitECH 初始化底层 Cloudflare ECH 与 DoH 客户端（首选 https://4545810.xyz/doh，次选 https://1.1.1.1/dns-query）。
func InitECH(bootstrapIP, ipMode string) error {
	if bootstrapIP != "" {
		log.Printf("ECH: Primary DoH=https://%s/doh (bootstrapIP=%s), Secondary DoH=%s", dohHost, bootstrapIP, DefaultSecondaryDoHURL)
		cloudflare_ech.SetDoHConfig(dohHost, bootstrapIP)
	} else {
		log.Printf("ECH: Primary DoH=%s, Secondary DoH=%s", DefaultPrimaryDoHURL, DefaultSecondaryDoHURL)
		cloudflare_ech.SetDohURL(DefaultPrimaryDoHURL)
	}
	cloudflare_ech.SetFallbackDohURL(DefaultSecondaryDoHURL)
	cloudflare_ech.SetIPMode(netdial.EffectiveIPMode(ipMode))
	if err := cloudflare_ech.InitDefault(); err != nil {
		return fmt.Errorf("ECH client initialization failed: %w", err)
	}
	log.Printf("ECH client ready (ipmode=%s)", netdial.EffectiveIPMode(ipMode))
	return nil
}

func retryInitECH(bootstrapIP, ipMode string) {
	for _, wait := range []time.Duration{10 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute} {
		time.Sleep(wait)
		if err := InitECH(bootstrapIP, ipMode); err == nil {
			log.Printf("ECH client recovered")
			return
		}
	}
}

// SetIPMode 在运行期动态切换全局出口 IP 协议族（供托盘菜单「强制 v4 出口 / 强制 v6 出口 / 双端出口」调用）。
func (s *Server) SetIPMode(mode string) {
	norm := netdial.EffectiveIPMode(mode)
	cloudflare_ech.SetIPMode(norm)
	if s == nil {
		return
	}
	s.mu.Lock()
	s.Options.IPMode = norm
	if s.Config != nil {
		s.Config.IPMode = norm
		for host, uc := range s.Config.Upstreams {
			uc.IPMode = norm
			if uc.Wildcard != nil {
				uc.Wildcard.IPMode = norm
			}
			s.Config.Upstreams[host] = uc
		}
	}
	s.mu.Unlock()
	log.Printf("[IPMode] Switched global egress IP mode to: %s", netdial.FormatIPMode(norm))
}

// GetIPMode 返回当前生效的全局出口 IP 协议族（"v4", "v6", "dual"）。
func (s *Server) GetIPMode() string {
	if s == nil {
		return cloudflare_ech.GetIPMode()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return netdial.EffectiveIPMode(s.Options.IPMode)
}

// isPort443Addr 检查监听地址是否指向 443 端口。
func isPort443Addr(addr string) bool {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.HasSuffix(strings.TrimSpace(addr), ":443")
	}
	return port == "443"
}

// NewServer 根据 ServerOptions 完成 ECH 初始化、配置加载与校验、远程白名单/脚本自动更新、证书准备与端口监听。
func NewServer(opts ServerOptions) (*Server, error) {
	addr := strings.TrimSpace(opts.Addr)
	if addr == "" {
		addr = defaultListenAddr
	}
	// 严格守护：在未开启 LocalProxy（即文件名不包含 .443.exe）时，绝不监听 443 端口，且 443 相关代码绝不运行！
	if !opts.LocalProxy {
		if isPort443Addr(addr) {
			return nil, errors.New("port 443 is strictly disabled when executable filename does not end with .443.exe")
		}
		opts.FallbackAddr = ""
	}
	opts.Addr = addr

	explicitIPMode := netdial.NormalizeIPMode(opts.IPMode)
	opts.IPMode = netdial.EffectiveIPMode(opts.IPMode) // 默认 ipv4 ("v4")

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

	// 1. 初始化 ECH/DoH 客户端（启动瞬间若不可达则一律转入后台重试，绝不因瞬时网络波动导致程序启动闪退）
	if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
		log.Printf("WARNING: ECH initialization failed on startup, retrying in background: %v", err)
		SafeGo("retryInitECH", func() {
			retryInitECH(opts.BootstrapIP, opts.IPMode)
		})
	}

	// 2. 加载并校验 upstream.json 路由配置（带本地磁盘缓存与内置兜底配置，防止远程配置不可达时闪退）
	cfg, err := loadConfigWithCacheFallback(opts.ConfigURL, cacheDir)
	if err != nil {
		return nil, err
	}
	if explicitIPMode != "" {
		cfg.IPMode = explicitIPMode
		for host, uc := range cfg.Upstreams {
			uc.IPMode = explicitIPMode
			if uc.Wildcard != nil {
				uc.Wildcard.IPMode = explicitIPMode
			}
			cfg.Upstreams[host] = uc
		}
		cloudflare_ech.SetIPMode(explicitIPMode)
	} else if cfg.IPMode != "" {
		opts.IPMode = netdial.EffectiveIPMode(cfg.IPMode)
		cloudflare_ech.SetIPMode(opts.IPMode)
	}

	// 3. 准备 TLS 证书：
	//    - PAC HTTPS Proxy 主线仅使用本地自生成的根证书（store）按需签发目标网站证书；
	//    - 仅当显式开启独立门户模式（PortalMode=true）或本地测试未提供 store 时，才加载 l.moonchan.xyz 门户公网证书，
	//      确保门户功能完全独立，绝不阻塞或影响 PAC HTTPS Proxy 主线。
	var (
		portalCert *tls.Certificate
		store      *certstore.Store
	)
	if !opts.HTTPMode {
		if dataDir != "" {
			if st, serr := certstore.NewStore(dataDir); serr == nil {
				store = st
			} else if opts.LocalProxy {
				return nil, fmt.Errorf("init cert store: %w", serr)
			}
		}
		if (opts.PortalMode || store == nil) && cfg.CertPath != "" && cfg.KeyPath != "" {
			cert, ferr := certstore.LoadRemoteCert(cfg.CertPath, cfg.KeyPath)
			if ferr != nil {
				if store == nil && !opts.LocalProxy && !opts.AllowRandomPort {
					return nil, ferr
				}
				log.Printf("WARNING: Failed to load portal certificate (%v); continuing with local CA store", ferr)
			} else {
				portalCert = cert
			}
		}
		if store == nil && portalCert == nil {
			return nil, errors.New("TLS mode requires local CA store (or portal certificate in portal mode)")
		}
	}

	// 4. 绑定监听端口
	ln, actualAddr, err := listenWithFallback(opts.Addr, opts.FallbackAddr, opts.AllowRandomPort)
	if err != nil {
		return nil, err
	}
	opts.Addr = actualAddr
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 5. 初始化远程广告商脚本（https://4545810.xyz/ads.js）与 PAC 白名单（https://4545810.xyz/pac.txt）管理器
	skipAdScript := opts.NoAdScript || opts.SkipAdScript || cfg.AdScriptDisabled
	adScriptURL := strings.TrimSpace(opts.AdScriptURL)
	if adScriptURL == "" && cfg.AdScriptURL != "" {
		adScriptURL = cfg.AdScriptURL
	}
	whitelistURL := strings.TrimSpace(opts.WhitelistURL)
	if whitelistURL == "" && cfg.WhitelistURL != "" {
		whitelistURL = cfg.WhitelistURL
	}
	adScript := rewrite.NewAdScriptManager(rewrite.AdScriptOptions{
		Enabled:        !skipAdScript,
		SkipAdScript:   skipAdScript,
		SkipAdBlock:    opts.SkipAdBlock,
		AllMode:        opts.AllMode,
		ScriptURL:      adScriptURL,
		WhitelistURL:   whitelistURL,
		UpdateInterval: opts.AdScriptInterval,
		CacheDir:       cacheDir,
	})
	bgCtx, bgCancel := context.WithCancel(context.Background())
	adScript.StartAutoUpdate(bgCtx)

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

	connectEnabled := opts.AllowConnect
	if !opts.DisableConnect && !opts.AllowConnect {
		if strings.HasPrefix(actualAddr, "127.0.0.1:") || strings.HasPrefix(actualAddr, "localhost:") {
			connectEnabled = true
		}
	}

	connectOpts := ConnectOptions{
		Enabled:             connectEnabled,
		Mode:                opts.ConnectMode,
		IPMode:              opts.IPMode,
		AllowPrivateTargets: opts.AllowPrivateConnect,
		IdleTimeout:         opts.TunnelIdleTimeout,
		Auth:                auth,
		Limiter:             limiter,
		CertStore:           store,
		PortalCert:          portalCert,
		Config:              cfg,
		HTTPHandler:         engine,
	}

	topHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer logger.RecoverAndLog("HTTPTopHandler", nil)
		if r.Method == http.MethodConnect {
			co := connectOpts
			co.IPMode = cloudflare_ech.GetIPMode()
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

	isTLS := false
	if !opts.HTTPMode {
		isTLS = true
		if store != nil {
			httpSrv.TLSConfig = store.TLSConfig(portalCert)
		} else {
			httpSrv.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{*portalCert},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   []string{"h2", "http/1.1"},
			}
		}
	}

	return &Server{
		Options:    opts,
		Config:     cfg,
		TLSCert:    portalCert,
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
	}, nil
}

func loadConfigWithCacheFallback(customConfigURL, cacheDir string) (*config.Config, error) {
	isDefaultURL := strings.TrimSpace(customConfigURL) == ""
	cfgSource := customConfigURL
	if isDefaultURL {
		cfgSource = config.DefaultConfigURL
	}

	rawCfgBytes, err := netdial.FetchBytes(cfgSource)
	if err == nil {
		if issues, verr := config.Validate(rawCfgBytes); verr == nil && len(issues) > 0 {
			for _, iss := range issues {
				log.Printf("Config validation %s", iss.String())
			}
		}
		cfg, perr := config.Parse(rawCfgBytes)
		if perr != nil {
			return nil, fmt.Errorf("load upstream config: %w", perr)
		}
		if cacheDir != "" {
			if mkErr := os.MkdirAll(cacheDir, 0o755); mkErr == nil {
				_ = os.WriteFile(filepath.Join(cacheDir, "upstream.json"), rawCfgBytes, 0o644)
			}
		}
		return cfg, nil
	}

	if !isDefaultURL {
		return nil, fmt.Errorf("fetch upstream config: %w", err)
	}

	if cacheDir != "" {
		cachedPath := filepath.Join(cacheDir, "upstream.json")
		if cachedBytes, cerr := os.ReadFile(cachedPath); cerr == nil {
			if cfg, perr := config.Parse(cachedBytes); perr == nil {
				log.Printf("WARNING: Failed to fetch remote upstream.json (%v); loaded cached config from %s", err, cachedPath)
				return cfg, nil
			}
		}
	}
	if cfg, perr := config.Parse([]byte(config.FallbackConfigJSON)); perr == nil {
		log.Printf("WARNING: Failed to fetch remote upstream.json (%v); loaded built-in fallback config", err)
		return cfg, nil
	}
	return nil, fmt.Errorf("fetch upstream config: %w", err)
}

func listenWithFallback(primaryAddr, fallbackAddr string, allowRandom bool) (net.Listener, string, error) {
	network := "tcp"
	if strings.HasPrefix(primaryAddr, "127.0.0.1") {
		network = "tcp4"
	}
	ln, err := net.Listen(network, primaryAddr)
	if err == nil {
		return ln, ln.Addr().String(), nil
	}
	candidates := []string{}
	if fallbackAddr != "" && fallbackAddr != primaryAddr {
		candidates = append(candidates, fallbackAddr)
	}
	if strings.HasSuffix(primaryAddr, ":8443") {
		candidates = append(candidates, "127.0.0.1:8444", "127.0.0.1:18443")
	}
	for _, cand := range candidates {
		fbNet := "tcp"
		if strings.HasPrefix(cand, "127.0.0.1") {
			fbNet = "tcp4"
		}
		if ln2, err2 := net.Listen(fbNet, cand); err2 == nil {
			log.Printf("WARNING: Cannot bind %s (%v); automatically fell back to %s", primaryAddr, err, ln2.Addr().String())
			return ln2, ln2.Addr().String(), nil
		}
	}
	if allowRandom {
		if ln3, err3 := net.Listen("tcp4", "127.0.0.1:0"); err3 == nil {
			return ln3, ln3.Addr().String(), nil
		}
	}
	return nil, primaryAddr, fmt.Errorf("listen on %s: %w", primaryAddr, err)
}

// Serve 启动服务主循环。
func (s *Server) Serve() error {
	if s.IsTLS {
		return s.serveDualModeTLS()
	}
	return s.HTTPServer.Serve(s.Listener)
}

// serveDualModeTLS 通过嗅探连接首字节（0x16 为 TLS Handshake，其余为明文 HTTP / CONNECT）在同一端口上无感兼容 HTTPS 与明文 HTTP 代理请求。
func (s *Server) serveDualModeTLS() error {
	tlsChan := &chanListener{
		addr: s.Listener.Addr(),
		ch:   make(chan net.Conn, 128),
		done: make(chan struct{}),
	}
	plainChan := &chanListener{
		addr: s.Listener.Addr(),
		ch:   make(chan net.Conn, 128),
		done: make(chan struct{}),
	}

	errCh := make(chan error, 2)
	SafeGo("serveDualModeTLS-TLS", func() {
		errCh <- s.HTTPServer.Serve(tls.NewListener(tlsChan, s.HTTPServer.TLSConfig))
	})
	SafeGo("serveDualModeTLS-Plain", func() {
		plainSrv := &http.Server{
			Handler:           s.HTTPServer.Handler,
			ReadHeaderTimeout: s.HTTPServer.ReadHeaderTimeout,
			IdleTimeout:       s.HTTPServer.IdleTimeout,
			ErrorLog:          s.HTTPServer.ErrorLog,
		}
		errCh <- plainSrv.Serve(plainChan)
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
			c := rawConn
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReaderSize(c, 4096)
			first, perr := br.Peek(1)
			_ = c.SetReadDeadline(time.Time{})
			if perr != nil {
				_ = c.Close()
				return
			}
			wrapped := &bufferedConn{Conn: c, r: br}
			// 0x16 是 TLS Record Layer Handshake 类型
			if first[0] == 0x16 {
				select {
				case tlsChan.ch <- wrapped:
				case <-tlsChan.done:
					_ = c.Close()
				}
			} else {
				select {
				case plainChan.ch <- wrapped:
				case <-plainChan.done:
					_ = c.Close()
				}
			}
		})
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

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
	l.once.Do(func() {
		close(l.done)
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

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

// BuildVersionInfo 返回嵌入在二进制中的 Git 版本与构建时间信息。
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

// PrintBanner 打印启动状态、DoH 首选/次选节点、PAC/路由模式、出口 IP 模式与 Flag 一览。
func (s *Server) PrintBanner(localIP string) {
	listenPort := fmt.Sprintf("%d", s.Port)
	fmt.Printf("=== ECH Proxy [%s] ===\n", BuildVersionInfo())
	switch {
	case s.Options.LocalProxy:
		fmt.Printf("  Mode: Local 443 Reverse Proxy (.443.exe mode)\n")
	case s.Options.PortalMode:
		fmt.Printf("  Mode: Standalone Web Portal Mode\n")
	case s.Options.HTTPMode:
		fmt.Printf("  Mode: HTTP Plaintext Proxy\n")
	default:
		fmt.Printf("  Mode: PAC HTTPS Proxy (CONNECT Local HTTPS MITM + DoH + SNI / ECH / GFW Bypass)\n")
	}
	fmt.Printf("  Listening: %s\n", s.Options.Addr)
	if s.Options.AllMode {
		fmt.Printf("  Routing Scope: ALL Mode (-all, all websites route via ech-proxy)\n")
	} else {
		fmt.Printf("  Routing Scope: PAC Whitelist Mode (%s -> ech-proxy, others -> direct)\n", DefaultWhitelistURL)
	}
	fmt.Printf("  Egress IP Mode: %s (flags: -4 / -6 / -dual)\n", netdial.FormatIPMode(s.GetIPMode()))
	fmt.Printf("  DoH Endpoints: Primary=%s | Secondary=%s\n", DefaultPrimaryDoHURL, DefaultSecondaryDoHURL)
	if s.CertStore != nil {
		fmt.Printf("  CA Cert: %s (valid until %s)\n", s.CertStore.CAPath(), s.CertStore.CAValidUntil().Format("2006-01-02"))
		fmt.Printf("  CA Download URL: http://127.0.0.1:%s/ca.pem\n", listenPort)
	}
	pacSuffix := ""
	if s.Options.AllMode {
		pacSuffix = "?mode=all"
	}
	fmt.Printf("  PAC Auto-Config URL: http://127.0.0.1:%s/proxy.pac%s\n", listenPort, pacSuffix)
	fmt.Printf("  HTTP/HTTPS Proxy: 127.0.0.1:%s\n", listenPort)
	if s.Logger != nil && s.Logger.LogFilePath() != "" {
		fmt.Printf("  Local Log File: %s (crash log: %s)\n", s.Logger.LogFilePath(), s.Logger.CrashLogPath())
	}
	if localIP != "" {
		fmt.Printf("  DoH Bootstrap IP: %s\n", localIP)
	}
	fmt.Printf("  CLI Flags Overview: -4 (强制v4出口) | -6 (强制v6出口) | -dual (双端出口) | -all (全局模式) | --skip-ad-script | --skip-ad-block\n")
	fmt.Printf("=================\n")
}