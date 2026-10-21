// Package echproxy 组装各语义子模块（config, certstore, ech, rewrite, cookie, netdial）：
//   - 支持一键 PAC / HTTP CONNECT 正向代理（Smart MITM ECH/SNI 终结，无需改 hosts、无需 443 权限即可全量代理）；
//   - 支持 l.moonchan.xyz 及 *.l.moonchan.xyz 公网证书门户导航与子域反代；
//   - 支持本地 443 透明反向代理模式（hosts -> 127.0.0.1 + 本地自签 CA 动态签发证书 + 自动 SNI/ECH 转发）。
package echproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/certstore"
	"github.com/Hana-ame/ech-proxy/echproxy/config"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
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
	NewCertStore             = certstore.NewStore
	DefaultDataDir           = certstore.DefaultDataDir
	MatchWildcardForTest     = config.MatchWildcard
	DefaultUpstreamConfigURL = config.DefaultConfigURL
)

const (
	dohHost           = "moonchan.xyz"
	defaultListenAddr = "127.0.0.1:8443"
)

// ServerOptions 定义启动代理服务所需的配置项。
type ServerOptions struct {
	Addr                string     // 监听地址，默认 127.0.0.1:8443（443 模式为 127.0.0.1:443）
	AllowRandomPort     bool       // 端口占用时是否允许回退至随机端口（Android 端使用）
	FallbackAddr        string     // 443 端口无权限或被占用时的回退监听地址（如 127.0.0.1:8443）
	HTTPMode            bool       // 纯 HTTP 明文模式（仅用于本地调试，与 LocalProxy 互斥）
	ConfigURL           string     // upstream.json 路径或 URL，留空使用默认远程地址
	BootstrapIP         string     // DoH 引导 IP（可选）
	IPMode              string     // 全局出口协议族锁定："v4" 或 "v6"（可选）
	LocalProxy          bool       // 是否启用 443 本地透明反向代理模式
	DataDir             string     // 本地自签 CA 与叶子证书存储目录
	AllowConnect        bool       // 是否允许 HTTP CONNECT 代理请求
	DisableConnect      bool       // 显式禁用 HTTP CONNECT（优先于默认开启策略）
	ConnectMode         string     // CONNECT 模式："auto" / "mitm"（默认，支持 ECH/SNI）或 "tunnel"（纯 TCP）
	AllowPrivateConnect bool       // 是否允许 CONNECT 连接本机/内网地址（仅测试用）
	PerPeerMaxTunnels   int        // 单客户端最大并发 CONNECT 隧道数（默认 128）
	GlobalMaxTunnels    int        // 全局最大并发 CONNECT 隧道数（默认 1024）
	TunnelIdleTimeout   time.Duration
	Auth                AuthConfig // 访问认证配置（可选）
}

// Server 表示运行中的 ECH 代理服务器实例。
type Server struct {
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
}

// InitECH 初始化底层 Cloudflare ECH 与 DoH 客户端。
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
	if err := cloudflare_ech.InitDefault(); err != nil {
		return fmt.Errorf("ECH client initialization failed: %w", err)
	}
	log.Printf("ECH client ready")
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

// NewServer 根据 ServerOptions 完成 ECH 初始化、配置加载与校验、双轨证书准备与端口监听。
func NewServer(opts ServerOptions) (*Server, error) {
	opts.IPMode = netdial.NormalizeIPMode(opts.IPMode)

	// 1. 初始化 ECH/DoH 客户端（启动瞬间若不可达则转入后台重试，不阻塞本地 SNI/Direct 流量）
	if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
		if opts.LocalProxy || opts.AllowRandomPort {
			log.Printf("WARNING: ECH initialization failed, retrying in background: %v", err)
			go retryInitECH(opts.BootstrapIP, opts.IPMode)
		} else {
			return nil, err
		}
	}

	// 2. 加载并校验 upstream.json 路由配置
	cfgSource := opts.ConfigURL
	if cfgSource == "" {
		cfgSource = config.DefaultConfigURL
	}
	rawCfgBytes, err := netdial.FetchBytes(cfgSource)
	if err != nil {
		return nil, fmt.Errorf("fetch upstream config: %w", err)
	}
	if issues, verr := config.Validate(rawCfgBytes); verr == nil && len(issues) > 0 {
		for _, iss := range issues {
			log.Printf("Config validation %s", iss.String())
		}
	}
	cfg, err := config.Parse(rawCfgBytes)
	if err != nil {
		return nil, fmt.Errorf("load upstream config: %w", err)
	}
	if opts.IPMode == "" && cfg.IPMode != "" {
		opts.IPMode = cfg.IPMode
		cloudflare_ech.SetIPMode(opts.IPMode)
	}

	// 3. 准备双轨 TLS 证书：
	//    - l.moonchan.xyz 及 *.l.moonchan.xyz 使用公网证书（portalCert）
	//    - 其余所有通过 hosts=127.0.0.1 或 CONNECT MITM 接入的域名使用本地自签 CA 动态签发证书（store）
	var (
		portalCert *tls.Certificate
		store      *certstore.Store
	)
	if !opts.HTTPMode {
		if cfg.CertPath != "" && cfg.KeyPath != "" {
			cert, ferr := certstore.LoadRemoteCert(cfg.CertPath, cfg.KeyPath)
			if ferr != nil {
				if !opts.LocalProxy && !opts.AllowRandomPort {
					return nil, ferr
				}
				log.Printf("WARNING: Failed to load portal certificate: %v", ferr)
			} else {
				portalCert = cert
			}
		}
		dataDir := opts.DataDir
		if dataDir == "" {
			dataDir, _ = certstore.DefaultDataDir()
		}
		if dataDir != "" {
			if st, serr := certstore.NewStore(dataDir); serr == nil {
				store = st
			} else if opts.LocalProxy {
				return nil, fmt.Errorf("init cert store: %w", serr)
			}
		}
		// 修复 Issue #7：非 HTTP 模式下绝不静默降级为明文 HTTP
		if store == nil && portalCert == nil {
			return nil, errors.New("TLS mode requires either portal certificate or local CA store (use -http for plaintext mode)")
		}
	}

	// 4. 绑定监听端口（支持 443 权限不足/冲突时平滑回退到 FallbackAddr 或随机端口）
	addr := opts.Addr
	if addr == "" {
		addr = defaultListenAddr
	}
	ln, actualAddr, err := listenWithFallback(addr, opts.FallbackAddr, opts.AllowRandomPort)
	if err != nil {
		return nil, err
	}
	opts.Addr = actualAddr
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	auth := opts.Auth
	limiter := NewTunnelLimiter(opts.PerPeerMaxTunnels, opts.GlobalMaxTunnels)

	engine := NewEngineWithOptions(EngineOptions{
		Config:    cfg,
		CertStore: store,
		Auth:      &auth,
		Limiter:   limiter,
		Port:      port,
	})

	connectEnabled := opts.AllowConnect
	if !opts.DisableConnect && !opts.AllowConnect {
		// 默认在绑定本机回环地址时开启智能 CONNECT 支持，若显式设置了 AllowConnect/DisableConnect 则按设置执行
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
		Auth:                &auth,
		Limiter:             limiter,
		CertStore:           store,
		PortalCert:          portalCert,
		Config:              cfg,
		HTTPHandler:         engine,
	}

	topHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleHTTPConnect(w, r, connectOpts)
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
		Auth:       &auth,
		Limiter:    limiter,
	}, nil
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
	if fallbackAddr != "" && fallbackAddr != primaryAddr {
		fbNet := "tcp"
		if strings.HasPrefix(fallbackAddr, "127.0.0.1") {
			fbNet = "tcp4"
		}
		if ln2, err2 := net.Listen(fbNet, fallbackAddr); err2 == nil {
			log.Printf("WARNING: Cannot bind %s (%v); automatically fell back to %s (use PAC http://%s/proxy.pac or run as Administrator/root for port 443)", primaryAddr, err, ln2.Addr().String(), ln2.Addr().String())
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

// Serve 启动服务主循环。在 TLS 模式下使用支持明文 HTTP CONNECT / PAC 与 TLS 自动分流的双模 Listener，
// 使得同一端口（如 8443）既能直接作为浏览器 HTTP/HTTPS 正向代理与 PAC 服务器，又能直接响应 HTTPS 访问！
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
	go func() {
		errCh <- s.HTTPServer.Serve(tls.NewListener(tlsChan, s.HTTPServer.TLSConfig))
	}()
	go func() {
		plainSrv := &http.Server{
			Handler:           s.HTTPServer.Handler,
			ReadHeaderTimeout: s.HTTPServer.ReadHeaderTimeout,
			IdleTimeout:       s.HTTPServer.IdleTimeout,
			ErrorLog:          s.HTTPServer.ErrorLog,
		}
		errCh <- plainSrv.Serve(plainChan)
	}()

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
		go func(c net.Conn) {
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
		}(rawConn)
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
	go func() {
		if err := s.Serve(); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.Listener != nil {
		_ = s.Listener.Close()
	}
	if s.HTTPServer != nil {
		return s.HTTPServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) Close() error {
	if s.Listener != nil {
		_ = s.Listener.Close()
	}
	if s.HTTPServer != nil {
		return s.HTTPServer.Close()
	}
	return nil
}

// BuildVersionInfo 返回嵌入在二进制中的 Git 版本与构建时间信息（修复 Issue #4 防止误跑旧二进制）。
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

// PrintBanner 打印启动状态、三种接入方式指引与路由表信息。
func (s *Server) PrintBanner(localIP string) {
	listenPort := fmt.Sprintf("%d", s.Port)
	fmt.Printf("=== ECH Proxy [%s] ===\n", BuildVersionInfo())
	switch {
	case s.Options.LocalProxy:
		fmt.Printf("  Mode: Local Reverse Proxy (443 TLS + Smart CONNECT/PAC, self-generated CA + auto SNI/ECH)\n")
	case s.Options.HTTPMode:
		fmt.Printf("  Mode: HTTP Plaintext Proxy\n")
	default:
		fmt.Printf("  Mode: Unified Smart Proxy (Portal + HTTP/HTTPS CONNECT MITM + Auto SNI/ECH)\n")
	}
	fmt.Printf("  Listening: %s\n", s.Options.Addr)
	if s.CertStore != nil {
		fmt.Printf("  CA Cert: %s (valid until %s)\n", s.CertStore.CAPath(), s.CertStore.CAValidUntil().Format("2006-01-02"))
		fmt.Printf("  CA Download URL: http://127.0.0.1:%s/ca.pem\n", listenPort)
	}
	fmt.Printf("  PAC Auto-Config URL: http://127.0.0.1:%s/proxy.pac\n", listenPort)
	fmt.Printf("  HTTP/HTTPS Proxy: 127.0.0.1:%s\n", listenPort)
	if localIP != "" {
		fmt.Printf("  DoH Bootstrap IP: %s\n", localIP)
	}
	if s.Options.IPMode != "" {
		fmt.Printf("  IP Mode: %s (pinned)\n", s.Options.IPMode)
	} else {
		fmt.Printf("  IP Mode: auto\n")
	}

	domains := s.Config.UpstreamOrder
	if len(domains) == 0 {
		for h := range s.Config.Upstreams {
			domains = append(domains, h)
		}
	}
	for _, d := range domains {
		uc, ok := s.Config.Upstreams[d]
		if !ok {
			continue
		}
		fmt.Printf("  Domain: %s:%s -> %s (%s)", d, listenPort, uc.Host, ModeName(uc.Mode))
		if w := uc.Wildcard; w != nil {
			fmt.Printf(" [+wildcard %s*%s:%s -> *%s]", w.Prefix, w.EntrySuffix, listenPort, w.UpstreamSuffix)
		}
		fmt.Println()
	}
	fmt.Printf("=================\n")
}