// Package echproxy 组装各语义子模块（config, certstore, ech, rewrite, cookie, netdial），
// 对外提供统一的服务管理入口，支持两大核心运行模式：
//  1. 8443 门户反向代理模式（默认）：加载公网证书，提供导航门户与代理子域名访问。
//  2. 443 本地透明反向代理模式（-local 或 .443.exe）：本机自签 CA 动态签发域名证书，配合 hosts 原网址直连。
package echproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/certstore"
	"github.com/Hana-ame/ech-proxy/echproxy/config"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/gin-gonic/gin"
)

// 导出常用类型与函数别名，保持与桌面端/Android 端调用方的完全兼容。
type (
	Config         = config.Config
	UpstreamConfig = config.UpstreamConfig
	UpstreamMap    = config.UpstreamMap
	WildcardRule   = config.WildcardRule
	CertStore      = certstore.Store
)

var (
	ParseConfig             = config.Parse
	LoadConfig              = config.Load
	FetchBytes              = netdial.FetchBytes
	NewCertStore            = certstore.NewStore
	DefaultDataDir          = certstore.DefaultDataDir
	MatchWildcardForTest    = config.MatchWildcard
	DefaultUpstreamConfigURL = config.DefaultConfigURL
)

const (
	dohHost           = "moonchan.xyz"
	defaultListenAddr = "127.0.0.1:8443"
)

// ServerOptions 定义启动代理服务所需的配置项。
type ServerOptions struct {
	Addr            string // 监听地址，默认 127.0.0.1:8443（本地反代模式为 127.0.0.1:443）
	AllowRandomPort bool   // 端口占用时是否允许回退至随机端口（Android 端使用）
	HTTPMode        bool   // 纯 HTTP 明文模式（仅用于本地调试，与 LocalProxy 互斥）
	ConfigURL       string // upstream.json 路径或 URL，留空使用默认远程地址
	BootstrapIP     string // DoH 引导 IP（可选）
	IPMode          string // 全局出口协议族锁定："v4" 或 "v6"（可选）
	LocalProxy      bool   // 是否启用 443 本地透明反向代理模式（自生成 CA + 按需签发原域名证书）
	DataDir         string // 443 本地模式的 CA 与叶子证书存储目录
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

// NewServer 根据 ServerOptions 完成 ECH 初始化、配置加载、证书准备与端口监听。
func NewServer(opts ServerOptions) (*Server, error) {
	// 1. 初始化 ECH 隧道客户端（443 本地模式下若启动瞬间网络不可达则转入后台重试）
	if opts.LocalProxy {
		if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
			log.Printf("WARNING: ECH initialization failed, retrying in background: %v", err)
			go retryInitECH(opts.BootstrapIP, opts.IPMode)
		}
	} else if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
		return nil, err
	}

	// 2. 加载 upstream.json 路由配置
	cfg, err := config.Load(opts.ConfigURL)
	if err != nil {
		return nil, fmt.Errorf("load upstream config: %w", err)
	}

	// 3. 准备 TLS 证书：
	//    - 443 本地模式：初始化本机自签名 CA，同时尝试加载门户公网证书供 l.moonchan.xyz 使用
	//    - 8443 门户模式：加载配置的公网证书
	var (
		tlsCert   *tls.Certificate
		store     *certstore.Store
	)
	if opts.LocalProxy {
		dataDir := opts.DataDir
		if dataDir == "" {
			var derr error
			if dataDir, derr = certstore.DefaultDataDir(); derr != nil {
				return nil, derr
			}
		}
		st, serr := certstore.NewStore(dataDir)
		if serr != nil {
			return nil, fmt.Errorf("init cert store: %w", serr)
		}
		store = st
		if cfg.CertPath != "" && cfg.KeyPath != "" {
			tlsCert, _ = certstore.LoadRemoteCert(cfg.CertPath, cfg.KeyPath)
		}
	} else if !opts.HTTPMode && cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, ferr := certstore.LoadRemoteCert(cfg.CertPath, cfg.KeyPath)
		if ferr != nil {
			if !opts.AllowRandomPort {
				return nil, ferr
			}
			log.Printf("Failed to load certificate, degrading to HTTP: %v", ferr)
		} else {
			tlsCert = cert
		}
	}

	// 4. 构建路由引擎并绑定端口
	engine := NewEngine(cfg)
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
			ln, err = net.Listen("tcp4", "127.0.0.1:0")
		}
		if err != nil {
			return nil, fmt.Errorf("listen on %s: %w", addr, err)
		}
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	httpSrv := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	isTLS := false
	if opts.LocalProxy {
		isTLS = true
		httpSrv.TLSConfig = store.TLSConfig(indexHost, tlsCert)
	} else if !opts.HTTPMode && tlsCert != nil {
		isTLS = true
		httpSrv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	return &Server{
		Options:    opts,
		Config:     cfg,
		TLSCert:    tlsCert,
		CertStore:  store,
		Engine:     engine,
		HTTPServer: httpSrv,
		Listener:   ln,
		Port:       port,
		IsTLS:      isTLS,
	}, nil
}

func (s *Server) Serve() error {
	if s.IsTLS {
		return s.HTTPServer.Serve(tls.NewListener(s.Listener, s.HTTPServer.TLSConfig))
	}
	return s.HTTPServer.Serve(s.Listener)
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
	if s.HTTPServer != nil {
		return s.HTTPServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) Close() error {
	if s.HTTPServer != nil {
		return s.HTTPServer.Close()
	}
	return nil
}

// PrintBanner 打印启动状态与路由表信息。
func (s *Server) PrintBanner(localIP string) {
	listenPort := fmt.Sprintf("%d", s.Port)
	fmt.Printf("=== ECH Proxy ===\n")
	switch {
	case s.Options.LocalProxy:
		fmt.Printf("  Mode: Local Reverse Proxy (443 TLS, self-generated CA)\n")
	case s.Options.HTTPMode:
		fmt.Printf("  Mode: HTTP (Local Proxy)\n")
	default:
		fmt.Printf("  Mode: Portal Reverse Proxy (8443 TLS)\n")
	}
	fmt.Printf("  Listening: %s\n", s.Options.Addr)
	if s.Options.LocalProxy && s.CertStore != nil {
		fmt.Printf("  CA Cert: %s (valid until %s)\n", s.CertStore.CAPath(), s.CertStore.CAValidUntil().Format("2006-01-02"))
		fmt.Printf("  Data Dir: %s\n", s.CertStore.DataDir)
	}
	if localIP != "" {
		fmt.Printf("  DoH Bootstrap IP: %s\n", localIP)
	}
	if s.Options.IPMode != "" {
		fmt.Printf("  IP Mode: %s\n", s.Options.IPMode)
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
