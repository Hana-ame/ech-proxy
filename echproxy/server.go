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

	"github.com/gin-gonic/gin"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
)

// DefaultUpstreamConfigURL 是默认的远程上游配置地址（全局单一可信源）。
const DefaultUpstreamConfigURL = "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/upstream.json?proxy_host=raw.githubusercontent.com"

// ServerOptions 封装启动 ECH 代理服务器所需的参数。
type ServerOptions struct {
	Addr            string // 监听地址，默认为 "127.0.0.1:8443"
	AllowRandomPort bool   // 若 Addr 指定端口被占用，是否回退到随机可用端口（Android 等移动端场景）
	HTTPMode        bool   // 是否强制 HTTP 模式（不启用 TLS）
	ConfigURL       string // upstream.json 远程地址，若为空则使用 DefaultUpstreamConfigURL
	BootstrapIP     string // DoH bootstrap IP (可选)
	IPMode          string // "v4" / "v6" 偏好 (可选)
}

// Server 代表一个运行中的 ECH 代理服务器实例。
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

// InitECH 初始化底层的 Cloudflare ECH 与 DoH 客户端。
func InitECH(bootstrapIP, ipMode string) error {
	if bootstrapIP != "" {
		log.Printf("ECH: DoH=moonchan.xyz, bootstrapIP=%s", bootstrapIP)
		cloudflare_ech.SetDoHConfig("moonchan.xyz", bootstrapIP)
	} else {
		log.Printf("ECH: DoH=https://moonchan.xyz/doh")
		cloudflare_ech.SetDohURL("https://moonchan.xyz/doh")
	}

	if ipMode != "" {
		cloudflare_ech.SetIPMode(ipMode)
	}

	v4ok, v6ok := cloudflare_ech.CheckDualStack(context.Background())
	if v4ok || v6ok {
		suffix := ""
		if ipMode != "" {
			suffix = " (强制 " + ipMode + ")"
		}
		log.Printf("IP 栈检测: IPv4=%v IPv6=%v%s", v4ok, v6ok, suffix)
	} else {
		log.Printf("IP 栈检测失败（DNS 不可达）")
	}

	log.Printf("正在初始化 ECH 客户端...")
	if err := cloudflare_ech.InitDefault(); err != nil {
		return fmt.Errorf("ECH 客户端初始化失败: %w", err)
	}
	log.Printf("ECH 客户端就绪")
	return nil
}

// LoadTLSCert 根据配置中的 CertPath 和 KeyPath 动态获取并解析 TLS 证书密钥对。
func LoadTLSCert(cfg *Config) (*tls.Certificate, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("配置中缺少 cert_path 或 key_path")
	}
	log.Printf("正在拉取证书: %s", cfg.CertPath)
	certPEM, err := FetchBytes(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("拉取证书失败: %w", err)
	}
	log.Printf("正在拉取密钥: %s", cfg.KeyPath)
	keyPEM, err := FetchBytes(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("拉取密钥失败: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书密钥失败: %w", err)
	}
	log.Printf("证书加载成功")
	return &cert, nil
}

// NewEngine 创建并配置包含 Recovery、CORS 及 SetupRouter 的标准 Gin 引擎。
func NewEngine(cfg *Config) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(CORSMiddleware())
	SetupRouter(r, cfg)
	return r
}

// NewServer 根据给定的 ServerOptions 完成全套初始化流程并绑定端口。
func NewServer(opts ServerOptions) (*Server, error) {
	// 1. 初始化 ECH 网络客户端
	if err := InitECH(opts.BootstrapIP, opts.IPMode); err != nil {
		return nil, err
	}

	// 2. 加载远程上游配置
	configURL := opts.ConfigURL
	if configURL == "" {
		configURL = DefaultUpstreamConfigURL
	}
	log.Printf("正在加载上游配置: %s", configURL)
	cfg, err := LoadConfig(configURL)
	if err != nil {
		return nil, fmt.Errorf("加载上游配置失败: %w", err)
	}
	log.Printf("上游配置加载成功: %d 条规则", len(cfg.Upstreams))

	// 3. 非 HTTP 模式下拉取 TLS 证书
	var tlsCert *tls.Certificate
	if !opts.HTTPMode && cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, err := LoadTLSCert(cfg)
		if err != nil {
			if !opts.AllowRandomPort {
				// 桌面版严格报错
				return nil, err
			}
			log.Printf("加载证书失败，将降级运行: %v", err)
		} else {
			tlsCert = cert
		}
	}

	// 4. 构建统一 Gin 路由引擎
	engine := NewEngine(cfg)

	// 5. 绑定网络监听
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:8443"
	}
	network := "tcp"
	if strings.HasPrefix(addr, "127.0.0.1") {
		network = "tcp4"
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		if opts.AllowRandomPort {
			log.Printf("地址 %s 占用或不可用, 尝试随机端口...", addr)
			ln, err = net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, fmt.Errorf("随机端口监听失败: %w", err)
			}
		} else {
			return nil, fmt.Errorf("监听 %s 失败: %w", addr, err)
		}
	}

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	// 6. 构建 http.Server
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

// Serve 开始提供 HTTP/HTTPS 服务（阻塞调用）。
func (s *Server) Serve() error {
	if s.IsTLS {
		tlsLn := tls.NewListener(s.Listener, s.HTTPServer.TLSConfig)
		return s.HTTPServer.Serve(tlsLn)
	}
	return s.HTTPServer.Serve(s.Listener)
}

// ServeAsync 在后台 goroutine 中启动服务。
func (s *Server) ServeAsync() error {
	go func() {
		if err := s.Serve(); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()
	return nil
}

// Shutdown 优雅关闭服务器。
func (s *Server) Shutdown(ctx context.Context) error {
	if s.HTTPServer != nil {
		return s.HTTPServer.Shutdown(ctx)
	}
	return nil
}

// Close 立即关闭服务器。
func (s *Server) Close() error {
	if s.HTTPServer != nil {
		return s.HTTPServer.Close()
	}
	return nil
}

// PrintBanner 按照 orderedmap 记录的 upstream 书写顺序打印启动 Banner（严格按配置顺序，不自行排序）。
func (s *Server) PrintBanner(localIP string) {
	listenPort := fmt.Sprintf("%d", s.Port)
	fmt.Printf("=== ECH Proxy ===\n")
	fmt.Printf("  模式: %s\n", map[bool]string{true: "HTTP (本地代理)", false: "TLS (远程)"}[s.Options.HTTPMode])
	fmt.Printf("  监听: %s\n", s.Options.Addr)
	if localIP != "" {
		fmt.Printf("  DoH IP: %s\n", localIP)
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
		fmt.Printf("  域名: %s -> %s (%s)", entry, uc.Host, ModeName(uc.Mode))
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
			fmt.Printf(" [+通配 %s -> *%s]", we, w.UpstreamSuffix)
		}
		fmt.Println()
	}
	fmt.Printf("=================\n")
}
