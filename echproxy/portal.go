package echproxy

import (
	_ "embed"
	"encoding/json"
	"html"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/certstore"
	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

//go:embed assets/index.html
var indexHTML string

const (
	indexHost   = "l.moonchan.xyz"
	defaultPort = "8443"
)

// EngineOptions 定义创建路由引擎时的可选扩展组件（本地 CA、CONNECT 限流器、认证策略、远程广告脚本/白名单与本地日志器等）。
type EngineOptions struct {
	Config    *config.Config
	CertStore *certstore.Store
	Auth      *AuthConfig
	Limiter   *TunnelLimiter
	AdScript  *rewrite.AdScriptManager
	Logger    *logger.Manager
	AllMode   bool
	IPMode    string
	Port      uint16
}

// NewEngine 构建并配置 Gin 路由引擎，同时服务 8443 门户模式、443 本地透明反代模式及 PAC/CA 自助下载端点。
func NewEngine(cfg *config.Config) *gin.Engine {
	return NewEngineWithOptions(EngineOptions{Config: cfg})
}

// NewEngineWithOptions 使用完整配置项构建 Gin 路由引擎。
func NewEngineWithOptions(opts EngineOptions) *gin.Engine {
	cfg := opts.Config
	if cfg == nil {
		cfg = &config.Config{}
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), corsMiddleware())

	seedCookiesFromConfig(cfg)
	proxyHandler := ProxyHandlerWithOptions(cfg.Upstreams, cfg.BlockedHosts, opts.Auth, opts.AdScript)

	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// 远程去广告与成人站点推广脚本端点（供查看、外部引用或手动触发 refresh=1 立即拉取更新）
	r.GET("/__ech_proxy__/ad_script.js", func(c *gin.Context) {
		c.Header("Content-Type", "application/javascript; charset=utf-8")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		if opts.AdScript == nil || !opts.AdScript.Enabled() {
			c.String(http.StatusOK, "/* ech-proxy ad_script is disabled (-no-ad-script) */\n")
			return
		}
		if c.Query("refresh") == "1" && isPortalOrLocalAdminHost(stripPort(c.Request.Host)) {
			_, _ = opts.AdScript.RefreshOnce()
		}
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", opts.AdScript.ScriptBytes())
	})

	// 本地持久化日志与崩溃快照导出端点（仅限本机回环或门户域名访问，方便崩溃时用户一键下载上传排障）
	r.GET("/debug/log", func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if !isPortalOrLocalAdminHost(host) {
			proxyHandler(c)
			return
		}
		logMgr := opts.Logger
		if logMgr == nil {
			logMgr = logger.Default()
		}
		if c.Query("crash") == "1" && logMgr != nil && logMgr.CrashLogPath() != "" {
			if data, err := os.ReadFile(logMgr.CrashLogPath()); err == nil {
				c.Header("Content-Type", "text/plain; charset=utf-8")
				c.Header("Content-Disposition", `attachment; filename="ech-proxy-crash-latest.log"`)
				c.Data(http.StatusOK, "text/plain; charset=utf-8", data)
				return
			}
			c.String(http.StatusNotFound, "no crash log recorded")
			return
		}
		if c.Query("download") == "1" && logMgr != nil && logMgr.LogFilePath() != "" {
			logMgr.Sync()
			if data, err := os.ReadFile(logMgr.LogFilePath()); err == nil {
				c.Header("Content-Type", "text/plain; charset=utf-8")
				c.Header("Content-Disposition", `attachment; filename="ech-proxy.log"`)
				c.Data(http.StatusOK, "text/plain; charset=utf-8", data)
				return
			}
		}
		c.Header("Content-Type", "text/plain; charset=utf-8")
		if logMgr != nil {
			c.String(http.StatusOK, logMgr.RecentLines(300))
			return
		}
		c.String(http.StatusOK, "local logger is not initialized")
	})

	// 运行时状态诊断端点
	r.GET("/statusz", func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if !isPortalOrLocalAdminHost(host) {
			proxyHandler(c)
			return
		}
		caPath := ""
		caValid := ""
		if opts.CertStore != nil {
			caPath = opts.CertStore.CAPath()
			if !opts.CertStore.CAValidUntil().IsZero() {
				caValid = opts.CertStore.CAValidUntil().Format("2006-01-02")
			}
		}
		activeTunnels := 0
		if opts.Limiter != nil {
			activeTunnels = opts.Limiter.ActiveCount()
		}
		adEnabled := false
		allMode := opts.AllMode
		adSource := "disabled"
		adVersion := ""
		whitelistCount := 0
		if opts.AdScript != nil {
			adEnabled = opts.AdScript.Enabled()
			if opts.AdScript.AllMode() {
				allMode = true
			}
			adSource = opts.AdScript.Source()
			adVersion = opts.AdScript.VersionHash()
			whitelistCount = len(opts.AdScript.Whitelist())
		}
		logFile := ""
		if opts.Logger != nil {
			logFile = opts.Logger.LogFilePath()
		} else if logger.Default() != nil {
			logFile = logger.Default().LogFilePath()
		}
		c.JSON(http.StatusOK, gin.H{
			"status":            "ok",
			"upstreams":         len(cfg.Upstreams),
			"ca_path":           caPath,
			"ca_valid_until":    caValid,
			"active_tunnels":    activeTunnels,
			"auth_enabled":      opts.Auth != nil && opts.Auth.Enabled(),
			"all_mode":          allMode,
			"ip_mode":           netdial.FormatIPMode(opts.IPMode),
			"ad_script_enabled": adEnabled,
			"ad_script_source":  adSource,
			"ad_script_version": adVersion,
			"whitelist_count":   whitelistCount,
			"log_file":          logFile,
		})
	})

	// 一键下载本地 CA 根证书（方便浏览器、移动端直接点击安装信任）
	caDownloadHandler := func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if !isPortalOrLocalAdminHost(host) {
			proxyHandler(c)
			return
		}
		if opts.CertStore == nil {
			c.String(http.StatusNotFound, "local CA store is not initialized")
			return
		}
		pemBytes, err := opts.CertStore.CAPEM()
		if err != nil {
			c.String(http.StatusInternalServerError, "export CA: %v", err)
			return
		}
		c.Header("Content-Type", "application/x-x509-ca-cert")
		c.Header("Content-Disposition", `attachment; filename="ech-proxy-ca.crt"`)
		c.Data(http.StatusOK, "application/x-x509-ca-cert", pemBytes)
	}
	r.GET("/ca.pem", caDownloadHandler)
	r.GET("/ca.crt", caDownloadHandler)

	// 自动代理配置脚本（PAC）：
	// - 默认白名单模式：远程白名单（黄网列表）与配置中的目标域名走 ech-proxy（PROXY），其他网站全部直连（DIRECT）；
	// - all 模式（-all 或 ?mode=all）：无视名单，所有网站均走 ech-proxy。
	r.GET("/proxy.pac", func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if !isPortalOrLocalAdminHost(host) {
			proxyHandler(c)
			return
		}
		proxyAddr := c.Request.Host
		if !strings.Contains(proxyAddr, ":") {
			p := defaultPort
			if opts.Port > 0 {
				p = jsonNumber(int(opts.Port))
			}
			proxyAddr = "127.0.0.1:" + p
		} else {
			_, p, _ := net.SplitHostPort(proxyAddr)
			proxyAddr = "127.0.0.1:" + p
		}
		global := opts.AllMode || (opts.AdScript != nil && opts.AdScript.AllMode()) || c.Query("mode") == "all" || c.Query("global") == "1"
		var whitelist []string
		if opts.AdScript != nil {
			whitelist = opts.AdScript.Whitelist()
		}
		pac := config.GeneratePAC(cfg, proxyAddr, global, whitelist)
		c.Header("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
		c.String(http.StatusOK, pac)
	})

	// 自动生成完整的 hosts 配置片段（供偏爱 443 透明反代模式的用户直接复制）
	r.GET("/hosts.txt", func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if !isPortalOrLocalAdminHost(host) {
			proxyHandler(c)
			return
		}
		ip := c.DefaultQuery("ip", "127.0.0.1")
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.String(http.StatusOK, config.GenerateHostsBlock(cfg, ip))
	})

	r.GET("/", func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if isPortalOrLocalAdminHost(host) {
			servePortal(c, cfg)
			return
		}
		if _, ok := config.Resolve(cfg.Upstreams, host); ok {
			proxyHandler(c)
			return
		}
		servePortal(c, cfg)
	})

	r.NoRoute(proxyHandler)
	return r
}

func isPortalOrLocalAdminHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == indexHost || h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
		rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
	}
}

func seedCookiesFromConfig(cfg *config.Config) {
	for _, uc := range cfg.Upstreams {
		if raw := cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile); raw != "" {
			cookie.DefaultJar.Seed(uc.Host, raw)
		}
		if w := uc.Wildcard; w != nil {
			if raw := cookie.ReadFixedCookie(w.Cookie, w.CookieFile); raw != "" {
				cookie.DefaultJar.Seed(strings.TrimPrefix(w.UpstreamSuffix, "."), raw)
			}
		}
	}
}

func servePortal(c *gin.Context, cfg *config.Config) {
	page := strings.Replace(indexHTML, "{{UPSTREAMS}}", renderUpstreamList(cfg, c.Request.Host), 1)
	c.Header("Content-Type", "text/html; charset=utf-8")
	rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
	c.String(http.StatusOK, page)
}

func renderUpstreamList(cfg *config.Config, requestHost string) string {
	var sb strings.Builder
	port := ":" + defaultPort
	if _, p, err := net.SplitHostPort(requestHost); err == nil {
		if p == "443" || p == "80" {
			port = ""
		} else {
			port = ":" + p
		}
	}
	entries := cfg.UpstreamOrder
	if len(entries) == 0 {
		for k := range cfg.Upstreams {
			entries = append(entries, k)
		}
	}
	colors := []string{"#5ce1e6", "#f0a35e", "#7c9cff", "#5ecb8e", "#e68ab8", "#9b8cff", "#5ec9e6", "#e6c45e"}
	ci := 0
	for _, entry := range entries {
		uc, ok := cfg.Upstreams[entry]
		if !ok || !uc.Display {
			continue
		}
		color := colors[ci%len(colors)]
		ci++
		mode := uc.Mode
		if mode == "" {
			mode = "ech"
		}
		desc := uc.Describe
		if desc == "" {
			desc = "Access " + uc.Host + " via ECH Proxy"
		}
		badge := "E"
		if len(entry) > 0 {
			badge = strings.ToUpper(entry[:1])
		}
		sb.WriteString(`<div class="card" data-entry="` + html.EscapeString(strings.ToLower(entry+" "+uc.Host+" "+desc)) + `"><a class="item" href="https://` + html.EscapeString(entry) + port + `/">`)
		sb.WriteString(`<div class="badge" style="background:` + color + `">` + html.EscapeString(badge) + `</div>`)
		sb.WriteString(`<div class="info"><div class="entry">` + html.EscapeString(entry) + `</div>`)
		sb.WriteString(`<div class="desc">` + html.EscapeString(desc) + `</div>`)
		sb.WriteString(`<div class="target">→ ` + html.EscapeString(uc.Host) + `</div></div>`)
		sb.WriteString(`<div class="mode">` + html.EscapeString(mode) + `</div>`)
		sb.WriteString(`</a></div>`)
	}
	return sb.String()
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}