package echproxy

import (
	_ "embed"
	"html"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/certstore"
	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
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

func NewEngine(cfg *config.Config) *gin.Engine {
	return NewEngineWithOptions(EngineOptions{Config: cfg})
}

// New443Engine 构建 443 方案专属的极简反代引擎：
//   - 仅处理 443 原域名 HTTPS 流量，不挂载 PAC、广告脚本或 8443 门户路由。
func New443Engine(_ *certstore.Store, auth *AuthConfig) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), corsMiddleware())
	emptyCfg := &config.Config{}
	proxyHandler := ProxyHandlerWithConfig(emptyCfg, auth, nil)
	r.NoRoute(proxyHandler)
	return r
}

func NewEngineWithOptions(opts EngineOptions) *gin.Engine {
	cfg := opts.Config
	if cfg == nil {
		cfg = &config.Config{}
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), corsMiddleware())

	seedCookiesFromConfig(cfg)
	proxyHandler := ProxyHandlerWithConfig(cfg, opts.Auth, opts.AdScript)

	r.Use(func(c *gin.Context) {
		host := netdial.CleanHost(c.Request.Host)
		if !isPortalOrLocalAdminHost(host) &&
			c.Request.URL.Path != "/__ech_proxy__/ads.js" &&
			c.Request.URL.Path != "/__ech_proxy__/ad_script.js" {
			proxyHandler(c)
			c.Abort()
			return
		}
		c.Next()
	})

	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	serveAdScriptEndpoint := func(c *gin.Context) {
		c.Header("Content-Type", "application/javascript; charset=utf-8")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		if opts.AdScript == nil || !opts.AdScript.Enabled() {
			c.String(http.StatusOK, "/* ech-proxy ads.js is skipped (--skip-ad-script) */\n")
			return
		}
		if c.Query("refresh") == "1" && isPortalOrLocalAdminHost(netdial.CleanHost(c.Request.Host)) {
			_, _ = opts.AdScript.RefreshOnce()
		}
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", opts.AdScript.ScriptBytes())
	}
	r.GET("/__ech_proxy__/ads.js", serveAdScriptEndpoint)
	r.GET("/__ech_proxy__/ad_script.js", serveAdScriptEndpoint)

	r.GET("/debug/log", func(c *gin.Context) {
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

	r.GET("/statusz", func(c *gin.Context) {
		caPath, caValid := "", ""
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
		adEnabled, adOn, skipAdScript, skipAdBlock := false, true, true, false
		allMode := opts.AllMode
		adSource, adVersion := "disabled", ""
		whitelistCount, adultSitesCount, blocklistCount, easyListRules := 0, 0, 0, 0
		easyListLoaded := false
		if opts.AdScript != nil {
			adEnabled = opts.AdScript.Enabled()
			adOn = opts.AdScript.On()
			skipAdScript = opts.AdScript.SkipAdScript()
			skipAdBlock = opts.AdScript.SkipAdBlock()
			if opts.AdScript.AllMode() {
				allMode = true
			}
			adSource = opts.AdScript.Source()
			adVersion = opts.AdScript.VersionHash()
			whitelistCount = len(opts.AdScript.Whitelist())
			adultSitesCount = len(opts.AdScript.AdultSites())
			bl := opts.AdScript.Blocklist()
			blocklistCount = len(bl.Domains) + len(bl.Selectors)
			easyListLoaded = opts.AdScript.EasyListLoaded()
			easyListRules = opts.AdScript.EasyListRuleCount()
		}
		logFile := ""
		if opts.Logger != nil {
			logFile = opts.Logger.LogFilePath()
		} else if logger.Default() != nil {
			logFile = logger.Default().LogFilePath()
		}
		upstreams, _ := cfg.Snapshot()
		c.JSON(http.StatusOK, gin.H{
			"status":              "ok",
			"upstreams":           len(upstreams),
			"ca_path":             caPath,
			"ca_valid_until":      caValid,
			"active_tunnels":      activeTunnels,
			"auth_enabled":        opts.Auth != nil && opts.Auth.Enabled(),
			"all_mode":            allMode,
			"ip_mode":             netdial.FormatIPMode(cloudflare_ech.GetIPMode()),
			"doh_primary":         cloudflare_ech.PrimaryDoHURL(),
			"doh_secondary":       cloudflare_ech.SecondaryDoHURL(),
			"ad_script_enabled":   adEnabled,
			"ad_on":               adOn,
			"skip_ad_script":      skipAdScript,
			"skip_ad_block":       skipAdBlock,
			"ad_script_source":    adSource,
			"ad_script_version":   adVersion,
			"whitelist_count":     whitelistCount,
			"adult_sites_count":   adultSitesCount,
			"blocklist_count":     blocklistCount,
			"easylist_loaded":     easyListLoaded,
			"easylist_rule_count": easyListRules,
			"log_file":            logFile,
		})
	})

	caDownloadHandler := func(c *gin.Context) {
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

	// PAC 自动代理脚本：严格仅依据 pac.txt 白名单（与 upstream.json 完全解耦），且自适应任意监听端口
	r.GET("/proxy.pac", func(c *gin.Context) {
		portStr := defaultPort
		if opts.Port > 0 {
			portStr = strconv.Itoa(int(opts.Port))
		}
		if p := netdial.ExtractPort(c.Request.Host); p != "" {
			portStr = p
		}
		proxyAddr := "127.0.0.1:" + portStr
		global := opts.AllMode || (opts.AdScript != nil && opts.AdScript.AllMode()) || c.Query("mode") == "all" || c.Query("global") == "1"
		var wl []string
		if opts.AdScript != nil {
			wl = opts.AdScript.Whitelist()
		}
		pac := config.GeneratePAC(nil, proxyAddr, global, wl)
		c.Header("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
		c.String(http.StatusOK, pac)
	})

	r.GET("/hosts.txt", func(c *gin.Context) {
		ip := c.DefaultQuery("ip", "127.0.0.1")
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.String(http.StatusOK, config.GenerateHostsBlock(cfg, ip))
	})

	r.GET("/", func(c *gin.Context) {
		servePortal(c, cfg)
	})

	r.NoRoute(proxyHandler)
	return r
}

func isPortalOrLocalAdminHost(host string) bool {
	h := netdial.CleanHost(host)
	return h == indexHost || h == "localhost" || h == "127.0.0.1" || h == "::1" || net.ParseIP(h) != nil
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
	upstreams, _ := cfg.Snapshot()
	for _, uc := range upstreams {
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
	if p := netdial.ExtractPort(requestHost); p != "" {
		if p == "443" || p == "80" {
			port = ""
		} else {
			port = ":" + p
		}
	}
	upstreams, _ := cfg.Snapshot()
	entries := cfg.OrderSnapshot()
	if len(entries) == 0 {
		for k := range upstreams {
			entries = append(entries, k)
		}
	}
	colors := []string{"#5ce1e6", "#f0a35e", "#7c9cff", "#5ecb8e", "#e68ab8", "#9b8cff", "#5ec9e6", "#e6c45e"}
	ci := 0
	for _, entry := range entries {
		uc, ok := upstreams[entry]
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