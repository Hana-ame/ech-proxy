package echproxy

import (
	_ "embed"
	"html"
	"net"
	"net/http"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

//go:embed assets/index.html
var indexHTML string

const (
	indexHost   = "l.moonchan.xyz"
	defaultPort = "8443"
)

// NewEngine 构建并配置 Gin 路由引擎，同时服务 8443 门户模式与 443 本地透明反代模式。
func NewEngine(cfg *config.Config) *gin.Engine {
	if cfg == nil {
		cfg = &config.Config{}
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), corsMiddleware())

	seedCookiesFromConfig(cfg)
	proxyHandler := ProxyHandler(cfg.Upstreams, cfg.BlockedHosts)

	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	r.GET("/", func(c *gin.Context) {
		host := stripPort(c.Request.Host)
		if host == indexHost {
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
		port = ":" + p
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
		badge := strings.ToUpper(entry[:1])
		sb.WriteString(`<div class="card"><a class="item" href="https://` + html.EscapeString(entry) + port + `/">`)
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
