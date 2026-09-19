// Package echproxy router.go provides gin routing shared by desktop and Android versions.
// Both entrypoints (win and android) invoke SetupRouter,
// preventing divergent routing or host dispatching logic.
package echproxy

import (
	_ "embed"
	"html"
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed assets/index.html
var indexHTML string

// indexHost is the host that displays the upstream list portal.
// l.moonchan.xyz root path "/" displays the portal list; other host root paths route to proxy.
const indexHost = "l.moonchan.xyz"

// defaultPort is the fallback port used in portal links when the Host header lacks one.
const defaultPort = "8443"

// SetupRouter registers all routing handlers on the Gin engine.
//
// Routing rules (both root path "/" and NoRoute follow the same host evaluation):
//   - Host == indexHost (l.moonchan.xyz) root path "/" -> renders upstream portal list
//   - Host exact match or wildcard match an upstream -> routes through proxy
//   - Unknown Host root path "/" -> fallback to portal list (renders list when {{UPSTREAMS}} present)
//   - All other paths -> NoRoute proxies directly (ProxyHandler dispatches to upstream by host)
func SetupRouter(r *gin.Engine, cfg *Config) {
	SeedCookiesFromConfig(cfg)
	upstreamHandler := ProxyHandler(cfg.Upstreams, cfg.BlockedHosts)

	r.GET("/healthz", func(c *gin.Context) {
		c.String(200, "ok")
	})

	r.GET("/", func(c *gin.Context) {
		// host is the hostname stripped of port, used to match indexHost and upstreams table;
		// portal link ports are extracted directly from c.Request.Host (parsed in renderUpstreamList,
		// falling back to :8443 if missing).
		host := c.Request.Host
		if name, _, err := net.SplitHostPort(host); err == nil {
			host = name
		}
		// Portal entry host root path -> render portal list
		if host == indexHost {
			serveIndex(c, cfg, c.Request.Host)
			return
		}
		// Exact or wildcard upstream entry -> proxy
		if _, ok := cfg.Upstreams[host]; ok {
			upstreamHandler(c)
			return
		}
		if _, ok := MatchWildcardForTest(cfg.Upstreams, host); ok {
			upstreamHandler(c)
			return
		}
		// Unknown host -> fallback to portal list
		serveIndex(c, cfg, c.Request.Host)
	})

	// All other paths are proxied directly (ProxyHandler dispatches to corresponding upstream by host)
	r.NoRoute(func(c *gin.Context) {
		upstreamHandler(c)
	})
}

// serveIndex returns indexHTML; replaces {{UPSTREAMS}} placeholder with rendered list.
func serveIndex(c *gin.Context, cfg *Config, requestHost string) {
	page := indexHTML
	if strings.Contains(page, "{{UPSTREAMS}}") {
		page = strings.Replace(page, "{{UPSTREAMS}}", renderUpstreamList(cfg, requestHost), 1)
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(200, page)
}

// renderUpstreamList renders entry links following upstream.json write order (UpstreamOrder),
// skipping entries with display=false. Each item is a clickable link to the corresponding entry.
func renderUpstreamList(cfg *Config, requestHost string) string {
	var sb strings.Builder
	port := ""
	if _, p, err := net.SplitHostPort(requestHost); err == nil {
		port = ":" + p
	} else {
		// Default to defaultPort if Host header lacks port
		port = ":" + defaultPort
	}
	entries := cfg.UpstreamOrder
	if len(entries) == 0 {
		for entry := range cfg.Upstreams {
			entries = append(entries, entry)
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
		sb.WriteString(`<a class="item" href="https://` + html.EscapeString(entry) + port + `/">`)
		sb.WriteString(`<div class="badge" style="background:` + color + `">` + html.EscapeString(badge) + `</div>`)
		sb.WriteString(`<div class="info"><div class="entry">` + html.EscapeString(entry) + `</div>`)
		sb.WriteString(`<div class="desc">` + html.EscapeString(desc) + `</div>`)
		sb.WriteString(`<div class="target">→ ` + html.EscapeString(uc.Host) + `</div></div>`)
		sb.WriteString(`<div class="mode">` + html.EscapeString(mode) + `</div>`)
		sb.WriteString(`</a>`)
	}
	return sb.String()
}
