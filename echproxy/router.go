// Package echproxy router.go provides gin routing shared by desktop and Android versions.
// Both entrypoints (win and android) invoke SetupRouter,
// preventing divergent routing or host dispatching logic.
package echproxy

import (
	_ "embed"
	"html"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed assets/index.html
var indexHTML string

//go:embed assets/login.html
var loginHTML string

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

	r.Any("/control/cookie", func(c *gin.Context) {
		handleControlCookie(c, cfg)
	})
	r.Any("/_ech/cookie", func(c *gin.Context) {
		handleControlCookie(c, cfg)
	})

	// 自造登录页：同源提供，reCAPTCHA 走官方域（合法），登录后的 Set-Cookie 落回本域
	r.GET("/_ech/login", func(c *gin.Context) {
		c.Data(200, "text/html; charset=utf-8", []byte(loginHTML))
	})
	// 登录 API 同源代理：把 /ajax/login 请求转发到官方域，并透传 Set-Cookie（含 cookie_domain 重写）
	r.Any("/_ech/login-api/*path", func(c *gin.Context) {
		handleLoginProxy(c, cfg)
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
		hasCookie := uc.Cookie != "" || uc.CookieFile != "" || uc.CookiePriority != ""
		defaultMode := uc.CookiePriority
		if defaultMode == "" {
			if uc.Cookie != "" || uc.CookieFile != "" {
				defaultMode = "seed"
			} else {
				defaultMode = "browser"
			}
		}

		sb.WriteString(`<div class="card"`)
		if hasCookie {
			sb.WriteString(` data-cookie-entry="` + html.EscapeString(entry) + `" data-default-mode="` + html.EscapeString(defaultMode) + `"`)
		}
		sb.WriteString(`>`)

		sb.WriteString(`<a class="item" href="https://` + html.EscapeString(entry) + port + `/">`)
		sb.WriteString(`<div class="badge" style="background:` + color + `">` + html.EscapeString(badge) + `</div>`)
		sb.WriteString(`<div class="info"><div class="entry">` + html.EscapeString(entry) + `</div>`)
		sb.WriteString(`<div class="desc">` + html.EscapeString(desc) + `</div>`)
		sb.WriteString(`<div class="target">→ ` + html.EscapeString(uc.Host) + `</div></div>`)
		sb.WriteString(`<div class="mode">` + html.EscapeString(mode) + `</div>`)
		sb.WriteString(`</a>`)

		if hasCookie {
			sb.WriteString(`<div class="cookie-ctrl">`)
			sb.WriteString(`<div class="cookie-meta">`)
			sb.WriteString(`<span class="cookie-label">Cookie 控制面:</span>`)
			sb.WriteString(`<span class="c-status" id="c-status-` + html.EscapeString(entry) + `"></span>`)
			sb.WriteString(`</div>`)
			sb.WriteString(`<div class="cookie-actions">`)
			sb.WriteString(`<button type="button" class="c-btn c-seed" onclick="switchCookie(event, '` + html.EscapeString(entry) + `', 'seed')">🍪 使用公用 Cookie</button>`)
			sb.WriteString(`<button type="button" class="c-btn c-browser" onclick="switchCookie(event, '` + html.EscapeString(entry) + `', 'browser')">👤 使用本地 Cookie</button>`)
			sb.WriteString(`</div>`)
			sb.WriteString(`</div>`)
		}

		sb.WriteString(`</div>`)
	}
	return sb.String()
}

func handleControlCookie(c *gin.Context, cfg *Config) {
	entry := strings.TrimSpace(c.Query("entry"))
	if entry == "" {
		entry = strings.TrimSpace(c.PostForm("entry"))
	}
	if entry == "" {
		h := c.Request.Host
		if nh, _, err := net.SplitHostPort(h); err == nil {
			h = nh
		}
		if h != indexHost {
			entry = h
		}
	}

	uc, matchedEntry, ok := findUpstreamConfig(cfg, entry)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "upstream entry not found", "entry": entry})
		return
	}

	mode := strings.ToLower(strings.TrimSpace(c.Query("mode")))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(c.PostForm("mode")))
	}

	if mode == "" || mode == "status" {
		currentMode := getEffectiveCookiePriority(c, uc, matchedEntry)
		c.JSON(http.StatusOK, gin.H{
			"ok":    true,
			"entry": matchedEntry,
			"mode":  currentMode,
			"host":  uc.Host,
		})
		return
	}

	if mode != "seed" && mode != "browser" && mode != "reset" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mode, must be 'seed' or 'browser'"})
		return
	}

	if mode == "reset" {
		mode = "seed"
	}

	applyCookieModeSwitch(c, uc, matchedEntry, mode)

	if c.Query("redirect") == "1" || c.Query("return_to") != "" {
		target := c.Query("return_to")
		if target == "" {
			port := ""
			if _, p, err := net.SplitHostPort(c.Request.Host); err == nil {
				port = ":" + p
			} else {
				port = ":" + defaultPort
			}
			target = "https://" + matchedEntry + port + "/"
		}
		c.Redirect(http.StatusFound, target)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"entry":   matchedEntry,
		"mode":    mode,
		"message": "Cookie mode successfully updated to " + mode,
	})
}

func findUpstreamConfig(cfg *Config, entry string) (UpstreamConfig, string, bool) {
	if cfg == nil || len(cfg.Upstreams) == 0 {
		return UpstreamConfig{}, "", false
	}
	if uc, ok := cfg.Upstreams[entry]; ok {
		return uc, entry, true
	}
	if uc, ok := matchWildcard(cfg.Upstreams, entry); ok {
		return uc, entry, true
	}
	for k, uc := range cfg.Upstreams {
		if strings.HasPrefix(k, entry+".") || k == entry {
			return uc, k, true
		}
	}
	return UpstreamConfig{}, "", false
}
