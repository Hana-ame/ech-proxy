// Package echproxy 的 router.go 提供桌面版与 Android 版共用的 gin 分流路由。
// 两个入口（cmd/ech-proxy 与 cmd/ech-proxy-android）调用同一份 SetupRouter，
// 避免 gin 路由 / host 分流逻辑写两遍产生漂移。
package echproxy

import (
	_ "embed"
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed assets/index.html
var indexHTML string

// indexHost 是显示 upstream 列表页的 host。桌面版与 Android 版统一行为：
// l.moonchan.xyz 的根路径 "/" 显示列表页，其余 host 根路径按分流走代理。
const indexHost = "l.moonchan.xyz"

// SetupRouter 在 gin 引擎上注册全部分流路由（桌面版与 Android 版共用同一份逻辑）。
//
// 分流规则（根路径 "/" 与 NoRoute 都走同一套 host 判定）：
//   - Host == indexHost (l.moonchan.xyz) 的根路径 "/" → 渲染 upstream 列表页
//   - Host 精确匹配或通配匹配某 upstream → 走代理
//   - 未知 Host 的根路径 "/" → 原样返回列表页（含 {{UPSTREAMS}} 时渲染列表）
//   - 其余路径 → NoRoute 直接代理（ProxyHandler 内部按 host 分流到对应 upstream）
func SetupRouter(r *gin.Engine, cfg *Config) {
	upstreamHandler := ProxyHandler(cfg.Upstreams, cfg.BlockedHosts)

	r.GET("/healthz", func(c *gin.Context) {
		c.String(200, "ok")
	})

	r.GET("/", func(c *gin.Context) {
		// host 为去掉端口的 hostname，用于匹配 indexHost 与 upstream 表；
		// 列表页链接的端口直接取自 c.Request.Host（renderUpstreamList 内解析，
		// Host 头无端口时兜底 :8443）。
		host := c.Request.Host
		if name, _, err := net.SplitHostPort(host); err == nil {
			host = name
		}
		// 列表入口 host 的根路径 → 渲染列表页
		if host == indexHost {
			serveIndex(c, cfg, c.Request.Host)
			return
		}
		// 精确或通配入口 → 走代理
		if _, ok := cfg.Upstreams[host]; ok {
			upstreamHandler(c)
			return
		}
		if _, ok := MatchWildcardForTest(cfg.Upstreams, host); ok {
			upstreamHandler(c)
			return
		}
		// 未知 host → 兜底列表页
		serveIndex(c, cfg, c.Request.Host)
	})

	// 其余所有路径直接代理（ProxyHandler 内部按 host 分流到对应 upstream）
	r.NoRoute(func(c *gin.Context) {
		upstreamHandler(c)
	})
}

// serveIndex 返回 indexHTML；若含 {{UPSTREAMS}} 占位符则按 upstream 顺序渲染列表。
func serveIndex(c *gin.Context, cfg *Config, requestHost string) {
	page := indexHTML
	if strings.Contains(page, "{{UPSTREAMS}}") {
		page = strings.Replace(page, "{{UPSTREAMS}}", renderUpstreamList(cfg, requestHost), 1)
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(200, page)
}

// renderUpstreamList 按 upstream.json 书写顺序（UpstreamOrder）渲染入口列表，
// 跳过 display=false 的条目。每项为可点击链接，跳转同端口对应入口。
func renderUpstreamList(cfg *Config, requestHost string) string {
	var sb strings.Builder
	port := ""
	if _, p, err := net.SplitHostPort(requestHost); err == nil {
		port = ":" + p
	} else {
		// Host header 没带端口时兜底 8443（避免链接缺端口打不开）
		port = ":8443"
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
			desc = "通过 ECH 代理访问 " + uc.Host
		}
		badge := strings.ToUpper(entry[:1])
		sb.WriteString(`<a class="item" href="https://` + entry + port + `/">`)
		sb.WriteString(`<div class="badge" style="background:` + color + `">` + badge + `</div>`)
		sb.WriteString(`<div class="info"><div class="entry">` + entry + `</div>`)
		sb.WriteString(`<div class="desc">` + desc + `</div>`)
		sb.WriteString(`<div class="target">→ ` + uc.Host + `</div></div>`)
		sb.WriteString(`<div class="mode">` + mode + `</div>`)
		sb.WriteString(`</a>`)
	}
	return sb.String()
}
