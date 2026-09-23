package echproxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

// handleLoginProxy 是同源登录代理：把浏览器在自造登录页发起的 /ajax/login 请求，
// 经 ech-proxy 的 ECH 出口转发到官方域 accounts.pixiv.net，并把响应 Set-Cookie
// 重写为当前入口域，使登录态落回本机浏览器/ech-proxy 会话。
//
// 为什么这样能过 reCAPTCHA：自造登录页本身可托管在本域，但它的 reCAPTCHA 调用
// 打到官方登录页（accounts.pixiv.net/login）由其在前端生成 score token —— 官方域
// 下 token 合法；本代理只负责承载登录 POST 与 cookie 回传，不生成 reCAPTCHA。
// （纯 Go 端无法伪造 reCAPTCHA score token，Google 服务端签发；2026-09-23 实测。）
func handleLoginProxy(c *gin.Context, cfg *Config) {
	// 登录接口只在官方域 accounts.pixiv.net（www.pixiv.net 无 /ajax/login）。
	// 固定用官方域 + ECH 域前置（在 Cloudflare 后面），不从配置匹配避免误路由。
	upstreamHost := "accounts.pixiv.net"
	mode := "ech"

	// 转发路径：/ _ech/login-api/ajax/login?lang=zh -> /ajax/login?lang=zh（去掉 / _ech/login-api 前缀）
	path := c.Request.URL.Path
	const prefix = "/_ech/login-api"
	if strings.HasPrefix(path, prefix) {
		path = path[len(prefix):]
	}
	if path == "" {
		path = "/"
	}
	u := &url.URL{Scheme: "https", Host: upstreamHost, Path: path, RawQuery: c.Request.URL.RawQuery}

	var body io.Reader
	if c.Request.Body != nil {
		body = c.Request.Body
	}
	outReq, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, u.String(), body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create request: " + err.Error()})
		return
	}
	// 转发关键头（避免逐跳头；Referer/Origin 用官方域，让上游与 reCAPTCHA 校验一致）
	outReq.Header.Set("User-Agent", c.Request.UserAgent())
	outReq.Header.Set("Accept", c.Request.Header.Get("Accept"))
	outReq.Header.Set("Content-Type", c.Request.Header.Get("Content-Type"))
	outReq.Header.Set("Referer", "https://accounts.pixiv.net/login")
	outReq.Header.Set("Origin", "https://accounts.pixiv.net")
	outReq.Header.Set("Accept-Language", c.Request.Header.Get("Accept-Language"))
	if ck := c.Request.Header.Get("Cookie"); ck != "" {
		// 透传浏览器已有 cookie（如本域已存的登录态）
		ck = strings.ReplaceAll(ck, "Domain=accounts.pixiv.net;", "")
		outReq.Header.Set("Cookie", ck)
	}
	outReq.Host = upstreamHost

	start := time.Now()
	resp, err := proxyRoundTripForMode(outReq, mode)
	if err != nil {
		log.Printf("[login-proxy] upstream error: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	if Debug {
		log.Printf("[login-proxy] <- %s %s (%.0fms)", resp.Status, u.String(), float64(time.Since(start).Milliseconds()))
	}

	// 回传头 + Set-Cookie 重写到本域
	for k, vs := range resp.Header {
		for _, v := range vs {
			c.Writer.Header().Add(k, v)
		}
	}
	// 关键：把 .pixiv.net 的登录 cookie 重写为当前入口域（浏览器才会存；下次请求 ech-proxy 带上）
	if c.Request.TLS == nil {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	}
	cookieDomain := currentLoginDomain(c)
	rewriteSetCookieDomains(c.Writer.Header(), cookieDomain, c.Request.TLS == nil)

	// 读 body 并透传
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		log.Printf("[login-proxy] read body: %v", err)
	}

	// 劫持：登录响应里只要下发了有效 PHPSESSID（含 requireExtraVerification 阶段
	// 凭据已通过的会话），就把它 seed 进 jar，供后续 ech-proxy 请求代持登录态。
	seedLoginCookies(resp)

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), b)
}

// seedLoginCookies 把官方域登录响应里的 Set-Cookie 提取成 Netscape 格式并 seed 进 jar。
func seedLoginCookies(resp *http.Response) {
	scs := resp.Header.Values("Set-Cookie")
	if len(scs) == 0 {
		return
	}
	var lines []string
	for _, sc := range scs {
		// 转 Netscape 格式（便于复用 seedCookieRawLocked 的域处理）
		c, err := http.ParseSetCookie(sc)
		if err != nil || c.Name == "" {
			continue
		}
		// 跳过清除指令（deleted / Max-Age<=0），否则会把"删除"也当成登录态 seed 进去
		if c.Value == "" || c.Value == "deleted" || c.MaxAge < 0 {
			continue
		}
		domain := c.Domain
		if domain == "" {
			domain = "accounts.pixiv.net"
		}
		expires := ""
		if !c.Expires.IsZero() {
			expires = fmt.Sprintf("%d", c.Expires.Unix())
		}
		lines = append(lines, strings.Join([]string{domain, "TRUE", "/", "FALSE", expires, c.Name, c.Value}, "\t"))
	}
	if len(lines) > 0 {
		seedCookieRaw("accounts.pixiv.net", strings.Join(lines, "\n"))
		// 同时 seed 到 .pixiv.net 域，方便所有 pixiv 子域请求共享登录态
		seedCookieRaw(".pixiv.net", strings.Join(lines, "\n"))
		log.Printf("[login-proxy] seeded %d login cookies into jar", len(lines))
	}
}

// proxyRoundTripForMode 复用 ech/sni/direct 与 proxyRoundTrip 相同逻辑（避免依赖 gin context 封装）。
func proxyRoundTripForMode(req *http.Request, mode string) (*http.Response, error) {
	switch mode {
	case "direct":
		return netdial.Client(60 * time.Second).Do(req)
	case "sni":
		return sniFrontDo(req)
	default:
		return cloudflare_ech.Do(req)
	}
}

// currentLoginDomain 返回把登录 cookie 落到哪个域（用请求 Host 的主机名）。
func currentLoginDomain(c *gin.Context) string {
	h := c.Request.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	// 若请求来自 *.l.moonchan.xyz，落 .l.moonchan.xyz 或 pixiv 入口域
	if strings.HasSuffix(h, ".l.moonchan.xyz") {
		return "l.moonchan.xyz"
	}
	return h
}
