package echproxy

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

// Debug 控制是否输出逐请求的详细调试日志（通过 CLI -v 开启）。
var Debug bool

func debugLogf(format string, args ...any) {
	if Debug {
		log.Printf(format, args...)
	}
}

const (
	writeTimeout        = 30 * time.Minute
	maxSelfRedirectHops = 3

	// forceCertQueryParam 是证书警告页「强行访问」按钮的覆盖参数名。
	// 命中 ?__ech_proxy_force_cert__=1 时跳过上游证书校验继续连接（用户在看到过期/不一致警告后明确选择继续）。
	forceCertQueryParam = "__ech_proxy_force_cert__"
)

// roundTripFn 供单元测试注入自定义传输层使用，生产环境默认调用 cloudflare_ech.RoundTrip。
var roundTripFn = cloudflare_ech.RoundTrip

// ModeName 返回传输模式的可读名称。
func ModeName(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "sni":
		return "SNI Camouflage"
	case "direct":
		return "Direct"
	case "auto":
		return "Auto (ECH/SNI)"
	default:
		return "Cloudflare ECH"
	}
}

// ProxyHandler 核心反向代理处理器（无鉴权包装，保持向后兼容）。
func ProxyHandler(upstreams config.UpstreamMap, blockedHosts []string) gin.HandlerFunc {
	return ProxyHandlerWithOptions(upstreams, blockedHosts, nil, nil)
}

// ProxyHandlerWithAuth 核心反向代理处理器（带鉴权，保持向后兼容）。
func ProxyHandlerWithAuth(upstreams config.UpstreamMap, blockedHosts []string, auth *AuthConfig) gin.HandlerFunc {
	return ProxyHandlerWithOptions(upstreams, blockedHosts, auth, nil)
}

// ProxyHandlerWithOptions 核心反向代理处理器，统一承载：
//   - 模式一（PAC / CONNECT MITM 零配置模式）：白名单域名（或 all 模式下的全部域名）通过 ECH/SNI 转发；
//   - 模式二（8443 门户反代模式）：将 *.l.moonchan.xyz 映射至真实上游并执行域名重写、SW 注入与 Cookie 转换；
//   - 模式三（443 本地透明反代模式）：将原域名直接通过 ECH/SNI 隧道转发；
//   - 远程脚本注入（AdScript）：白名单 = 黄网（或 HTML 含成人网站广告）= 去掉原有广告 + 加上自己广告。
func ProxyHandlerWithOptions(upstreams config.UpstreamMap, blockedHosts []string, auth *AuthConfig, adScript *rewrite.AdScriptManager) gin.HandlerFunc {
	blocked := append([]string(nil), blockedHosts...)

	return func(c *gin.Context) {
		defer logger.RecoverAndLog("ProxyHandler", func(r any, _ []byte) {
			if !c.Writer.Written() {
				c.String(http.StatusInternalServerError, "internal proxy error")
			}
		})

		start := time.Now()
		clientIP := c.ClientIP()
		host := stripPort(c.Request.Host)

		// 若启用了认证，对反代流量执行鉴权校验
		if auth != nil && auth.Enabled() {
			ok, err := auth.Check(c.Request, clientIP)
			if errors.Is(err, ErrAuthRateLimited) {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
				c.String(http.StatusTooManyRequests, "too many authentication failures")
				return
			}
			if !ok {
				rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
				c.Header("WWW-Authenticate", `Basic realm="ech-proxy"`)
				c.String(http.StatusUnauthorized, "authentication required")
				return
			}
		}

		// 1. 匹配上游路由规则（精确匹配、泛子域名匹配或非门户原域名自动透传）
		uc, ok := config.Resolve(upstreams, host)
		if !ok {
			log.Printf("[%s] Upstream config not found: %s", clientIP, host)
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusBadGateway, "no upstream for host: %s", host)
			return
		}

		ucForRewrite := uc
		if ucForRewrite.Wildcard == nil {
			ucForRewrite.Wildcard = config.InheritWildcard(upstreams, host)
		}
		// 修复 Issue #3：根据当前请求域名决定是否执行 *.l.moonchan.xyz 门户重写
		rewriter := rewrite.BuildEntryRewriterForHost(host, ucForRewrite, blocked)

		// 2. 构造发往真实上游的 HTTP 请求
		outReq, err := buildUpstreamRequest(c, uc)
		if err != nil {
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusInternalServerError, "create request: %v", err)
			return
		}

		// 3. 通过 ECH / SNI / Direct 隧道发送请求
		resp, err := roundTripFn(outReq, uc.Mode, uc.IPMode)
		if err != nil {
			// 上游证书校验失败（过期/不一致）：渲染区分类型的 HTML 警告页（含强行访问按钮），替代 502
			if kind, certHost, detail, ok := cloudflare_ech.ClassifyCertError(err); ok {
				serveCertWarningPage(c, kind, certHost, detail, host, uc.Host)
				return
			}
			log.Printf("[%s] Upstream request failed (%s): %v", clientIP, uc.Host, err)
			rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
			c.String(http.StatusBadGateway, "upstream: %v", err)
			return
		}
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()

		cookie.DefaultJar.SaveResponseCookies(uc.Host, resp)
		debugLogf("[%s] %s %s -> %s (%s, %v)", clientIP, c.Request.Method, c.Request.URL.Path, uc.Host, resp.Status, time.Since(start))

		// 4. 处理响应头（剔除逐跳头、改写 Set-Cookie Domain、重写 Location 重定向、注入 CORS）
		port := extractPort(c.Request.Host)
		cookieDomain := uc.CookieDomain
		if cookieDomain == "" {
			cookieDomain = host
		}
		prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, rewriter, port)

		// 防止上游 Canonical 重定向（如 iwara.tv -> www.iwara.tv）被 rewriter 改写回自身导致 301 死循环（支持多跳防护）
		for hop := 0; hop < maxSelfRedirectHops && resp.StatusCode/100 == 3; hop++ {
			loc := c.Writer.Header().Get("Location")
			if loc == "" || !isSelfRedirect(loc, c.Request) {
				break
			}
			nextResp, ok := followSelfRedirect(c, outReq, resp, uc)
			if !ok {
				break
			}
			_ = resp.Body.Close()
			resp = nextResp
			outReq = nextResp.Request
			cookie.DefaultJar.SaveResponseCookies(resp.Request.Host, resp)
			clearHeaders(c.Writer.Header())
			prepareResponseHeaders(c.Writer.Header(), resp.Header, uc, cookieDomain, c.Request, rewriter, port)
		}

		// 5. 若处于门户模式且开启了 sw_inject、请求 /sw.js（而上游未返回 JS），则自动返回生成的 Service Worker 脚本
		if uc.SWInject && config.IsPortalDomain(host) && c.Request.URL.Path == "/sw.js" && !rewrite.IsJavascriptResponse(resp) {
			c.Writer.Header().Del("Content-Length")
			c.Writer.Header().Set("Content-Type", "application/javascript")
			c.Writer.WriteHeader(http.StatusOK)
			_, _ = c.Writer.Write([]byte(rewrite.GenerateServiceWorkerJS(upstreams, indexHost, port, blocked)))
			return
		}

		// 若对 HTML 页面启用了脚本注入（白名单站点、all 模式或 ServiceWorker），移除上游严格的 CSP 头以确保内联脚本可执行
		if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") &&
			((adScript != nil && adScript.Enabled() && (adScript.IsWhitelisted(host, uc.Host) || adScript.AllMode())) || uc.SWInject) {
			c.Writer.Header().Del("Content-Security-Policy")
			c.Writer.Header().Del("Content-Security-Policy-Report-Only")
		}

		// 6. 写回响应状态码并传输/重写响应体
		c.Status(resp.StatusCode)
		sendResponseBody(c, host, uc, resp, rewriter, adScript, port)
	}
}

func buildUpstreamRequest(c *gin.Context, uc config.UpstreamConfig) (*http.Request, error) {
	reqURI := c.Request.RequestURI
	if reqURI == "" {
		reqURI = c.Request.URL.RequestURI()
	} else if strings.HasPrefix(reqURI, "http://") || strings.HasPrefix(reqURI, "https://") {
		if u, err := url.ParseRequestURI(reqURI); err == nil {
			reqURI = u.RequestURI()
		}
	}
	if !strings.HasPrefix(reqURI, "/") {
		reqURI = "/" + reqURI
	}

	// 「强行访问」覆盖：用户在证书警告页点击继续后，请求带 ?__ech_proxy_force_cert__=1。
	// 注入跳过上游证书校验的标记，并从发往上游的 URI 中剥离该参数（不外泄给上游）。
	forceAllowCert := c.Query(forceCertQueryParam) == "1"
	reqCtx := cloudflare_ech.WithSNIServerName(c.Request.Context(), uc.SNIServerName)
	if forceAllowCert {
		reqCtx = cloudflare_ech.WithAllowBadCert(reqCtx)
		if u, perr := url.Parse(reqURI); perr == nil {
			q := u.Query()
			q.Del(forceCertQueryParam)
			u.RawQuery = q.Encode()
			reqURI = u.RequestURI()
		}
	}

	outReq, err := http.NewRequestWithContext(reqCtx, c.Request.Method, "https://"+uc.Host+reqURI, c.Request.Body)
	if err != nil {
		return nil, err
	}

	cookie.DefaultJar.SaveClientCookies(uc.Host, c.Request)
	rewrite.CopyHeaders(outReq.Header, c.Request.Header)

	if _, ok := uc.Headers["X-Forwarded-For"]; !ok {
		outReq.Header.Del("X-Forwarded-For")
	}
	if _, ok := uc.Headers["X-Forwarded-Proto"]; !ok {
		outReq.Header.Del("X-Forwarded-Proto")
	}
	if uc.Referer != "" {
		outReq.Header.Set("Referer", uc.Referer)
	}
	rewrite.ApplyHeaderRules(outReq.Header, uc.Headers, true, c.Request)

	outReq.Host = uc.Host
	outReq.ContentLength = c.Request.ContentLength

	fixedCookie := cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile)
	if fixedCookie != "" {
		cookie.DefaultJar.Seed(uc.Host, fixedCookie)
	}
	cookie.DefaultJar.ApplyToRequestWithPriority(uc.Host, outReq, fixedCookie, uc.CookiePriority)
	return outReq, nil
}

func prepareResponseHeaders(dst, src http.Header, uc config.UpstreamConfig, cookieDomain string, req *http.Request, rewriter func([]byte, string) []byte, port string) {
	rewrite.CopyHeaders(dst, src)
	cookie.RewriteSetCookieHeaders(dst, cookieDomain, req.TLS == nil)
	rewrite.ApplyHeaderRules(dst, uc.ResponseHeaders, false, nil)
	rewrite.RewriteRedirectHeaders(dst, rewriter, port)
	rewrite.ApplyCORSHeaders(dst, req)
}

func isSelfRedirect(rewrittenLoc string, clientReq *http.Request) bool {
	u, err := url.Parse(rewrittenLoc)
	if err != nil {
		return false
	}
	reqPath := clientReq.URL.RequestURI()
	if reqPath == "" {
		reqPath = "/"
	}
	locPath := u.RequestURI()
	if locPath == "" {
		locPath = "/"
	}
	return (u.Host == "" || strings.EqualFold(u.Host, clientReq.Host)) && locPath == reqPath
}

func followSelfRedirect(c *gin.Context, outReq *http.Request, resp *http.Response, uc config.UpstreamConfig) (*http.Response, bool) {
	rawTarget, err := outReq.URL.Parse(resp.Header.Get("Location"))
	if err != nil || rawTarget.Host == "" {
		return nil, false
	}
	if rawTarget.Scheme == "http" {
		rawTarget.Scheme = "https"
	}
	method := c.Request.Method
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		if method != http.MethodGet && method != http.MethodHead {
			method = http.MethodGet
		}
	}
	reqCtx := cloudflare_ech.WithSNIServerName(c.Request.Context(), uc.SNIServerName)
	nextReq, err := http.NewRequestWithContext(reqCtx, method, rawTarget.String(), nil)
	if err != nil {
		return nil, false
	}
	rewrite.CopyHeaders(nextReq.Header, outReq.Header)
	nextReq.Host = rawTarget.Host
	cookie.DefaultJar.ApplyToRequestWithPriority(rawTarget.Host, nextReq, cookie.ReadFixedCookie(uc.Cookie, uc.CookieFile), uc.CookiePriority)
	nextResp, err := roundTripFn(nextReq, uc.Mode, uc.IPMode)
	if err != nil {
		return nil, false
	}
	nextResp.Request = nextReq
	return nextResp, true
}

func clearHeaders(h http.Header) {
	for k := range h {
		delete(h, k)
	}
}

func sendResponseBody(c *gin.Context, requestHost string, uc config.UpstreamConfig, resp *http.Response, rewriter func([]byte, string) []byte, adScript *rewrite.AdScriptManager, port string) {
	rc := http.NewResponseController(c.Writer)

	// 文本类且不超过 8MB：解压 -> 重写域名与内容 -> 注入远程去广告/推广脚本 -> 注入 SW -> 重新压缩并发送
	if rewriter != nil && rewrite.IsTextContent(resp.Header.Get("Content-Type")) &&
		(resp.ContentLength <= 0 || resp.ContentLength <= rewrite.MaxRewriteSize) {

		body, err := io.ReadAll(io.LimitReader(resp.Body, rewrite.MaxRewriteSize+1))
		if err != nil || len(body) > rewrite.MaxRewriteSize {
			// 修复超大 Chunked 文本截断 Bug：若超过 8MB 上限，先写出已读部分，再继续流式转发剩余 resp.Body
			if len(body) > 0 {
				_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
				if _, werr := c.Writer.Write(body); werr != nil {
					return
				}
			}
			if err == nil {
				streamRemainingBody(c, rc, resp.Body)
			}
			return
		}

		origEnc := resp.Header.Get("Content-Encoding")
		plain, derr := rewrite.DecompressBody(body, origEnc)
		if derr != nil {
			c.Writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = c.Writer.Write(body)
			return
		}

		plain = rewriter(plain, port)

		lowerCT := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(lowerCT, "text/html") {
			if adScript != nil && adScript.Enabled() {
				plain = adScript.InjectIntoHTMLForHost(plain, requestHost, uc.Host)
			}
			if uc.SWInject && config.IsPortalDomain(requestHost) && !bytes.Contains(plain, []byte("serviceWorker")) {
				reg := []byte(`<script>navigator.serviceWorker.register('/sw.js').catch(function(){})</script>`)
				if idx := bytes.Index(plain, []byte("</head>")); idx >= 0 {
					plain = append(plain[:idx], append(reg, plain[idx:]...)...)
				} else {
					plain = append(plain, reg...)
				}
			}
		}

		c.Writer.Header().Del("Content-Encoding")
		if compressed, enc := rewrite.CompressBody(plain, origEnc, c.Request.Header.Get("Accept-Encoding")); enc != "" {
			plain = compressed
			c.Writer.Header().Set("Content-Encoding", enc)
		}
		c.Writer.Header().Set("Content-Length", strconv.Itoa(len(plain)))
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = c.Writer.Write(plain)
		return
	}

	// 二进制流或大文件（图片、视频等）：32KB 分块直接流式转发
	streamRemainingBody(c, rc, resp.Body)
}

func streamRemainingBody(c *gin.Context, rc *http.ResponseController, body io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			if _, werr := c.Writer.Write(buf[:n]); werr != nil {
				break
			}
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
}

func extractPort(hostport string) string {
	if _, p, err := net.SplitHostPort(hostport); err == nil {
		return p
	}
	return ""
}

// serveCertWarningPage 在上游证书校验失败（过期/不一致）时向客户端渲染区分类型的 HTML 警告页。
// MITM/反代通道此时客户端 TLS 已建立（覆盖证书），客户端无法自行判断上游真实证书，故由代理代为提示。
// 警告页含「强行访问」按钮：点击后以 ?__ech_proxy_force_cert__=1 重新请求并跳过校验。
func serveCertWarningPage(c *gin.Context, kind, certHost, detail, requestHost, upstreamHost string) {
	rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
	forceURL := forceAccessURL(c.Request.URL, c.Request.Host)
	htmlBody := buildCertWarningHTML(kind, certHost, detail, requestHost, upstreamHost, forceURL)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Writer.WriteHeader(http.StatusBadGateway) // 502 + HTML 警告体（浏览器渲染警告页而非裸 502）
	_, _ = c.Writer.Write([]byte(htmlBody))
}

// forceAccessURL 构造「强行访问」目标：原请求 URL 追加 ?__ech_proxy_force_cert__=1。
// 不修改传入的 *url.URL。
func forceAccessURL(u *url.URL, requestHost string) string {
	var clone url.URL
	if u != nil {
		clone = *u // 拷贝结构体值，避免改动原始 c.Request.URL
	}
	q := clone.Query()
	q.Set(forceCertQueryParam, "1")
	clone.RawQuery = q.Encode()
	scheme := clone.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := requestHost
	if host == "" {
		host = clone.Host
	}
	return scheme + "://" + host + clone.RequestURI()
}

const certWarningHTMLTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#1a1d23;color:#e6e6e6;font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.6}
.wrap{max-width:720px;margin:0 auto;padding:48px 24px}
h1{font-size:22px;margin:0 0 18px}
.box{background:#262b33;border:1px solid #3a3f4a;border-radius:10px;padding:20px 22px;margin:14px 0}
.box.warn{border-color:#d97706}
.box.danger{border-color:#dc2626}
code{background:#11141a;padding:2px 6px;border-radius:4px;color:#5ce1e6;font-size:13px}
.detail{background:#11141a;border-radius:6px;padding:12px 14px;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#9aa0a6;word-break:break-all;white-space:pre-wrap;margin-top:14px}
.btns{margin-top:22px;display:flex;gap:12px;flex-wrap:wrap}
a.btn{display:inline-block;padding:11px 20px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px}
a.force{background:#dc2626;color:#fff}
a.force:hover{background:#b91c1c}
a.back{background:#3a3f4a;color:#e6e6e6}
.muted{color:#6b7280;font-size:12px;margin-top:12px}
</style>
</head>
<body>
<div class="wrap">
<h1>{{HEADLINE}}</h1>
<div class="box {{CLASS}}">
{{EXPLAIN}}
<div class="detail">{{DETAIL}}</div>
</div>
<div class="box">
<p style="margin:0 0 8px"><strong>为什么会看到这个页面？</strong></p>
<p style="margin:0;color:#9aa0a6;line-height:1.6">ech-proxy 在 MITM 模式下用本地 CA 覆盖了客户端证书，你的浏览器无法自行判断上游真实证书。代理代为校验了上游 <code>{{UPSTREAM}}</code> 返回的证书并发现了上述问题。</p>
</div>
<div class="btns">
<a class="btn force" href="{{FORCE_URL}}">强行访问（不安全）</a>
<a class="btn back" href="/">返回门户</a>
</div>
<p class="muted">强行访问将跳过证书校验继续连接上游，存在中间人风险，请仅在你确信安全时使用。</p>
</div>
</body>
</html>`

// buildCertWarningHTML 渲染区分「过期」与「不一致」的证书警告页。
func buildCertWarningHTML(kind, certHost, detail, requestHost, upstreamHost, forceURL string) string {
	var title, headline, class, explain string
	switch kind {
	case "expired":
		title = "上游证书已过期 - ech-proxy"
		headline = "⚠ 上游证书已过期或尚未生效"
		class = "warn"
		explain = fmt.Sprintf("代理连接上游 <code>%s</code> 时，其返回的证书时间有效性校验未通过。可能站点证书已过期，或服务器/本机时间有误。", html.EscapeString(upstreamHost))
	case "mismatch":
		title = "上游证书不一致 - ech-proxy"
		headline = "⚠ 上游证书与请求域名不一致"
		class = "danger"
		explain = fmt.Sprintf("代理连接上游 <code>%s</code> 时，其返回的证书未覆盖真实请求域名 <code>%s</code>。这可能意味着遭遇了中间人攻击，或连接到了错误的服务器。", html.EscapeString(upstreamHost), html.EscapeString(certHost))
	default:
		title = "上游证书校验失败 - ech-proxy"
		headline = "⚠ 上游证书校验失败"
		class = "warn"
		explain = fmt.Sprintf("代理连接上游 <code>%s</code> 时证书校验未通过。", html.EscapeString(upstreamHost))
	}
	out := certWarningHTMLTemplate
	repl := func(k, v string) { out = strings.ReplaceAll(out, k, v) }
	repl("{{TITLE}}", html.EscapeString(title))
	repl("{{HEADLINE}}", html.EscapeString(headline))
	repl("{{CLASS}}", class)
	repl("{{EXPLAIN}}", explain) // explain 已用 html.EscapeString 转义其内部片段，整体为受信片段
	repl("{{DETAIL}}", html.EscapeString(detail))
	repl("{{UPSTREAM}}", html.EscapeString(upstreamHost))
	repl("{{FORCE_URL}}", html.EscapeString(forceURL))
	return out
}