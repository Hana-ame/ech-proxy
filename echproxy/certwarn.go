package echproxy

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

// serveCertWarningPage 在上游证书校验失败（域名不一致 / 已过期 / 证书链不可信）时向浏览器渲染区分类型的中文警告页。
//
// 为什么需要：
// 在 PAC + CONNECT MITM 本地 HTTPS 代理模式下，本地代理使用自生成的 CA 证书与浏览器握手，
// 因此由本地代理负责比对真实目标域名（truedomain.com）与服务端回传证书：
//   - 若域名不一致 -> 明確提示「不一致」（显示 truedomain.com 与服务端实际回传证书域名）；
//   - 若证书已过期 -> 明确提示「已过期」（显示证书生效与过期时间）；
//   - 并提供「强行访问」按钮（带一次性防伪 Token，点击后在当前会话放行该站点并继续执行去广告与插入自有广告脚本）。
func serveCertWarningPage(c *gin.Context, err error, kind, certHost, detail, requestHost, upstreamHost string) {
	rewrite.ApplyCORSHeaders(c.Writer.Header(), c.Request)
	if certHost == "" {
		certHost = upstreamHost
	}
	token := forceCerts.issueForceToken(upstreamHost)
	forceURL := ""
	if token != "" {
		forceURL = forceAccessURL(c.Request.URL, c.Request.Host, token)
	}
	htmlBody := buildCertWarningHTML(err, kind, certHost, detail, requestHost, upstreamHost, forceURL)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	c.Writer.WriteHeader(http.StatusBadGateway)
	_, _ = c.Writer.Write([]byte(htmlBody))
}

// forceAccessURL 构造「强行访问」目标：原请求 URL 追加 ?__ech_proxy_force_cert__=<token>。
func forceAccessURL(u *url.URL, requestHost, token string) string {
	var clone url.URL
	if u != nil {
		clone = *u
	}
	q := clone.Query()
	q.Set(forceCertQueryParam, token)
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
.wrap{max-width:740px;margin:0 auto;padding:48px 24px}
h1{font-size:22px;margin:0 0 18px}
.box{background:#262b33;border:1px solid #3a3f4a;border-radius:10px;padding:20px 22px;margin:14px 0}
.box.warn{border-color:#d97706}
.box.danger{border-color:#dc2626}
code{background:#11141a;padding:2px 6px;border-radius:4px;color:#5ce1e6;font-size:13px}
.kv{margin:12px 0 0;padding:10px 14px;background:#161920;border-radius:6px;font-size:13px;color:#c9d1d9}
.kv div{margin:4px 0}
.detail{background:#11141a;border-radius:6px;padding:12px 14px;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#9aa0a6;word-break:break-all;white-space:pre-wrap;margin-top:14px}
.btns{margin-top:22px;display:flex;gap:12px;flex-wrap:wrap}
a.btn{display:inline-block;padding:11px 20px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;cursor:pointer}
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
{{CERT_META}}
<div class="detail">{{DETAIL}}</div>
</div>
<div class="box">
<p style="margin:0 0 8px"><strong>为什么会看到这个页面？</strong></p>
<p style="margin:0;color:#9aa0a6;line-height:1.6">ech-proxy 在本地 HTTPS 代理模式下使用本地自生成 CA 证书终结 TLS，并代表浏览器向源站 <code>{{UPSTREAM}}</code> 发起加密请求（SNI 伪装 / ECH / TLS 分片）。在核对真实目标域名与源站回传证书时发现了上述安全异常。</p>
</div>
{{BUTTONS}}
</div>
</body>
</html>`

// buildCertWarningHTML 渲染区分「过期 / 不一致 / 不可信」的证书警告页。
// 严格保证三类提示文案互不混用（expired 仅含「已过期」，mismatch 仅含「不一致」，chain 仅含「不可信」）。
func buildCertWarningHTML(rawErr error, kind, certHost, detail, requestHost, upstreamHost, forceURL string) string {
	var title, headline, class, explain string
	switch kind {
	case "expired":
		title = "上游证书已过期 - ech-proxy"
		headline = "⚠ 上游证书已过期或尚未生效"
		class = "warn"
		explain = fmt.Sprintf("代理连接真实目标域名 <code>%s</code> 时，服务端回传的证书时间有效性校验未通过（证书已过期或尚未生效）。", html.EscapeString(upstreamHost))
	case "mismatch":
		title = "上游证书不一致 - ech-proxy"
		headline = "⚠ 上游证书与请求域名不一致"
		class = "danger"
		explain = fmt.Sprintf("代理连接真实目标域名 <code>%s</code> 时，服务端回传的证书域名与伪装前访问的真实域名 <code>%s</code> 不一致。这可能意味着遭遇了中间人劫持，或连接到了错误的源站服务器。", html.EscapeString(upstreamHost), html.EscapeString(certHost))
	case "chain":
		title = "上游证书不可信 - ech-proxy"
		headline = "⚠ 上游证书链未被系统根信任"
		class = "danger"
		explain = fmt.Sprintf("代理连接真实目标域名 <code>%s</code> 时，服务端回传的证书链未通过系统根证书信任校验（自签名或未知签发机构）。", html.EscapeString(upstreamHost))
	default:
		title = "上游证书校验失败 - ech-proxy"
		headline = "⚠ 上游证书校验失败"
		class = "warn"
		explain = fmt.Sprintf("代理连接上游 <code>%s</code> 时证书校验未通过。", html.EscapeString(upstreamHost))
	}

	var certMeta string
	var ce *cloudflare_ech.CertError
	if rawErr != nil && errors.As(rawErr, &ce) && ce != nil {
		var metaBuilder strings.Builder
		metaBuilder.WriteString(`<div class="kv">`)
		metaBuilder.WriteString(fmt.Sprintf(`<div><strong>访问真实域名 (True Domain)：</strong><code>%s</code></div>`, html.EscapeString(ce.Host)))
		if len(ce.DNSNames) > 0 {
			metaBuilder.WriteString(fmt.Sprintf(`<div><strong>服务端回传证书域名 (SANs)：</strong><code>%s</code></div>`, html.EscapeString(strings.Join(ce.DNSNames, ", "))))
		} else if ce.Subject != "" {
			metaBuilder.WriteString(fmt.Sprintf(`<div><strong>服务端回传证书主体 (Subject)：</strong><code>%s</code></div>`, html.EscapeString(ce.Subject)))
		}
		if !ce.NotBefore.IsZero() && !ce.NotAfter.IsZero() {
			metaBuilder.WriteString(fmt.Sprintf(`<div><strong>证书有效期：</strong><code>%s</code> 至 <code>%s</code></div>`,
				html.EscapeString(ce.NotBefore.UTC().Format(time.RFC3339)),
				html.EscapeString(ce.NotAfter.UTC().Format(time.RFC3339))))
		}
		metaBuilder.WriteString(`</div>`)
		certMeta = metaBuilder.String()
	}

	buttons := ""
	if forceURL != "" {
		buttons = `<div class="btns">
<a id="ech-proxy-force-access-btn" class="btn force" href="` + html.EscapeString(forceURL) + `">强行访问（忽略证书警告并继续）</a>
<a class="btn back" href="/">返回门户</a>
</div>
<p class="muted">点击「强行访问」将在当前会话中忽略该域名的上游证书异常并继续加载网页（同时正常执行广告拦截与脚本注入）。</p>`
	} else {
		buttons = `<div class="btns">
<a class="btn back" href="/">返回门户</a>
</div>
<p class="muted">强行访问请求过于频繁，请稍后刷新本页重试。</p>`
	}

	out := certWarningHTMLTemplate
	repl := func(k, v string) { out = strings.ReplaceAll(out, k, v) }
	repl("{{TITLE}}", html.EscapeString(title))
	repl("{{HEADLINE}}", html.EscapeString(headline))
	repl("{{CLASS}}", class)
	repl("{{EXPLAIN}}", explain)
	repl("{{CERT_META}}", certMeta)
	repl("{{DETAIL}}", html.EscapeString(detail))
	repl("{{UPSTREAM}}", html.EscapeString(upstreamHost))
	repl("{{BUTTONS}}", buttons)
	return out
}
