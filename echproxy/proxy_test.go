package echproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"github.com/gin-gonic/gin"
)

// TestIssue17And26_UpstreamJSONAndPximgRouting 验证：
// 1. certs/l.moonchan.xyz/upstream.json 语法与结构完整合法 (#26)，且通过严格静态校验 ValidateConfig (#8)；
// 2. 包含 pixiv.net、pximg.net、i.pximg.net、s.pximg.net 路由且携带防盗链 Referer (#17)；
// 3. 任何未写入 upstream.json 的非 l.moonchan.xyz 域名（修改 hosts=127.0.0.1 或通过 CONNECT 后）均可自动透传转发。
func TestIssue17And26_UpstreamJSONAndPximgRouting(t *testing.T) {
	buf, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json: %v", err)
	}
	if err := json.Unmarshal(buf, &map[string]any{}); err != nil {
		t.Fatalf("upstream.json invalid JSON: %v", err)
	}
	issues, verr := ValidateConfig(buf)
	if verr != nil || ConfigHasErrors(issues) {
		t.Fatalf("ValidateConfig failed: err=%v issues=%s", verr, FormatConfigIssues(issues))
	}
	cfg, err := ParseConfig(buf)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	// 验证 Pixiv 主站与子域
	for _, host := range []string{"pixiv.net", "www.pixiv.net", "account.pixiv.net", "accounts.pixiv.net", "api.sec.pixiv.net"} {
		uc, ok := config.Resolve(cfg.Upstreams, host)
		if !ok || uc.Host != host || uc.IPMode != "v4" {
			t.Errorf("Pixiv host %s resolve mismatch: host=%q ip_mode=%q ok=%v", host, uc.Host, uc.IPMode, ok)
		}
	}

	// 验证 #17: pximg.net / i.pximg.net / s.pximg.net 路由与防盗链 Referer
	for _, imgHost := range []string{"pximg.net", "i.pximg.net", "s.pximg.net", "imp.pximg.net"} {
		uc, ok := config.Resolve(cfg.Upstreams, imgHost)
		if !ok || uc.Host != imgHost {
			t.Errorf("pximg host %s resolve failed: got %q (ok=%v)", imgHost, uc.Host, ok)
		}
		if uc.Referer != "https://www.pixiv.net/" {
			t.Errorf("pximg host %s missing Referer: got %q", imgHost, uc.Referer)
		}
	}

	// 验证任意未在 upstream.json 中声明的 hosts=127.0.0.1 域名自动透传（Mode="auto"）
	autoUC, ok := config.Resolve(cfg.Upstreams, "unlisted.example.org")
	if !ok || autoUC.Host != "unlisted.example.org" || autoUC.Mode != "auto" {
		t.Errorf("unlisted non-portal domain should auto-passthrough, got: %+v (ok=%v)", autoUC, ok)
	}
}

// TestIssue23_ForceHTTPSRedirectUpgrade 验证上游返回 http:// Location 或 Refresh 时强制升级为 https:// (#23)。
func TestIssue23_ForceHTTPSRedirectUpgrade(t *testing.T) {
	h := http.Header{}
	h.Set("Location", "http://www.pixiv.net/?return_to=%2F")
	h.Set("Refresh", "0; url=http://www.dlsite.com/home")

	rewriter := rewrite.BuildEntryRewriter(config.UpstreamConfig{
		Rewrites: map[string]string{"www.dlsite.com": "dlsite.l.moonchan.xyz"},
	}, nil)
	rewrite.RewriteRedirectHeaders(h, rewriter, "8443")

	if got := h.Get("Location"); got != "https://www.pixiv.net/?return_to=%2F" {
		t.Errorf("Location was not upgraded to https: got %q", got)
	}
	if got := h.Get("Refresh"); got != "0; url=https://dlsite.l.moonchan.xyz:8443/home" {
		t.Errorf("Refresh was not upgraded and rewritten: got %q", got)
	}
}

// TestIssue28_BlockArbitraryFileReadAndControlPlane 验证：
// 1. cookie_file 拒绝读取系统任意路径或 ".." 路径穿越 (#28)；
// 2. 控制面端点 /control/cookie 不再暴露。
func TestIssue28_BlockArbitraryFileReadAndControlPlane(t *testing.T) {
	for _, unsafePath := range []string{"/etc/passwd", "../../../etc/hosts", `C:\Windows\win.ini`} {
		if got := cookie.ReadFixedCookie("", unsafePath); got != "" {
			t.Errorf("unsafe cookie_file %q was not blocked, returned %d bytes", unsafePath, len(got))
		}
	}
	if got := cookie.ReadFixedCookie("session=abc123", ""); got != "session=abc123" {
		t.Errorf("inline cookie string failed: got %q", got)
	}
}

// TestLargeChunkedTextResponseNotTruncated 验证超过 8MB (MaxRewriteSize) 的 Chunked 文本响应不会被截断。
func TestLargeChunkedTextResponseNotTruncated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	largeSize := rewrite.MaxRewriteSize + 512*1024 // 8.5 MB
	payload := bytes.Repeat([]byte("A"), largeSize)

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: -1, // 模拟未知长度的 Chunked 响应
			Header:        http.Header{"Content-Type": []string{"application/javascript"}},
			Body:          io.NopCloser(bytes.NewReader(payload)),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	cfg := &config.Config{
		Upstreams: config.UpstreamMap{
			"test.l.moonchan.xyz": {Host: "test.example.com"},
		},
	}
	engine := NewEngine(cfg)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://test.l.moonchan.xyz:8443/bundle.js", nil)
	req.Host = "test.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != largeSize {
		t.Errorf("large chunked body truncated: got %d bytes, want %d bytes", rec.Body.Len(), largeSize)
	}
}

// TestUnifiedWhitelistPACAndAdultAdInjection 验证：
// 1. 远程唯一白名单（whitelist = 黄网 = 去原有广告 + 加自己广告 + PAC 走 proxy，其他直接 direct）；
// 2. all 模式（AllMode = true）：PAC 对所有网站返回 PROXY，且 HTML 中含成人广告的未知网站也会去广告并加自有推广；
// 3. /__ech_proxy__/ad_script.js、/debug/log、/proxy.pac 与 /statusz 端点正常工作。
func TestUnifiedWhitelistPACAndAdultAdInjection(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logDir := t.TempDir()
	logMgr, err := logger.NewManager(logger.Options{
		LogDir:     logDir,
		ConsoleOut: io.Discard,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer logMgr.Close()
	_, _ = logMgr.Write([]byte("diagnostic log line 1\n"))

	adMgr := NewAdScriptManager(AdScriptOptions{
		Enabled:  true,
		AllMode:  false,
		CacheDir: t.TempDir(),
	})
	adMgr.SetWhitelist([]string{"e-hentai.org", "missav.com"})

	upstreamHTML := `<!DOCTYPE html><html><head><title>Gallery</title><script src="https://syndication.exoclick.com/ads.js"></script></head><body><div class="ad-banner">Ad</div></body></html>`

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":            []string{"text/html; charset=utf-8"},
				"Content-Security-Policy": []string{"script-src 'self'"},
			},
			Body: io.NopCloser(strings.NewReader(upstreamHTML)),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	cfg := &config.Config{
		Upstreams: config.UpstreamMap{
			"ex.l.moonchan.xyz": {Host: "e-hentai.org"},
		},
	}
	engine := NewEngineWithOptions(EngineOptions{
		Config:   cfg,
		AdScript: adMgr,
		Logger:   logMgr,
	})

	// 1. 验证默认白名单模式下 /proxy.pac 包含远程白名单域名 (missav.com / e-hentai.org) 且 GLOBAL_MODE = false
	recPAC := httptest.NewRecorder()
	reqPAC := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/proxy.pac", nil)
	reqPAC.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recPAC, reqPAC)
	pacStr := recPAC.Body.String()
	if !strings.Contains(pacStr, "var GLOBAL_MODE = false;") || !strings.Contains(pacStr, `"missav.com":true`) {
		t.Errorf("default PAC should include remote whitelist domain missav.com and GLOBAL_MODE=false, got: %s", pacStr)
	}

	// 2. 验证 all 模式下 /proxy.pac 设置 GLOBAL_MODE = true（所有网站走 ech-proxy）
	adMgr.SetAllMode(true)
	recPACAll := httptest.NewRecorder()
	reqPACAll := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/proxy.pac", nil)
	reqPACAll.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recPACAll, reqPACAll)
	if !strings.Contains(recPACAll.Body.String(), "var GLOBAL_MODE = true;") {
		t.Errorf("all mode PAC should set GLOBAL_MODE = true, got: %s", recPACAll.Body.String())
	}
	adMgr.SetAllMode(false)

	// 3. 访问白名单中的黄网 (ex.l.moonchan.xyz -> e-hentai.org)：剥离原有广告并注入自有广告脚本
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://ex.l.moonchan.xyz:8443/", nil)
	req.Host = "ex.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec, req)
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, `id="ech-proxy-ad-script"`) || !strings.Contains(bodyStr, `data-is-adult="1"`) {
		t.Errorf("expected injected ad script with data-is-adult=\"1\" in HTML response, got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "syndication.exoclick.com") {
		t.Errorf("expected exoclick ad URL to be stripped from HTML")
	}

	// 4. 关闭 flag (SetEnabled(false)) 时，不再注入脚本
	adMgr.SetEnabled(false)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "https://ex.l.moonchan.xyz:8443/", nil)
	req2.Host = "ex.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), `id="ech-proxy-ad-script"`) {
		t.Errorf("expected no ad script when disabled via flag")
	}
	adMgr.SetEnabled(true)

	// 5. 验证 /__ech_proxy__/ad_script.js 与 /debug/log 端点
	recScript := httptest.NewRecorder()
	reqScript := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/__ech_proxy__/ad_script.js", nil)
	reqScript.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recScript, reqScript)
	if recScript.Code != http.StatusOK || !strings.Contains(recScript.Body.String(), "isAdultWebsite") {
		t.Errorf("/__ech_proxy__/ad_script.js unexpected response: code=%d", recScript.Code)
	}

	recLog := httptest.NewRecorder()
	reqLog := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/debug/log?download=1", nil)
	reqLog.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recLog, reqLog)
	if recLog.Code != http.StatusOK || !strings.Contains(recLog.Body.String(), "diagnostic log line 1") {
		t.Errorf("/debug/log unexpected response: code=%d body=%q", recLog.Code, recLog.Body.String())
	}
}

// TestIssue21AndAutoTransparentReverseProxy 验证：
// 1. 除 l.moonchan.xyz 体系外，所有域名（含多级子域 api.sec.pixiv.net 与双后缀域名 www.dlsite.co.jp）均由本地自签名 CA 动态签发证书，且下发完整证书链与 SKID/AKID (#21)；
// 2. 同一监听端口同时支持 HTTPS 访问与明文 HTTP (/proxy.pac, /ca.pem, /statusz) 自动分流；
// 3. 请求通过自动 SNI/ECH 隧道转发至真实上游。
func TestIssue21AndAutoTransparentReverseProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	buf, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json: %v", err)
	}
	cfg, err := ParseConfig(buf)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"X-Saw-Host":    []string{req.Host},
				"X-Saw-Referer": []string{req.Header.Get("Referer")},
			},
			Body: io.NopCloser(strings.NewReader("ok:" + req.Host)),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	engine := NewEngineWithOptions(EngineOptions{
		Config:    cfg,
		CertStore: store,
		Port:      port,
	})
	tlsCfg := store.TLSConfig(nil)
	srv := &Server{
		Config:    cfg,
		CertStore: store,
		Engine:    engine,
		HTTPServer: &http.Server{
			Handler:   engine,
			TLSConfig: tlsCfg,
		},
		Listener: ln,
		Port:     port,
		IsTLS:    true,
	}
	go srv.Serve()
	defer srv.Close()

	caPEM, err := os.ReadFile(store.CAPath())
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA cert failed")
	}

	// 1. 验证同一端口的明文 HTTP 自助端点 (/proxy.pac, /ca.pem, /statusz)
	plainResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", port))
	if err != nil {
		t.Fatalf("GET plain /proxy.pac on dual-mode port failed: %v", err)
	}
	pacBody, _ := io.ReadAll(plainResp.Body)
	plainResp.Body.Close()
	if !strings.Contains(string(pacBody), "FindProxyForURL") {
		t.Errorf("unexpected /proxy.pac body: %q", string(pacBody))
	}

	// 2. 测试 www.pixiv.net、api.sec.pixiv.net、i.pximg.net、s.pximg.net、www.dlsite.co.jp 以及未列入 upstream.json 的任意域名
	for _, sni := range []string{"www.pixiv.net", "api.sec.pixiv.net", "i.pximg.net", "s.pximg.net", "www.dlsite.co.jp", "custom.site.example"} {
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", port))
				},
				TLSClientConfig: &tls.Config{
					ServerName: sni,
					RootCAs:    roots,
				},
			},
		}
		resp, err := client.Get("https://" + sni + "/test")
		if err != nil {
			t.Fatalf("GET https://%s/test failed: %v", sni, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "ok:"+sni {
			t.Errorf("%s body = %q, want %q", sni, string(b), "ok:"+sni)
		}
		if strings.HasSuffix(sni, "pximg.net") && resp.Header.Get("X-Saw-Referer") != "https://www.pixiv.net/" {
			t.Errorf("%s expected Referer https://www.pixiv.net/, got %q", sni, resp.Header.Get("X-Saw-Referer"))
		}
		// 验证下发了完整证书链（leaf + CA）(#21)
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) < 2 {
			t.Errorf("%s expected full certificate chain (>=2 certs), got %d", sni, len(resp.TLS.PeerCertificates))
		}
	}
}

// TestCertWarningPage 验证上游证书校验失败时渲染区分「过期 / 不一致」的 HTML 警告页，
// 且页面含「强行访问」按钮（?__ech_proxy_force_cert__=<token>），同时验证浏览器并发请求 /favicon.ico 不会覆盖主页面 token。
func TestCertWarningPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orig := roundTripFn
	defer func() { roundTripFn = orig }()

	forceCerts.reset() // 隔离会话级状态（approved / tokens / 限速计数）

	cfg := &config.Config{
		Upstreams: config.UpstreamMap{
			"t.l.moonchan.xyz":  {Host: "truedomain.com"},
			"t2.l.moonchan.xyz": {Host: "truedomain2.com"},
		},
	}
	engine := NewEngine(cfg)

	extractForceToken := func(htmlBody string) string {
		idx := strings.Index(htmlBody, forceCertQueryParam+"=")
		if idx < 0 {
			return ""
		}
		start := idx + len(forceCertQueryParam) + 1
		end := strings.IndexByte(htmlBody[start:], '"')
		if end < 0 {
			return ""
		}
		return htmlBody[start : start+end]
	}

	assertWarning := func(name string, sentinel error, wantText string, forbidden ...string) {
		t.Helper()
		roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
			return nil, fmt.Errorf("dial upstream: %w", sentinel)
		}
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/path", nil)
		r.Host = "t.l.moonchan.xyz:8443"
		engine.ServeHTTP(rec, r)
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("%s: status=%d, want 502", name, rec.Code)
		}
		if ct := rec.Result().Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("%s: content-type=%q, want text/html", name, ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, wantText) {
			t.Errorf("%s: missing 「%s」: %s", name, wantText, body)
		}
		if !strings.Contains(body, "强行访问") {
			t.Errorf("%s: missing 强行访问 button: %s", name, body)
		}
		if extractForceToken(body) == "" {
			t.Errorf("%s: force token missing/empty in href: %s", name, body)
		}
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				t.Errorf("%s: must NOT contain 「%s」: %s", name, f, body)
			}
		}
	}

	// 1. 过期
	assertWarning("expired", cloudflare_ech.ErrCertExpired, "已过期", "不一致", "不可信")
	// 2. 不一致
	assertWarning("mismatch", cloudflare_ech.ErrCertMismatch, "不一致", "已过期", "不可信")
	// 3. 不可信链
	assertWarning("chain", cloudflare_ech.ErrCertUntrusted, "不可信", "已过期", "不一致")

	// 4. 强行访问：一次性 token + 并发 /favicon.ico 容错 + 会话级记忆
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		if !cloudflare_ech.AllowBadCert(req.Context()) {
			return nil, fmt.Errorf("dial upstream: %w", cloudflare_ech.ErrCertMismatch)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader("forced-ok")),
		}, nil
	}
	// 4a. 无参请求主页面 -> 警告页（不一致），提取主页面 token
	rec4a := httptest.NewRecorder()
	r4a := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/path", nil)
	r4a.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec4a, r4a)
	if rec4a.Code != http.StatusBadGateway || !strings.Contains(rec4a.Body.String(), "不一致") {
		t.Fatalf("4a no-param: want 502+不一致, got status=%d body=%q", rec4a.Code, rec4a.Body.String())
	}
	tok := extractForceToken(rec4a.Body.String())
	if tok == "" {
		t.Fatalf("4a: extracted force token empty: %s", rec4a.Body.String())
	}

	// 4a-favicon: 模拟浏览器在渲染警告页后立即自动请求 /favicon.ico，确保不会使主页面的 tok 失效
	recFav := httptest.NewRecorder()
	rFav := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/favicon.ico", nil)
	rFav.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(recFav, rFav)

	// 4b. 用户点击主页面上的「强行访问」按钮（携带主页面 tok）-> 必须成功消费并放行上游
	rec4b := httptest.NewRecorder()
	r4b := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/path?"+forceCertQueryParam+"="+tok, nil)
	r4b.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec4b, r4b)
	if rec4b.Code != http.StatusOK || rec4b.Body.String() != "forced-ok" {
		t.Fatalf("4b valid-token: want 200 forced-ok, got status=%d body=%q", rec4b.Code, rec4b.Body.String())
	}
	// 4c. 再次无参请求同主机 -> 会话级已批准，子资源直接放行（不再警告）
	rec4c := httptest.NewRecorder()
	r4c := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/style.css", nil)
	r4c.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec4c, r4c)
	if rec4c.Code != http.StatusOK || rec4c.Body.String() != "forced-ok" {
		t.Fatalf("4c session-approved: want 200 (no re-warning), got status=%d body=%q", rec4c.Code, rec4c.Body.String())
	}

	// 5. 防内嵌链接静默放行：另一主机 t2（未签发 token、未批准）携带 ?__ech_proxy_force_cert__=1
	//    -> token 不匹配 -> 不放行 -> 照常校验 -> 警告页（不静默放行）
	rec5 := httptest.NewRecorder()
	r5 := httptest.NewRequest(http.MethodGet, "https://t2.l.moonchan.xyz:8443/path?"+forceCertQueryParam+"=1", nil)
	r5.Host = "t2.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec5, r5)
	if rec5.Code != http.StatusBadGateway || !strings.Contains(rec5.Body.String(), "不一致") {
		t.Fatalf("5 embedded-link: want 502+不一致 (not bypassed), got status=%d body=%q", rec5.Code, rec5.Body.String())
	}
}