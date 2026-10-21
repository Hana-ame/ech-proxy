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
// 1. 8443 方案的 certs/l.moonchan.xyz/upstream.json 语法与结构完整合法 (#26)，且通过严格静态校验 ValidateConfig (#8)；
// 2. 在不加载 upstream.json 的 PAC 方案与 443 方案下（空 UpstreamMap），config.Resolve 对任意非 l.moonchan.xyz 域名执行纯粹的原域名自动透传，不内置任何特定域名硬编码。
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

	for _, host := range []string{"pixiv.net", "www.pixiv.net", "account.pixiv.net", "accounts.pixiv.net", "api.sec.pixiv.net"} {
		uc, ok := config.Resolve(cfg.Upstreams, host)
		if !ok || uc.Host != host || uc.IPMode != "v4" {
			t.Errorf("Pixiv host %s resolve mismatch: host=%q ip_mode=%q ok=%v", host, uc.Host, uc.IPMode, ok)
		}
	}

	// 验证完全解耦（空 UpstreamMap）下，任意非门户域名（含 i.pximg.net 与 unlisted.example.org）纯透传且不内置任何硬编码 Referer
	for _, h := range []string{"i.pximg.net", "unlisted.example.org"} {
		autoUC, ok := config.Resolve(nil, h)
		if !ok || autoUC.Host != h || autoUC.Mode != "auto" || autoUC.Referer != "" {
			t.Errorf("decoupled Resolve(nil, %q) = %+v (ok=%v), want pure passthrough with empty Referer", h, autoUC, ok)
		}
	}
}

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

func TestLargeChunkedTextResponseNotTruncated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	largeSize := rewrite.MaxRewriteSize + 512*1024
	payload := bytes.Repeat([]byte("A"), largeSize)

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: -1,
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
	adMgr.SetWhitelist([]string{"e-hentai.org", "missav.com", "pixiv.net"})
	// 成人网站清单（adult.txt）是去广告/注入的唯一闸门；pixiv.net 不在其中。
	adMgr.SetAdultSites([]string{"e-hentai.org", "missav.com"})

	adultHTML := `<!DOCTYPE html><html><head><title>Gallery</title><script src="https://syndication.exoclick.com/ads.js"></script></head><body><div class="ad-banner">Ad</div></body></html>`
	cleanHTML := `<!DOCTYPE html><html><head><title>Pixiv Art</title></head><body><div class="artwork">No adult ads here</div></body></html>`

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		body := adultHTML
		if strings.Contains(req.Host, "pixiv.net") {
			body = cleanHTML
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":            []string{"text/html; charset=utf-8"},
				"Content-Security-Policy": []string{"script-src 'self'"},
			},
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	// 即使 cfg 中含有 upstream.json 规则，PAC 模式下 /proxy.pac 与原域名请求也完全与 upstream.json 解耦
	engine := NewEngineWithOptions(EngineOptions{
		Config: &config.Config{
			Upstreams: config.UpstreamMap{
				"dlsite.l.moonchan.xyz": {Host: "www.dlsite.com"},
			},
			BlockedHosts: []string{"https://fonts.googleapis.com"},
		},
		AdScript: adMgr,
		Logger:   logMgr,
	})

	recPAC := httptest.NewRecorder()
	reqPAC := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/proxy.pac", nil)
	reqPAC.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recPAC, reqPAC)
	pacStr := recPAC.Body.String()
	if !strings.Contains(pacStr, "var GLOBAL_MODE = false;") || !strings.Contains(pacStr, `"missav.com":true`) {
		t.Errorf("default PAC should include remote whitelist domain missav.com and GLOBAL_MODE=false, got: %s", pacStr)
	}
	if strings.Contains(pacStr, "dlsite") {
		t.Errorf("PAC must not leak domains from upstream.json: %s", pacStr)
	}

	adMgr.SetAllMode(true)
	recPACAll := httptest.NewRecorder()
	reqPACAll := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/proxy.pac", nil)
	reqPACAll.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recPACAll, reqPACAll)
	if !strings.Contains(recPACAll.Body.String(), "var GLOBAL_MODE = true;") {
		t.Errorf("all mode PAC should set GLOBAL_MODE = true, got: %s", recPACAll.Body.String())
	}
	adMgr.SetAllMode(false)

	// 1. 不在成人清单中的站点（pixiv.net，即便被 pac.txt 白名单收录） -> 绝不插入广告！
	recClean := httptest.NewRecorder()
	reqClean := httptest.NewRequest(http.MethodGet, "https://pixiv.net/", nil)
	reqClean.Host = "pixiv.net"
	engine.ServeHTTP(recClean, reqClean)
	if strings.Contains(recClean.Body.String(), "slimgather.com") || strings.Contains(recClean.Body.String(), "ech-proxy-ad-script") {
		t.Errorf("whitelisted site WITHOUT adult ads must NOT have ads injected: %s", recClean.Body.String())
	}

	// 2. 成人清单站点（e-hentai.org 含 exoclick） -> 替换并插入自己的成人广告
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://e-hentai.org/", nil)
	req.Host = "e-hentai.org"
	engine.ServeHTTP(rec, req)
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "slimgather.com") || !strings.Contains(bodyStr, "fussyreturn.com") || !strings.Contains(bodyStr, "<script>\n(function(augj){") {
		t.Errorf("expected injected <script> tags for slimgather.com and fussyreturn.com in HTML response, got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "syndication.exoclick.com") {
		t.Errorf("expected exoclick ad URL to be stripped from HTML")
	}

	adMgr.SetSkipAdScript(true)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "https://e-hentai.org/", nil)
	req2.Host = "e-hentai.org"
	engine.ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), "slimgather.com") {
		t.Errorf("expected no advertiser script when --skip-ad-script is enabled")
	}
	if strings.Contains(rec2.Body.String(), "syndication.exoclick.com") {
		t.Errorf("expected original exoclick ad still stripped when only --skip-ad-script is set")
	}
	adMgr.SetSkipAdScript(false)

	adMgr.SetSkipAdBlock(true)
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "https://e-hentai.org/", nil)
	req3.Host = "e-hentai.org"
	engine.ServeHTTP(rec3, req3)
	if !strings.Contains(rec3.Body.String(), "syndication.exoclick.com") {
		t.Errorf("expected original exoclick ad to be preserved when --skip-ad-block is enabled")
	}
	if !strings.Contains(rec3.Body.String(), "slimgather.com") {
		t.Errorf("expected advertiser <script> still injected when only --skip-ad-block is set")
	}
	adMgr.SetSkipAdBlock(false)

	recScript := httptest.NewRecorder()
	reqScript := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/__ech_proxy__/ads.js", nil)
	reqScript.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recScript, reqScript)
	if recScript.Code != http.StatusOK || !strings.Contains(recScript.Body.String(), "fussyreturn.com") {
		t.Errorf("/__ech_proxy__/ads.js unexpected response: code=%d body=%q", recScript.Code, recScript.Body.String())
	}

	recLog := httptest.NewRecorder()
	reqLog := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/debug/log?download=1", nil)
	reqLog.Host = "127.0.0.1:8443"
	engine.ServeHTTP(recLog, reqLog)
	if recLog.Code != http.StatusOK || !strings.Contains(recLog.Body.String(), "diagnostic log line 1") {
		t.Errorf("/debug/log unexpected response: code=%d body=%q", recLog.Code, recLog.Body.String())
	}
}

// TestIssue21AndAutoTransparentReverseProxy 验证不依赖 upstream.json 时：
// 1. 除 l.moonchan.xyz 体系外，所有域名均由本地自签名 CA 动态签发证书，且下发完整证书链 (#21)；
// 2. 同一监听端口同时支持 HTTPS 访问与明文 HTTP (/proxy.pac, /ca.pem, /statusz) 自动分流；
// 3. 请求通过自动 SNI/ECH 隧道原域名透传转发。
func TestIssue21AndAutoTransparentReverseProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	emptyCfg := &config.Config{}

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"X-Saw-Host": []string{req.Host},
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
		Config:    emptyCfg,
		CertStore: store,
		Port:      port,
	})
	tlsCfg := store.TLSConfig(nil)
	srv := &Server{
		Config:    emptyCfg,
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

	plainResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", port))
	if err != nil {
		t.Fatalf("GET plain /proxy.pac on dual-mode port failed: %v", err)
	}
	pacBody, _ := io.ReadAll(plainResp.Body)
	plainResp.Body.Close()
	if !strings.Contains(string(pacBody), "FindProxyForURL") {
		t.Errorf("unexpected /proxy.pac body: %q", string(pacBody))
	}

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
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) < 2 {
			t.Errorf("%s expected full certificate chain (>=2 certs), got %d", sni, len(resp.TLS.PeerCertificates))
		}
	}
}

func TestCertWarningPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orig := roundTripFn
	defer func() { roundTripFn = orig }()

	forceCerts.reset()

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

	assertWarning("expired", cloudflare_ech.ErrCertExpired, "已过期", "不一致", "不可信")
	assertWarning("mismatch", cloudflare_ech.ErrCertMismatch, "不一致", "已过期", "不可信")
	assertWarning("chain", cloudflare_ech.ErrCertUntrusted, "不可信", "已过期", "不一致")

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

	recFav := httptest.NewRecorder()
	rFav := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/favicon.ico", nil)
	rFav.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(recFav, rFav)

	rec4b := httptest.NewRecorder()
	r4b := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/path?"+forceCertQueryParam+"="+tok, nil)
	r4b.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec4b, r4b)
	if rec4b.Code != http.StatusOK || rec4b.Body.String() != "forced-ok" {
		t.Fatalf("4b valid-token: want 200 forced-ok, got status=%d body=%q", rec4b.Code, rec4b.Body.String())
	}

	rec4c := httptest.NewRecorder()
	r4c := httptest.NewRequest(http.MethodGet, "https://t.l.moonchan.xyz:8443/style.css", nil)
	r4c.Host = "t.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec4c, r4c)
	if rec4c.Code != http.StatusOK || rec4c.Body.String() != "forced-ok" {
		t.Fatalf("4c session-approved: want 200 (no re-warning), got status=%d body=%q", rec4c.Code, rec4c.Body.String())
	}

	rec5 := httptest.NewRecorder()
	r5 := httptest.NewRequest(http.MethodGet, "https://t2.l.moonchan.xyz:8443/path?"+forceCertQueryParam+"=1", nil)
	r5.Host = "t2.l.moonchan.xyz:8443"
	engine.ServeHTTP(rec5, r5)
	if rec5.Code != http.StatusBadGateway || !strings.Contains(rec5.Body.String(), "不一致") {
		t.Fatalf("5 embedded-link: want 502+不一致 (not bypassed), got status=%d body=%q", rec5.Code, rec5.Body.String())
	}
}

func TestPlainHTTPAndHTTPSProxyRoutingAndFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orig := roundTripFn
	defer func() { roundTripFn = orig }()

	var seenSchemes []string
	var seenProxyConn string
	var seenPostBody string

	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		seenSchemes = append(seenSchemes, req.URL.Scheme+"://"+req.URL.Host+req.URL.RequestURI())
		seenProxyConn = req.Header.Get("Proxy-Connection")
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			seenPostBody = string(b)
		}
		if strings.HasPrefix(req.Host, "http-only.example.com") && req.URL.Scheme == "https" {
			return nil, fmt.Errorf("dial tcp: connection refused")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader("ok:" + req.Method + ":" + req.URL.Scheme + "://" + req.URL.Host + req.URL.RequestURI())),
		}, nil
	}

	cfg := &config.Config{
		Upstreams: config.UpstreamMap{
			"pixiv.net": {Host: "www.pixiv.net"},
		},
	}
	engine := NewEngine(cfg)

	seenSchemes = nil
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "http://http-only.example.com/submit?k=1", strings.NewReader("payload=123"))
	req1.Host = "http-only.example.com"
	req1.RequestURI = "http://http-only.example.com/submit?k=1"
	req1.Header.Set("Proxy-Connection", "keep-alive")
	engine.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK || rec1.Body.String() != "ok:POST:http://http-only.example.com/submit?k=1" {
		t.Fatalf("HTTP fallback failed: code=%d body=%q", rec1.Code, rec1.Body.String())
	}
	if len(seenSchemes) != 2 || !strings.HasPrefix(seenSchemes[0], "https://") || !strings.HasPrefix(seenSchemes[1], "http://") {
		t.Errorf("expected https attempt followed by http fallback, got %v", seenSchemes)
	}
	if seenProxyConn != "" {
		t.Errorf("Proxy-Connection header leaked to upstream: %q", seenProxyConn)
	}
	if seenPostBody != "payload=123" {
		t.Errorf("POST body lost during https->http fallback: got %q, want payload=123", seenPostBody)
	}

	seenSchemes = nil
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "http://legacy.example.com:8080/api", nil)
	req2.Host = "legacy.example.com:8080"
	req2.RequestURI = "http://legacy.example.com:8080/api"
	engine.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || len(seenSchemes) != 1 || seenSchemes[0] != "http://legacy.example.com:8080/api" {
		t.Errorf("custom port HTTP request mismatch: code=%d schemes=%v body=%q", rec2.Code, seenSchemes, rec2.Body.String())
	}

	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "https://pixiv.net/", strings.NewReader("login=1"))
	req3.Host = "pixiv.net"
	engine.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "ok:POST:https://www.pixiv.net/" {
		t.Errorf("POST / on proxied host failed: code=%d body=%q", rec3.Code, rec3.Body.String())
	}
}

func TestHeadAndNoContentResponsesPreserveHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orig := roundTripFn
	defer func() { roundTripFn = orig }()

	adMgr := NewAdScriptManager(AdScriptOptions{
		Enabled:  true,
		CacheDir: t.TempDir(),
	})
	adMgr.SetAdultSites([]string{"e-hentai.org"})

	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":   []string{"text/html; charset=utf-8"},
					"Content-Length": []string{"98765"},
				},
				Body: io.NopCloser(strings.NewReader("")),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header: http.Header{
				"Content-Type": []string{"text/html; charset=utf-8"},
			},
			Body: io.NopCloser(strings.NewReader("")),
		}, nil
	}

	engine := NewEngineWithOptions(EngineOptions{
		Config:   &config.Config{},
		AdScript: adMgr,
	})

	recHead := httptest.NewRecorder()
	reqHead := httptest.NewRequest(http.MethodHead, "https://e-hentai.org/index.html", nil)
	reqHead.Host = "e-hentai.org"
	engine.ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", recHead.Code)
	}
	if gotCL := recHead.Header().Get("Content-Length"); gotCL != "98765" {
		t.Errorf("HEAD Content-Length clobbered: got %q, want 98765", gotCL)
	}
	if recHead.Body.Len() != 0 {
		t.Errorf("HEAD response must not have body bytes, got %d", recHead.Body.Len())
	}

	rec204 := httptest.NewRecorder()
	req204 := httptest.NewRequest(http.MethodGet, "https://e-hentai.org/ping", nil)
	req204.Host = "e-hentai.org"
	engine.ServeHTTP(rec204, req204)
	if rec204.Code != http.StatusNoContent {
		t.Fatalf("204 status = %d, want 204", rec204.Code)
	}
	if rec204.Body.Len() != 0 {
		t.Errorf("204 response must not have injected body, got %q", rec204.Body.String())
	}
}
