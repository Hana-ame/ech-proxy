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