package echproxy

import (
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

	"github.com/gin-gonic/gin"
)

// TestShippedUpstreamJSONCompatibility 验证未改动的 certs/l.moonchan.xyz/upstream.json
// 可被完整解析，且同时满足 8443 门户模式与 443 本地模式的路由需求。
func TestShippedUpstreamJSONCompatibility(t *testing.T) {
	buf, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json: %v", err)
	}
	if err := json.Unmarshal(buf, &map[string]any{}); err != nil {
		t.Fatalf("upstream.json invalid JSON: %v", err)
	}
	cfg, err := ParseConfig(buf)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	// 1. 验证 8443 门户泛域名模式（如 iwara-xxx.l.moonchan.xyz -> xxx.iwara.tv）
	iwaraSub, ok := MatchWildcardForTest(cfg.Upstreams, "iwara-api.l.moonchan.xyz")
	if !ok || iwaraSub.Host != "api.iwara.tv" {
		t.Errorf("8443 wildcard iwara-api.l.moonchan.xyz -> got %q (ok=%v), want api.iwara.tv", iwaraSub.Host, ok)
	}

	// 2. 验证 443 本地透明反代模式（pixiv.net 主域名及 *.pixiv.net 子域名）
	apex, ok := cfg.Upstreams["pixiv.net"]
	if !ok || apex.Host != "pixiv.net" || apex.IPMode != "v4" {
		t.Errorf("443 apex pixiv.net config mismatch: %+v (ok=%v)", apex, ok)
	}
	for _, sub := range []string{"www.pixiv.net", "account.pixiv.net", "api.sec.pixiv.net"} {
		uc, ok := MatchWildcardForTest(cfg.Upstreams, sub)
		if !ok || uc.Host != sub || uc.IPMode != "v4" {
			t.Errorf("443 wildcard %s -> got host=%q ip_mode=%q (ok=%v)", sub, uc.Host, uc.IPMode, ok)
		}
	}
}

// TestMode1_8443PortalAndRewrite 验证功能一（8443 门户反向代理模式）：
// 门户列表渲染、子域名路由、响应体域名替换与 Service Worker 注入。
func TestMode1_8443PortalAndRewrite(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rawCfg := `{
		"upstreams": {
			"l.moonchan.xyz": {
				"host": "reminder.moonchan.xyz",
				"mode": "direct",
				"display": false
			},
			"dlsite.l.moonchan.xyz": {
				"host": "www.dlsite.com",
				"ip_mode": "v4",
				"referer": "https://www.dlsite.com/",
				"display": true,
				"sw_inject": true,
				"rewrites": {
					"www.dlsite.com": "dlsite.l.moonchan.xyz",
					"img.dlsite.jp": "dlsite-img.l.moonchan.xyz"
				}
			}
		},
		"blocked_hosts": ["https://www.googletagmanager.com"]
	}`
	cfg, err := ParseConfig([]byte(rawCfg))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		body := `<html><head><script src="https://www.googletagmanager.com/gtm.js"></script></head><body>https://www.dlsite.com/home and https://img.dlsite.jp/a.jpg</body></html>`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	engine := NewEngine(cfg)

	// 1. 访问门户首页 l.moonchan.xyz:8443/
	reqPortal := httptest.NewRequest(http.MethodGet, "/", nil)
	reqPortal.Host = "l.moonchan.xyz:8443"
	wPortal := httptest.NewRecorder()
	engine.ServeHTTP(wPortal, reqPortal)
	if wPortal.Code != http.StatusOK || !strings.Contains(wPortal.Body.String(), "dlsite.l.moonchan.xyz:8443") {
		t.Errorf("portal page failed: code=%d body=%s", wPortal.Code, wPortal.Body.String())
	}

	// 2. 访问代理站点 dlsite.l.moonchan.xyz:8443/home
	reqProxy := httptest.NewRequest(http.MethodGet, "/home", nil)
	reqProxy.Host = "dlsite.l.moonchan.xyz:8443"
	wProxy := httptest.NewRecorder()
	engine.ServeHTTP(wProxy, reqProxy)
	out := wProxy.Body.String()
	if !strings.Contains(out, "https://dlsite.l.moonchan.xyz:8443/home") {
		t.Errorf("expected domain rewrite to dlsite.l.moonchan.xyz:8443, got: %s", out)
	}
	if !strings.Contains(out, "https://dlsite-img.l.moonchan.xyz:8443/a.jpg") {
		t.Errorf("expected CDN domain rewrite, got: %s", out)
	}
	if strings.Contains(out, "googletagmanager.com") {
		t.Errorf("expected blocked host stripped, got: %s", out)
	}
	if !strings.Contains(out, "navigator.serviceWorker.register('/sw.js')") {
		t.Errorf("expected SW registration injected, got: %s", out)
	}
}

// TestMode2_443LocalReverseProxyEndToEnd 验证功能二（443 本地透明反向代理模式）：
// 自生成本地 CA、按需动态签发域名通配符证书，以及原域名（如 www.pixiv.net）端到端转发。
func TestMode2_443LocalReverseProxyEndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	rawCfg := `{
		"upstreams": {
			"pixiv.net": {
				"host": "pixiv.net",
				"ip_mode": "v4",
				"wildcard": {
					"entry_suffix": ".pixiv.net",
					"upstream_suffix": ".pixiv.net"
				}
			}
		}
	}`
	cfg, err := ParseConfig([]byte(rawCfg))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		if ipMode != "v4" {
			t.Errorf("expected ipMode=v4, got %q", ipMode)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-Upstream-Host": []string{req.Host}},
			Body:       io.NopCloser(strings.NewReader("ok:" + req.Host)),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	tlsCfg := store.TLSConfig(indexHost, nil)
	httpSrv := &http.Server{
		Handler:   NewEngine(cfg),
		TLSConfig: tlsCfg,
	}
	go httpSrv.Serve(tls.NewListener(ln, tlsCfg))
	defer httpSrv.Close()

	caPEM, err := os.ReadFile(store.CAPath())
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA cert failed")
	}

	for _, sni := range []string{"www.pixiv.net", "account.pixiv.net"} {
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
		resp, err := client.Get("https://" + sni + "/artworks/1")
		if err != nil {
			t.Fatalf("GET https://%s failed: %v", sni, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "ok:"+sni {
			t.Errorf("body = %q, want %q", string(b), "ok:"+sni)
		}
	}
}
