package echproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
)

func TestParseConnectTargetRejectsMalformedAndPrefersRequestURI(t *testing.T) {
	badCases := []string{
		"",
		"example.com",
		":443",
		"example.com:",
		"example.com:0",
		"example.com:65536",
		"example.com:abc",
		"https://example.com:443",
		"/path/only",
	}
	for _, raw := range badCases {
		req := &http.Request{Method: http.MethodConnect, RequestURI: raw, Host: raw}
		if h, p, err := parseConnectTarget(req); err == nil {
			t.Errorf("parseConnectTarget(%q) unexpectedly succeeded: host=%q port=%q", raw, h, p)
		}
	}

	// RequestURI authority 优先于 Host
	req := &http.Request{
		Method:     http.MethodConnect,
		RequestURI: "preferred.example.com:8443",
		Host:       "fallback.example.com:443",
	}
	h, p, err := parseConnectTarget(req)
	if err != nil || h != "preferred.example.com" || p != "8443" {
		t.Errorf("parseConnectTarget = (%q, %q, %v), want (preferred.example.com, 8443, nil)", h, p, err)
	}
}

func TestConnectDisabledReturns405(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.RequestURI = "example.com:443"

	handleHTTPConnect(rec, req, ConnectOptions{Enabled: false})
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("disabled CONNECT status = %d, want 405", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "-allow-connect") {
		t.Errorf("disabled CONNECT body = %q, want mention of -allow-connect", rec.Body.String())
	}
}

func TestConnectAuthSSRFAndConcurrencyLimits(t *testing.T) {
	var dialCalls atomic.Int32
	origDial := dialConnectFn
	dialConnectFn = func(ctx context.Context, host, port, ipMode string) (net.Conn, error) {
		dialCalls.Add(1)
		return nil, errors.New("should not dial")
	}
	defer func() { dialConnectFn = origDial }()

	auth := &AuthConfig{Token: "secret-token"}
	limiter := NewTunnelLimiter(2, 3)
	opts := ConnectOptions{
		Enabled: true,
		Mode:    ConnectModeTunnel,
		Auth:    auth,
		Limiter: limiter,
		Config:  &config.Config{BlockedHosts: []string{"https://blocked.example.com"}},
	}

	// 1. 缺少凭证 -> 407 Proxy Authentication Required
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.RequestURI = "example.com:443"
	req.RemoteAddr = "192.0.2.10:12345"
	handleHTTPConnect(rec, req, opts)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("missing auth status = %d, want 407", rec.Code)
	}

	// 2. SSRF 拦截（169.254.169.254 与 127.0.0.1 及 blocked_hosts）-> 403 Forbidden，且不消耗限流配额、不拨号
	for _, forbidden := range []string{"169.254.169.254:80", "127.0.0.1:8080", "localhost:443", "blocked.example.com:443"} {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodConnect, "http://"+forbidden, nil)
		req.RequestURI = forbidden
		req.RemoteAddr = "192.0.2.10:12345"
		req.Header.Set("Proxy-Authorization", "Bearer secret-token")
		handleHTTPConnect(rec, req, opts)
		if rec.Code != http.StatusForbidden {
			t.Errorf("SSRF target %q status = %d, want 403", forbidden, rec.Code)
		}
	}
	if dialCalls.Load() != 0 {
		t.Errorf("dialConnectFn called %d times on 401/403 targets, want 0", dialCalls.Load())
	}
	if limiter.ActiveCount() != 0 {
		t.Errorf("403 SSRF targets leaked limiter quota: active=%d", limiter.ActiveCount())
	}

	// 3. 验证 per-peer 与 global 限流器
	rel1, ok1 := limiter.Acquire("198.51.100.1")
	rel2, ok2 := limiter.Acquire("198.51.100.1")
	_, ok3 := limiter.Acquire("198.51.100.1") // 超过 per-peer 上限 2
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-peer acquire got (%v, %v, %v), want (true, true, false)", ok1, ok2, ok3)
	}

	// Peer A 满额不影响 Peer B（直到触及 global 上限 3）
	relB1, okB1 := limiter.Acquire("198.51.100.2")
	_, okB2 := limiter.Acquire("198.51.100.2") // 触及 global 上限 3
	if !okB1 || okB2 {
		t.Fatalf("peer B acquire got (%v, %v), want (true, false)", okB1, okB2)
	}

	// 归还配额后可再次申请
	rel1()
	rel2()
	relB1()
	if limiter.ActiveCount() != 0 {
		t.Errorf("active count after release = %d, want 0", limiter.ActiveCount())
	}
}

func TestConnectUnreachableUpstreamReturns502AndPipelinedBytesRelay(t *testing.T) {
	// 启动本地回显 TCP 服务端模拟上游
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 10)
				if _, err := io.ReadFull(conn, buf); err == nil {
					_, _ = conn.Write([]byte("ECHO:" + string(buf)))
				}
			}(c)
		}
	}()

	origDial := dialConnectFn
	dialConnectFn = func(ctx context.Context, host, port, ipMode string) (net.Conn, error) {
		if host == "unreachable.example.com" {
			return nil, errors.New("connection refused")
		}
		return net.Dial("tcp", upLn.Addr().String())
	}
	defer func() { dialConnectFn = origDial }()

	opts := ConnectOptions{
		Enabled: true,
		Mode:    ConnectModeTunnel,
		Limiter: NewTunnelLimiter(10, 20),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleHTTPConnect(w, r, opts)
	}))
	defer srv.Close()

	// 1. 不可达上游返回 502 Bad Gateway
	conn1, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	_, _ = conn1.Write([]byte("CONNECT unreachable.example.com:443 HTTP/1.1\r\nHost: unreachable.example.com:443\r\n\r\n"))
	br1 := bufio.NewReader(conn1)
	resp1, err := http.ReadResponse(br1, nil)
	if err != nil {
		t.Fatalf("read 502 response: %v", err)
	}
	if resp1.StatusCode != http.StatusBadGateway {
		t.Errorf("unreachable upstream status = %d, want 502", resp1.StatusCode)
	}

	// 2. Pipelined 字节（与 CONNECT 请求放在同一 TCP 报文发出）完整转发至上游并回显
	conn2, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	pipelinedPayload := "0123456789"
	_, _ = conn2.Write([]byte("CONNECT valid.example.com:443 HTTP/1.1\r\nHost: valid.example.com:443\r\n\r\n" + pipelinedPayload))

	br2 := bufio.NewReader(conn2)
	resp2, err := http.ReadResponse(br2, nil)
	if err != nil || resp2.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT valid response = %v, %v", resp2, err)
	}
	echoBuf := make([]byte, 15)
	if _, err := io.ReadFull(br2, echoBuf); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(echoBuf) != "ECHO:0123456789" {
		t.Errorf("echoed bytes = %q, want %q", string(echoBuf), "ECHO:0123456789")
	}
}

func TestRelayClosesBothSidesWhenOneEndDiesAndErrorClassification(t *testing.T) {
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()

	done := make(chan struct{})
	go func() {
		relay(c2, u1)
		close(done)
	}()

	// 模拟上游返回数据后主动关闭，而客户端保持静默（B1）
	_, _ = u2.Write([]byte("hello"))
	buf := make([]byte, 5)
	_, _ = io.ReadFull(c1, buf)
	_ = u2.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay hung when upstream closed while client stayed idle")
	}

	// B4: 验证错误分类器不吞掉 TLS/证书错误
	if !isExpectedConnError(net.ErrClosed) || !isExpectedConnError(errors.New("read: connection reset by peer")) {
		t.Error("expected network close errors to be classified as expected")
	}
	if isExpectedConnError(errors.New("tls: bad certificate")) || isExpectedConnError(errors.New("x509: certificate signed by unknown authority")) {
		t.Error("TLS/x509 certificate errors must NOT be classified as expected conn errors")
	}
}

func TestConnectSmartMITMRoutesThroughECHProxyPipeline(t *testing.T) {
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

	origRT := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"X-Via-MITM": []string{"true"},
				"X-Referer":  []string{req.Header.Get("Referer")},
			},
			Body: io.NopCloser(strings.NewReader("mitm-ok:" + req.Host)),
		}, nil
	}
	defer func() { roundTripFn = origRT }()

	engine := NewEngineWithOptions(EngineOptions{Config: cfg, CertStore: store})
	opts := ConnectOptions{
		Enabled:     true,
		Mode:        ConnectModeMITM,
		CertStore:   store,
		Config:      cfg,
		HTTPHandler: engine,
		Limiter:     NewTunnelLimiter(10, 20),
	}

	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleHTTPConnect(w, r, opts)
			return
		}
		engine.ServeHTTP(w, r)
	}))
	defer proxySrv.Close()

	caPEM, _ := store.CAPEM()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	proxyURL, _ := http.NewRequest(http.MethodGet, proxySrv.URL, nil)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL.URL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
	}

	// 通过标准 HTTP CONNECT 正向代理直接访问 i.pximg.net 与多级子域 api.sec.pixiv.net（无需改 hosts、无需 443 端口！）
	for _, target := range []string{"https://i.pximg.net/img-original/test.jpg", "https://api.sec.pixiv.net/v1/check"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("CONNECT MITM GET %s failed: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Header.Get("X-Via-MITM") != "true" {
			t.Errorf("%s missing X-Via-MITM header", target)
		}
		if strings.Contains(target, "i.pximg.net") && resp.Header.Get("X-Referer") != "https://www.pixiv.net/" {
			t.Errorf("i.pximg.net via CONNECT MITM missing anti-hotlink Referer, got %q", resp.Header.Get("X-Referer"))
		}
		if !strings.HasPrefix(string(body), "mitm-ok:") {
			t.Errorf("%s unexpected body %q", target, string(body))
		}
	}
}