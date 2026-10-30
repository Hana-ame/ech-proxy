package echproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.RequestURI = "example.com:443"
	req.RemoteAddr = "192.0.2.10:12345"
	handleHTTPConnect(rec, req, opts)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("missing auth status = %d, want 407", rec.Code)
	}

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

	rel1, ok1 := limiter.Acquire("198.51.100.1")
	rel2, ok2 := limiter.Acquire("198.51.100.1")
	_, ok3 := limiter.Acquire("198.51.100.1")
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("per-peer acquire got (%v, %v, %v), want (true, true, false)", ok1, ok2, ok3)
	}

	relB1, okB1 := limiter.Acquire("198.51.100.2")
	_, okB2 := limiter.Acquire("198.51.100.2")
	if !okB1 || okB2 {
		t.Fatalf("peer B acquire got (%v, %v), want (true, false)", okB1, okB2)
	}

	rel1()
	rel2()
	relB1()
	if limiter.ActiveCount() != 0 {
		t.Errorf("active count after release = %d, want 0", limiter.ActiveCount())
	}
}

func TestConnectUnreachableUpstreamReturns502AndPipelinedBytesRelay(t *testing.T) {
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

	_, _ = u2.Write([]byte("hello"))
	buf := make([]byte, 5)
	_, _ = io.ReadFull(c1, buf)
	_ = u2.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay hung when upstream closed while client stayed idle")
	}

	if !isExpectedConnError(net.ErrClosed) || !isExpectedConnError(errors.New("read: connection reset by peer")) {
		t.Error("expected network close errors to be classified as expected")
	}
	if isExpectedConnError(errors.New("tls: bad certificate")) || isExpectedConnError(errors.New("x509: certificate signed by unknown authority")) {
		t.Error("TLS/x509 certificate errors must NOT be classified as expected conn errors")
	}
}

// TestConnectSmartMITMRoutesThroughECHProxyPipeline 验证 PAC MITM 方案在完全不加载 upstream.json 的情况下，
// 复用本地 CA (CertStore) 与 ECH/SNI 管道直接代理任意域名，且不内置任何硬编码 Referer。
func TestConnectSmartMITMRoutesThroughECHProxyPipeline(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	emptyCfg := &config.Config{}

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

	engine := NewEngineWithOptions(EngineOptions{Config: emptyCfg, CertStore: store})
	opts := ConnectOptions{
		Enabled:     true,
		Mode:        ConnectModeMITM,
		CertStore:   store,
		Config:      emptyCfg,
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
		if resp.Header.Get("X-Referer") != "" {
			t.Errorf("%s must not have built-in Referer when client did not send one, got %q", target, resp.Header.Get("X-Referer"))
		}
		if !strings.HasPrefix(string(body), "mitm-ok:") {
			t.Errorf("%s unexpected body %q", target, string(body))
		}
	}
}

func TestSingleConnListenerNoPanicOnMultipleClose(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	l := newSingleConnListener(c1)
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		go func() {
			_ = conn.Close()
		}()
		go func() {
			_ = l.Close()
		}()
	}

	time.Sleep(30 * time.Millisecond)
	_ = conn.Close()
	_ = l.Close()
}

func TestSingleConnListenerAndCloseNotifyConnNoDoubleClosePanic(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ln := newSingleConnListener(c1)
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("first Accept failed: %v", err)
	}

	// Simulate http.Server closing the accepted closeNotifyConn first,
	// followed by http.Server.Serve's defer onceCloseListener.Close() -> singleConnListener.Close().
	if err := accepted.Close(); err != nil {
		t.Fatalf("accepted.Close failed: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close after accepted.Close failed: %v", err)
	}
	// Repeat calls must be idempotent and never panic with "close of closed channel".
	_ = accepted.Close()
	_ = ln.Close()

	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("second Accept after close = %v, want net.ErrClosed", err)
	}
}
func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name string
		conn string
		upg  string
		want bool
	}{
		{"plain", "Upgrade", "websocket", true},
		{"case-insensitive", "keep-alive, Upgrade", "WebSocket", true},
		{"no-connection", "", "websocket", false},
		{"no-upgrade", "Upgrade", "", false},
		{"not-websocket", "Upgrade", "h2c", false},
	}
	for _, c := range cases {
		req := &http.Request{Header: http.Header{}}
		if c.conn != "" {
			req.Header.Set("Connection", c.conn)
		}
		if c.upg != "" {
			req.Header.Set("Upgrade", c.upg)
		}
		if got := isWebSocketUpgrade(req); got != c.want {
			t.Errorf("%s: isWebSocketUpgrade=%v want %v", c.name, got, c.want)
		}
	}
}

func TestWriteRawUpgradeRequestPreservesHopByHopHeaders(t *testing.T) {
	req := &http.Request{
		Method:     http.MethodGet,
		RequestURI: "/chat?x=1",
		Host:       "ws.example.com",
		Header: http.Header{
			"Connection":            []string{"Upgrade"},
			"Upgrade":               []string{"websocket"},
			"Sec-Websocket-Version": []string{"13"},
			"Sec-Websocket-Key":     []string{"dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
	var buf strings.Builder
	if err := writeRawUpgradeRequest(&buf, req, "ws.example.com", "443"); err != nil {
		t.Fatalf("writeRawUpgradeRequest: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"GET /chat?x=1 HTTP/1.1\r\n",
		"Host: ws.example.com\r\n",
		"Connection: Upgrade\r\n",
		"Upgrade: websocket\r\n",
		"Sec-Websocket-Version: 13\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("raw upgrade request missing %q in:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\r\n\r\n") {
		t.Errorf("raw upgrade request must end with blank line, got %q", out)
	}
}

// TestServeWebSocketMITMRelaysPlaintextUpgrade 验证 MITM 隧道内的 WebSocket 升级：
// 逐跳头被保留、101 原样回传、升级后双向字节流可互通（issue #43）。
func TestServeWebSocketMITMRelaysPlaintextUpgrade(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	const payload = "hello-websocket-frames"
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		sawUpgrade := false
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.EqualFold(strings.TrimSpace(line), "Upgrade: websocket") {
				sawUpgrade = true
			}
			if line == "\r\n" {
				break
			}
		}
		if !sawUpgrade {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		buf := make([]byte, 1024)
		for {
			n, err := br.Read(buf)
			if n > 0 {
				_, _ = c.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	origDial := dialConnectFn
	dialConnectFn = func(ctx context.Context, host, port, ipMode string) (net.Conn, error) {
		return net.Dial("tcp", upLn.Addr().String())
	}
	defer func() { dialConnectFn = origDial }()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWebSocketMITM(w, r, "ws.example.com", "80", false, ConnectOptions{})
	})}
	go proxySrv.Serve(proxyLn)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /chat HTTP/1.1\r\nHost: ws.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"))

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read upgrade status: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("upgrade status line = %q, want 101", statusLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write frames: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("read echoed frames: %v", err)
	}
	if string(echo) != payload {
		t.Errorf("echoed frames = %q, want %q", string(echo), payload)
	}
}

// TestTunnelLimiterDeletesPeerEntryWhenIdle 验证 issue #45：
// 计数归零时必须删除 peer 条目，否则每个出现过的客户端 IP 会永久残留。
func TestTunnelLimiterDeletesPeerEntryWhenIdle(t *testing.T) {
	l := NewTunnelLimiter(2, 10)
	rel, ok := l.Acquire("203.0.113.9")
	if !ok {
		t.Fatal("Acquire failed")
	}
	if _, present := l.peers.Load("203.0.113.9"); !present {
		t.Fatal("peer must be tracked while a tunnel is active")
	}
	rel()
	if _, present := l.peers.Load("203.0.113.9"); present {
		t.Error("peer entry must be deleted when its counter reaches zero")
	}
	if l.ActiveCount() != 0 {
		t.Errorf("active count = %d, want 0", l.ActiveCount())
	}
}

// TestAuthConfigCheckPurgesExpiredFailures 验证 issue #45：
// failures map 达到阈值时必须清扫已过窗口的条目，避免来源 IP 记录无界增长。
func TestAuthConfigCheckPurgesExpiredFailures(t *testing.T) {
	a := &AuthConfig{Token: "secret"}
	a.mu.Lock()
	a.failures = make(map[string]*authFailWindow, authFailuresPurgeThreshold+16)
	for i := 0; i < authFailuresPurgeThreshold+8; i++ {
		a.failures[fmt.Sprintf("198.51.100.%d", i)] = &authFailWindow{
			count:     1,
			windowEnd: time.Now().Add(-time.Minute),
		}
	}
	a.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if ok, err := a.Check(req, "203.0.113.1"); ok || err != nil {
		t.Fatalf("Check with bad credentials = (%v, %v), want (false, nil)", ok, err)
	}

	a.mu.Lock()
	n := len(a.failures)
	a.mu.Unlock()
	if n >= authFailuresPurgeThreshold {
		t.Errorf("expired auth failures not purged: len=%d", n)
	}
}
