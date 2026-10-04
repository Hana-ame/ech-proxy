package echproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// startEchoTLSServer runs a real TLS server that answers any request with
// "hello from <sni>". Using a genuine TLS origin is what makes the tunnel
// criterion meaningful: a byte counter would pass even if TLS were broken.
func startEchoTLSServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.Host)
	}))
	return srv.Listener.Addr().String(), srv.Close
}

// newConnectTestServer builds a gin engine wired exactly like production:
// SetupRouter with allowConnect, and the dial hook pointed at a local listener.
func newConnectTestServer(t *testing.T, allowConnect bool, dialTo string) (*httptest.Server, func()) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &Config{
		Upstreams: UpstreamMap{
			"l.moonchan.xyz": UpstreamConfig{Host: "reminder.moonchan.xyz", Mode: "direct"},
		},
		UpstreamOrder: []string{"l.moonchan.xyz"},
	}
	r := gin.New()
	r.Use(gin.Recovery())
	SetupRouter(r, cfg, allowConnect)

	orig := connectDialFn
	connectDialFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
		return net.Dial("tcp", dialTo)
	}

	srv := httptest.NewServer(r)
	return srv, func() {
		srv.Close()
		connectDialFn = orig
	}
}

// --- the headline criterion: a real TLS round trip through the tunnel -----

func TestConnectTunnelCarriesRealTLSRoundTrip(t *testing.T) {
	originAddr, closeOrigin := startEchoTLSServer(t)
	defer closeOrigin()

	proxySrv, closeProxy := newConnectTestServer(t, true, originAddr)
	defer closeProxy()

	// Speak CONNECT by hand: Go's http.Client has no CONNECT support, and a
	// hand-written client is also the honest test of the wire behavior.
	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originAddr, originAddr); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The origin is a TLS server; complete a handshake through the tunnel.
	tc := tls.Client(conn, &tls.Config{
		ServerName:         "tunnel.test",
		InsecureSkipVerify: true,
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake through tunnel failed: %v", err)
	}

	// And an actual HTTP request/response over that TLS session.
	fmt.Fprintf(tc, "GET /probe HTTP/1.1\r\nHost: tunnel.test\r\nConnection: close\r\n\r\n")
	body, err := io.ReadAll(io.LimitReader(tc, 4096))
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "hello from tunnel.test") {
		t.Errorf("expected origin greeting, got %q", string(body))
	}
}

// --- disabled by default ---------------------------------------------------

func TestConnectDisabledByDefault(t *testing.T) {
	originAddr, closeOrigin := startEchoTLSServer(t)
	defer closeOrigin()

	proxySrv, closeProxy := newConnectTestServer(t, false, originAddr)
	defer closeProxy()

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originAddr, originAddr)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 when CONNECT is disabled, got %d", resp.StatusCode)
	}
}

// --- unrouteable upstream --------------------------------------------------

func TestConnectUnreachableUpstreamReturns502(t *testing.T) {
	// Port 1 on loopback: nothing listens there, so the dial must fail fast.
	proxySrv, closeProxy := newConnectTestServer(t, true, "127.0.0.1:1")
	defer closeProxy()

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	fmt.Fprintf(conn, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 for unreachable target, got %d", resp.StatusCode)
	}
}

// TestConnectForwardsPipelinedBytes covers a real failure mode: a client that
// writes its TLS ClientHello in the same TCP segment as the CONNECT request.
// Those bytes sit in the hijack buffer before any relay starts, so a handler
// that ignores them silently eats the start of the handshake. The symptom on
// the client side is a confusing TLS error rather than anything pointing at
// the proxy.
func TestConnectForwardsPipelinedBytes(t *testing.T) {
	// A raw TCP origin that echoes whatever it first receives. Using a plain
	// echo (not TLS) lets the test assert on exact bytes, which is the point:
	// this is about byte fidelity, not protocol success.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	const pipelinedPayload = "pipelined!"

	received := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(pipelinedPayload))
		n, _ := io.ReadFull(c, buf)
		received <- string(buf[:n])
	}()

	proxySrv, closeProxy := newConnectTestServer(t, true, ln.Addr().String())
	defer closeProxy()

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	// CONNECT and the payload in ONE write, so the payload is buffered by the
	// server before it hijacks.
	authority := ln.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", authority, authority, pipelinedPayload)

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case got := <-received:
		if got != pipelinedPayload {
			t.Errorf("origin received %q, want %q — pipelined bytes were dropped", got, pipelinedPayload)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin never received the pipelined payload")
	}
}

// --- malformed CONNECT targets --------------------------------------------

func TestParseConnectTargetRejectsMalformed(t *testing.T) {
	bad := []string{
		"example.com",       // missing port
		":443",              // missing host
		"example.com:0",     // port out of range
		"example.com:70000", // port out of range
		"example.com:http",  // non-numeric port
		"",                  // empty
	}
	for _, authority := range bad {
		if _, err := parseConnectTarget(authority, nil); err == nil {
			t.Errorf("expected %q to be rejected", authority)
		}
	}
}

func TestParseConnectTargetAcceptsValid(t *testing.T) {
	got, err := parseConnectTarget("example.com:443", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.host != "example.com" || got.port != 443 {
		t.Errorf("got %+v, want example.com:443", got)
	}
}

func TestParseConnectTargetPrefersRequestURI(t *testing.T) {
	// Some clients send the authority in the request line, not the Host header.
	u, err := url.Parse("http://from-uri.example:8443")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := parseConnectTarget("from-header.example:443", u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.host != "from-uri.example" || got.port != 8443 {
		t.Errorf("got %+v, want from-uri.example:8443", got)
	}
}

// --- relay semantics -------------------------------------------------------

// TestRelayForwardsBothDirections is the criterion that the tunnel is actually
// a bidirectional pipe, not a one-way write.
func TestRelayForwardsBothDirections(t *testing.T) {
	proxyClientSide, clientSide := net.Pipe()
	proxyUpstreamSide, originSide := net.Pipe()
	defer originSide.Close()

	relayDone := make(chan struct{})
	go func() {
		relay(proxyClientSide, proxyUpstreamSide)
		close(relayDone)
	}()

	// upstream -> client
	if _, err := originSide.Write([]byte("upstream-greeting")); err != nil {
		t.Fatalf("origin write: %v", err)
	}
	clientSide.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len("upstream-greeting"))
	if _, err := io.ReadFull(clientSide, buf); err != nil {
		t.Fatalf("read upstream->client: %v", err)
	}
	if string(buf) != "upstream-greeting" {
		t.Errorf("got %q, want upstream-greeting", string(buf))
	}

	// client -> origin
	if _, err := clientSide.Write([]byte("client-hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	originSide.SetDeadline(time.Now().Add(10 * time.Second))
	buf2 := make([]byte, len("client-hello"))
	if _, err := io.ReadFull(originSide, buf2); err != nil {
		t.Fatalf("read client->upstream: %v", err)
	}
	if string(buf2) != "client-hello" {
		t.Errorf("got %q, want client-hello", string(buf2))
	}

	// Closing the client end must make relay return: that is the leak guard.
	clientSide.Close()
	select {
	case <-relayDone:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not return after the client side closed")
	}
}

// TestRelayClosesBothSidesWhenOneEndDies guards against the half-open leak that
// would otherwise keep a tunnel alive forever.
func TestRelayClosesBothSidesWhenOneEndDies(t *testing.T) {
	proxyClientSide, clientSide := net.Pipe()
	proxyUpstreamSide, originSide := net.Pipe()

	done := make(chan struct{})
	go func() {
		relay(proxyClientSide, proxyUpstreamSide)
		close(done)
	}()

	clientSide.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not return after the client side closed")
	}

	// The upstream side must also be finished; a read should not block forever.
	originSide.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := originSide.Read(make([]byte, 1)); err == nil {
		t.Error("expected the upstream side to be closed too")
	}
}

func TestIsExpectedConnError(t *testing.T) {
	expected := []error{
		nil,
		io.EOF,
		net.ErrClosed,
		fmt.Errorf("write tcp: broken pipe"),
		fmt.Errorf("read: connection reset by peer"),
	}
	for _, err := range expected {
		if !isExpectedConnError(err) {
			t.Errorf("expected %v to be treated as an expected close", err)
		}
	}
	if isExpectedConnError(fmt.Errorf("certificate signed by unknown authority")) {
		t.Error("a TLS failure must not be swallowed as an expected close")
	}
}

// --- non-CONNECT requests keep their old behavior -------------------------

func TestNonConnectRequestStillReverseProxied(t *testing.T) {
	originAddr, closeOrigin := startEchoTLSServer(t)
	defer closeOrigin()

	proxySrv, closeProxy := newConnectTestServer(t, true, originAddr)
	defer closeProxy()

	// A plain GET must still go through the reverse-proxy path, not the tunnel.
	resp, err := http.Get(proxySrv.URL + "/anything")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Error("a GET must not be answered by the CONNECT rejection path")
	}
}

// --- the dial hook must not silently change family behavior ---------------

// TestConnectDialIsPlainTCP documents that the tunnel does not go through the
// ECH or SNI dialers: those terminate TLS themselves, which would break the
// client's own handshake. This test pins that contract.
func TestConnectDialIsPlainTCP(t *testing.T) {
	// A plain TCP listener must be reachable through the hook.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	conn, err := dialConnectTarget(context.Background(), "127.0.0.1", ln.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatalf("dialConnectTarget failed: %v", err)
	}
	conn.Close()
}
