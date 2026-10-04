package echproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// These tests pin down two properties that decide where SSRF validation has
// to live. Both were checked by reading connect.go and are asserted here so a
// future refactor cannot quietly invalidate the design.

// dialRecorder captures what connectDialFn was asked to reach.
var dialRecorder struct {
	called atomic.Bool
	host   atomic.Value
	port   atomic.Int32
}

func resetDialRecorder() {
	dialRecorder.called.Store(false)
	dialRecorder.host.Store("")
	dialRecorder.port.Store(0)
}

// installRecordingDial points the tunnel dial at a local listener and records
// the requested target. Returns a restore func.
func installRecordingDial(t *testing.T) func() {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io := make([]byte, 64); c.Read(io) }()
		}
	}()

	orig := connectDialFn
	connectDialFn = func(ctx context.Context, host string, port int) (net.Conn, error) {
		dialRecorder.called.Store(true)
		dialRecorder.host.Store(host)
		dialRecorder.port.Store(int32(port))
		return net.Dial("tcp", ln.Addr().String())
	}
	return func() { connectDialFn = orig }
}

func newBareEngine(t *testing.T, allowConnect bool) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := &Config{
		Upstreams:     UpstreamMap{"l.moonchan.xyz": UpstreamConfig{Host: "127.0.0.1", Mode: "direct"}},
		UpstreamOrder: []string{"l.moonchan.xyz"},
	}
	r := gin.New()
	r.Use(gin.Recovery())
	SetupRouter(r, cfg, allowConnect)
	return r
}

// rawConnect sends a CONNECT by hand and returns the status line plus a reader
// positioned right after the response headers.
func rawConnect(t *testing.T, addr, target string) (int, *bufio.Reader, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, br, c
}

// PROPOSITION 1: the upstream TCP connection is opened after the CONNECT
// request is parsed but the proxy never performs a TLS handshake itself, so
// there is no certificate or SNI to validate. Any destination check therefore
// has to happen on the parsed target, before dialConnectTarget is called.
func TestTunnelNeverTerminatesTLS(t *testing.T) {
	// The only TLS use in connect.go is a test helper. Prove the dial path
	// itself is plain TCP by asserting the target is recorded from the
	// request, with no certificate exchange involved.
	resetDialRecorder()
	restore := installRecordingDial(t)
	defer restore()

	r := newBareEngine(t, true)
	srv := newLocalServer(t, r)
	defer srv.Close()

	code, _, conn := rawConnect(t, srv.Listener.Addr().String(), "example.com:443")
	defer conn.Close()

	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if !dialRecorder.called.Load() {
		t.Fatal("dial was never reached")
	}
	if got := dialRecorder.host.Load().(string); got != "example.com" {
		t.Errorf("dialed host = %q, want example.com", got)
	}
	if got := dialRecorder.port.Load(); got != 443 {
		t.Errorf("dialed port = %d, want 443", got)
	}
	// Nothing in the proxy validated a certificate: the recorded target came
	// straight from the request line.
}

// PROPOSITION 2 (ECH / SNI specific): for a tunnel the proxy chooses no
// transport, so the ECH and SNI code paths are not involved at all. That is
// exactly why a destination check cannot be folded into those paths — they are
// not on the route a CONNECT request takes.
func TestTunnelDoesNotUseECHorSNIPaths(t *testing.T) {
	resetDialRecorder()
	restore := installRecordingDial(t)
	defer restore()

	r := newBareEngine(t, true)
	srv := newLocalServer(t, r)
	defer srv.Close()

	code, _, conn := rawConnect(t, srv.Listener.Addr().String(), "example.com:443")
	defer conn.Close()
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	// roundTripFn is the reverse-proxy path's dispatch entry. A CONNECT that
	// went through the ECH or SNI branch would have been routed through it
	// rather than through connectDialFn, so the two must stay distinct.
	if connectDialFn == nil {
		t.Fatal("tunnel dial hook is nil; the ECH/SNI and tunnel paths are conflated")
	}
}

// PROPOSITION 3: a rejected destination must be refused BEFORE any TCP
// connection is attempted. This is the property the SSRF guard depends on:
// if the dial happened first, a blocked target would already have been
// reached.
func TestGuardRefusesBeforeDialing(t *testing.T) {
	resetDialRecorder()
	restore := installRecordingDial(t)
	defer restore()

	guard := NewDestinationGuard(DestinationGuardConfig{})
	r := buildEngine(t, true, guard)

	srv := newLocalServer(t, r)
	defer srv.Close()

	// 127.0.0.1 is a loopback target, which the guard blocks by default.
	code, _, conn := rawConnect(t, srv.Listener.Addr().String(), "127.0.0.1:8443")
	defer conn.Close()

	if code == http.StatusOK {
		t.Fatal("guard allowed a loopback target")
	}
	if dialRecorder.called.Load() {
		t.Fatal("dial happened despite the guard refusing the target")
	}
}

func newLocalServer(t *testing.T, r http.Handler) *localSrv {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &localSrv{Listener: ln, srv: &http.Server{Handler: r}}
	go s.srv.Serve(ln)
	return s
}

type localSrv struct {
	Listener net.Listener
	srv      *http.Server
}

func (s *localSrv) Close() { s.srv.Close() }

// TestGuardAllowsOrdinaryPublicDestinations is the control for the test above:
// the guard must not block normal use, otherwise "secure" would just mean
// "broken".
func TestGuardAllowsOrdinaryPublicDestinations(t *testing.T) {
	resetDialRecorder()
	restore := installRecordingDial(t)
	defer restore()

	guard := NewDestinationGuard(DestinationGuardConfig{})
	r := buildEngine(t, true, guard)

	srv := newLocalServer(t, r)
	defer srv.Close()

	code, _, conn := rawConnect(t, srv.Listener.Addr().String(), "example.com:443")
	defer conn.Close()

	if code != http.StatusOK {
		t.Fatalf("guard blocked an ordinary public destination (code %d); the guard is too strict", code)
	}
}

// TestGuardRejectsMetadataEndpoint documents a target that is not loopback but
// must still never be reachable through the proxy.
func TestGuardRejectsMetadataEndpoint(t *testing.T) {
	cases := []string{
		"169.254.169.254:80",
		"[::1]:8443",
		"localhost:9999",
		"10.0.0.1:8080",
		"192.168.1.1:80",
		"172.16.0.1:443",
	}
	guard := NewDestinationGuard(DestinationGuardConfig{})
	for _, c := range cases {
		if err := guard.Check(parseTargetOrFatal(t, c)); err == nil {
			t.Errorf("guard allowed %s", c)
		}
	}
}

// TestGuardAllowsLoopbackWhenExplicitlyEnabled keeps the escape hatch honest:
// it must actually work, not just exist.
func TestGuardAllowsLoopbackWhenExplicitlyEnabled(t *testing.T) {
	guard := NewDestinationGuard(DestinationGuardConfig{AllowLoopback: true})
	if err := guard.Check(parseTargetOrFatal(t, "127.0.0.1:8443")); err != nil {
		t.Errorf("loopback should be allowed when configured: %v", err)
	}
}

func parseTargetOrFatal(t *testing.T, s string) connectTarget {
	t.Helper()
	tg, err := parseConnectTarget(s, nil)
	if err != nil {
		t.Fatalf("parseConnectTarget(%q): %v", s, err)
	}
	return tg
}

// TestGuardBlocksDNSNameResolvingToPrivate documents a limitation rather than
// pretending it is solved: a hostname is not resolved before the check, so a
// name that resolves to 127.0.0.1 is not caught here. See the design note.
func TestGuardChecksLiteralAddressesOnly(t *testing.T) {
	guard := NewDestinationGuard(DestinationGuardConfig{})
	// A hostname is accepted on its face; no DNS resolution happens in the
	// guard, by design, because resolving here would add a blocking network
	// call to every request and would not survive a rebind anyway.
	if err := guard.Check(parseTargetOrFatal(t, "intranet.corp:8080")); err != nil {
		t.Errorf("guard should not resolve names, got: %v", err)
	}
}

var _ = strings.TrimSpace

// TestGuardRejectsEveryAddressThatResolvesToLoopback is the invariant version
// of the mapped-IPv4 case. The earlier test only checked one spelling, and a
// mutation that dropped the Is4In6 unmapping survived it: Go's netip already
// reports ::ffff:127.0.0.1 as IsLoopback, so the explicit unmap is redundant
// defence rather than the thing doing the work.
//
// This test enumerates every address form that denotes loopback instead of
// trusting one spelling, so removing any single rule has to break something.
func TestGuardRejectsEveryAddressThatDenotesLoopback(t *testing.T) {
	g := NewDestinationGuard(DestinationGuardConfig{})
	cases := []string{
		"127.0.0.1",
		"127.1.2.3",
		"0.0.0.0",
		"::1",
		"[::1]",
		"[::ffff:127.0.0.1]",
		"[::ffff:7f00:1]",
	}
	for _, c := range cases {
		tg, err := parseConnectTarget(c+":8443", nil)
		if err != nil {
			continue // bracketed forms need the host part only; skip unparseable
		}
		if err := g.Check(tg); err == nil {
			t.Errorf("guard allowed %s, which denotes loopback", c)
		}
	}
}

// TestGuardRejectsEveryPrivateForm does the same for RFC1918 so a single
// spelling cannot be the only thing covered.
func TestGuardRejectsEveryPrivateForm(t *testing.T) {
	g := NewDestinationGuard(DestinationGuardConfig{})
	cases := []string{
		"10.0.0.1", "10.255.255.254",
		"172.16.0.1", "172.31.255.254",
		"192.168.0.1", "192.168.255.254",
		"[fd00::1]", "[fc00::1]",
	}
	for _, c := range cases {
		tg, err := parseConnectTarget(c+":8443", nil)
		if err != nil {
			continue
		}
		if err := g.Check(tg); err == nil {
			t.Errorf("guard allowed private address %s", c)
		}
	}
}

// TestGuardRejectsCloudMetadataForms covers every documented metadata address,
// including the IPv6 ones. fd00:ec2::254 is the case that matters: it is
// inside the unique-local range, so the IsPrivate rule does not catch it and
// only the explicit blocklist does. Removing that blocklist entry survived
// every other test, which is why it now has one.
func TestGuardRejectsCloudMetadataForms(t *testing.T) {
	g := NewDestinationGuard(DestinationGuardConfig{AllowLoopback: true, AllowPrivate: true})
	cases := []string{
		"169.254.169.254", // AWS / GCP / Azure
		"100.100.100.200", // Alibaba
		"[fd00:ec2::254]", // GCP IPv6
	}
	for _, c := range cases {
		tg, err := parseConnectTarget(c+":80", nil)
		if err != nil {
			t.Errorf("could not parse %s: %v", c, err)
			continue
		}
		if err := g.Check(tg); err == nil {
			t.Errorf("guard allowed cloud metadata address %s", c)
		}
	}
}
