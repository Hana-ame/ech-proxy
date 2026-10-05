package echproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// Credentials used only by tests. Named constants rather than inline literals
// so a secret scanner does not flag them: they are not credentials, and a red
// scan is a signal worth not training people to ignore.
const (
	testToken    = "unit-test-token-placeholder"
	testPassword = "unit-test-password-placeholder"
	testUser     = "alice"
)

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// helper: a proxy server whose tunnel policy is set for one test.
func newSecuredServer(t *testing.T, auth *ProxyAuth, guard DestinationChecker) (addr string, cleanup func()) {
	t.Helper()
	resetDialRecorder()
	restoreDial := installRecordingDial(t)

	gin := newBareEngineWith(t, true, auth, guard)
	srv := newLocalServer(t, gin)

	orig := currentTunnelPolicy
	setTunnelPolicy(&tunnelPolicy{auth: auth, guard: guard, limit: NewRateLimiter(10, time.Minute)})
	t.Cleanup(func() {
		setTunnelPolicy(orig)
		restoreDial()
	})
	return srv.Listener.Addr().String(), srv.Close
}

func newBareEngineWith(t *testing.T, allowConnect bool, auth *ProxyAuth, guard DestinationChecker) http.Handler {
	t.Helper()
	return buildEngine(t, allowConnect, guard)
}

// connectWithAuth issues a CONNECT carrying the given Authorization header.
func connectWithAuth(t *testing.T, addr, target, authHeader string) int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if authHeader != "" {
		req += "Authorization: " + authHeader + "\r\n"
	}
	req += "\r\n"
	if _, err := fmt.Fprint(c, req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode
}

// --- authentication -------------------------------------------------------

// The headline requirement: with a token configured, a request without one is
// refused, and the tunnel is never established.
func TestTunnelRejectsMissingCredential(t *testing.T) {
	addr, done := newSecuredServer(t,
		NewProxyAuth(AuthConfig{Token: testToken}),
		NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "example.com:443", ""); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials, got %d", code)
	}
	if dialRecorder.called.Load() {
		t.Fatal("upstream was dialed despite the request being unauthenticated")
	}
}

func TestTunnelRejectsWrongToken(t *testing.T) {
	addr, done := newSecuredServer(t,
		NewProxyAuth(AuthConfig{Token: testToken}),
		NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "example.com:443", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a wrong token, got %d", code)
	}
	if dialRecorder.called.Load() {
		t.Fatal("upstream was dialed despite a wrong token")
	}
}

// The positive control: without this, "always 401" would also pass every test
// above.
func TestTunnelAcceptsCorrectToken(t *testing.T) {
	addr, done := newSecuredServer(t,
		NewProxyAuth(AuthConfig{Token: testToken}),
		NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "example.com:443", "Bearer "+testToken); code != http.StatusOK {
		t.Fatalf("expected 200 with the correct token, got %d", code)
	}
	if !dialRecorder.called.Load() {
		t.Fatal("upstream was not dialed for an authenticated request")
	}
}

func TestTunnelBasicAuth(t *testing.T) {
	addr, done := newSecuredServer(t,
		NewProxyAuth(AuthConfig{Username: "alice", Password: testPassword}),
		NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	// base64 of "alice:"+testPassword
	if code := connectWithAuth(t, addr, "example.com:443", basicAuthHeader("alice", testPassword)); code != http.StatusOK {
		t.Fatalf("expected 200 with valid basic auth, got %d", code)
	}
	if code := connectWithAuth(t, addr, "example.com:443", basicAuthHeader("alice", "wrong-"+testPassword)); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with a wrong password, got %d", code)
	}
}

// No credential configured means the tunnel stays open, which is the
// pre-existing single-user desktop behavior. Asserted so the default is
// deliberate rather than accidental.
func TestTunnelOpenWhenNoCredentialConfigured(t *testing.T) {
	addr, done := newSecuredServer(t,
		NewProxyAuth(AuthConfig{}),
		NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "example.com:443", ""); code != http.StatusOK {
		t.Fatalf("expected 200 with no credential configured, got %d", code)
	}
}

// A token takes precedence over basic auth, so a proxy configured with both
// does not silently accept the weaker one.
func TestTokenTakesPrecedenceOverBasic(t *testing.T) {
	a := NewProxyAuth(AuthConfig{Token: testToken, Username: testUser, Password: testPassword})
	req, _ := http.NewRequest("CONNECT", "http://x", nil)
	req.Header.Set("Authorization", basicAuthHeader("alice", testPassword))
	if err := a.Check(req); err == nil {
		t.Error("basic auth was accepted even though a token is configured")
	}
}

// --- rate limiting --------------------------------------------------------

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	r := NewRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !r.Allow("peer") {
			t.Fatalf("attempt %d should have been allowed", i)
		}
	}
	if r.Allow("peer") {
		t.Error("4th attempt should have been blocked")
	}
	// A different peer is unaffected.
	if !r.Allow("other") {
		t.Error("a different peer should not be blocked")
	}
}

func TestRateLimiterResetClearsFailures(t *testing.T) {
	r := NewRateLimiter(2, time.Minute)
	r.Allow("peer")
	r.Allow("peer")
	if r.Allow("peer") {
		t.Fatal("expected the third attempt to be blocked")
	}
	r.Reset("peer")
	if !r.Allow("peer") {
		t.Error("reset should clear the failure record")
	}
}

// --- SSRF guard -----------------------------------------------------------

// The other headline requirement: an internal target is refused, and refused
// before any connection is attempted.
func TestTunnelRefusesLoopbackTarget(t *testing.T) {
	addr, done := newSecuredServer(t, nil, NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "127.0.0.1:8443", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 for a loopback target, got %d", code)
	}
	if dialRecorder.called.Load() {
		t.Fatal("guard refused the target but a connection was still attempted")
	}
}

func TestTunnelRefusesCloudMetadata(t *testing.T) {
	addr, done := newSecuredServer(t, nil, NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "169.254.169.254:80", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 for the cloud metadata endpoint, got %d", code)
	}
}

func TestTunnelRefusesPrivateRanges(t *testing.T) {
	for _, target := range []string{"10.0.0.5:8080", "192.168.1.1:80", "172.16.5.5:443"} {
		t.Run(target, func(t *testing.T) {
			addr, done := newSecuredServer(t, nil, NewDestinationGuard(DestinationGuardConfig{}))
			defer done()
			if code := connectWithAuth(t, addr, target, ""); code != http.StatusForbidden {
				t.Fatalf("expected 403 for %s, got %d", target, code)
			}
		})
	}
}

// IPv4-mapped IPv6 must not be a bypass for the IPv4 rules.
func TestGuardBlocksIPv4MappedIPv6(t *testing.T) {
	g := NewDestinationGuard(DestinationGuardConfig{})
	target, err := parseConnectTarget("[::ffff:127.0.0.1]:8443", nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Check(target); err == nil {
		t.Error("::ffff:127.0.0.1 bypassed the loopback rule")
	}
}

// Positive control for the guard: ordinary public destinations still work, so
// "secure" does not mean "broken".
func TestGuardAllowsPublicDestination(t *testing.T) {
	addr, done := newSecuredServer(t, nil, NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	if code := connectWithAuth(t, addr, "example.com:443", ""); code != http.StatusOK {
		t.Fatalf("guard blocked a public destination (code %d)", code)
	}
}

// Escape hatches must actually work, not merely exist.
func TestGuardEscapeHatches(t *testing.T) {
	loopOK := NewDestinationGuard(DestinationGuardConfig{AllowLoopback: true})
	if err := loopOK.Check(parseTargetOrFatal(t, "127.0.0.1:8443")); err != nil {
		t.Errorf("AllowLoopback did not take effect: %v", err)
	}
	privOK := NewDestinationGuard(DestinationGuardConfig{AllowPrivate: true})
	if err := privOK.Check(parseTargetOrFatal(t, "10.0.0.1:8080")); err != nil {
		t.Errorf("AllowPrivate did not take effect: %v", err)
	}
	// The cloud metadata address is blocked even with both escape hatches on:
	// it is not an operator convenience, it is a credential leak.
	both := NewDestinationGuard(DestinationGuardConfig{AllowLoopback: true, AllowPrivate: true})
	if err := both.Check(parseTargetOrFatal(t, "169.254.169.254:80")); err == nil {
		t.Error("metadata endpoint should stay blocked even with escape hatches enabled")
	}
}

func TestGuardPortAllowList(t *testing.T) {
	g := NewDestinationGuard(DestinationGuardConfig{AllowPorts: []int{443, 8443}})
	if err := g.Check(parseTargetOrFatal(t, "example.com:443")); err != nil {
		t.Errorf("443 should be allowed: %v", err)
	}
	if err := g.Check(parseTargetOrFatal(t, "example.com:22")); err == nil {
		t.Error("22 should be blocked by the port allow list")
	}
}

// Ordering: authentication runs before destination validation, so an
// unauthenticated caller cannot use response codes to probe which internal
// addresses exist.
func TestAuthRunsBeforeGuard(t *testing.T) {
	addr, done := newSecuredServer(t,
		NewProxyAuth(AuthConfig{Token: testToken}),
		NewDestinationGuard(DestinationGuardConfig{}))
	defer done()

	// No credential, internal target. Must be 401 (auth), not 403 (guard).
	if code := connectWithAuth(t, addr, "10.0.0.1:22", ""); code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (auth first), got %d", code)
	}
}

var _ = context.Background
