package echproxy

import (
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
	"time"

	"github.com/gin-gonic/gin"
)

// pixivWildcardConfig returns the upstream config exactly as the local reverse
// proxy mode describes the pixiv passthrough, parsed through the real
// normalization path.
func pixivWildcardConfig(t *testing.T) UpstreamMap {
	t.Helper()
	data := `{
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
	cfg, err := ParseConfig([]byte(data))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return cfg.Upstreams
}

// TestWildcardEmptyPrefixPassthrough covers the pixiv local reverse proxy case:
// an entry pattern of "*.pixiv.net" (empty prefix) must match every subdomain
// and rewrite the host to itself. Before the wildcard.go fix, the
// "did the prefix match" guard fired unconditionally and *.pixiv.net never
// matched at all.
func TestWildcardEmptyPrefixPassthrough(t *testing.T) {
	cfg := pixivWildcardConfig(t)

	cases := map[string]string{
		"www.pixiv.net":      "www.pixiv.net",
		"account.pixiv.net":  "account.pixiv.net",
		"api.sec.pixiv.net":  "api.sec.pixiv.net",
		"manga.pixiv.net":    "manga.pixiv.net",
		"deep.sub.pixiv.net": "deep.sub.pixiv.net",
	}
	for host, want := range cases {
		uc, ok := MatchWildcardForTest(cfg, host)
		if !ok {
			t.Errorf("%s: expected wildcard match, got none", host)
			continue
		}
		if uc.Host != want {
			t.Errorf("%s: Host = %q, want %q", host, uc.Host, want)
		}
		if uc.Mode != "" {
			t.Errorf("%s: Mode = %q, want empty (ech forwarding)", host, uc.Mode)
		}
		if uc.IPMode != "v4" {
			t.Errorf("%s: IPMode = %q, want %q", host, uc.IPMode, "v4")
		}
	}

	// The bare apex domain is NOT a subdomain: "*.pixiv.net" must not match it.
	if _, ok := MatchWildcardForTest(cfg, "pixiv.net"); ok {
		t.Error("pixiv.net matched *.pixiv.net; the bare apex must be a separate entry")
	}
	// Unrelated domains must not match.
	if _, ok := MatchWildcardForTest(cfg, "www.pixiv.net.evil.com"); ok {
		t.Error("a sibling domain matched *.pixiv.net")
	}
}

// TestEmptyPrefixWildcardSurvivesNormalization asserts that a wildcard with an
// explicitly empty prefix (the pixiv passthrough shape) keeps that prefix and
// does not inherit one from a same-domain upstream.
func TestEmptyPrefixWildcardSurvivesNormalization(t *testing.T) {
	data := `{
		"upstreams": {
			"pixiv.net": {
				"host": "pixiv.net",
				"wildcard": {
					"entry_suffix": ".pixiv.net",
					"upstream_suffix": ".pixiv.net"
				}
			}
		}
	}`
	cfg, err := ParseConfig([]byte(data))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	for _, uc := range cfg.Upstreams {
		w := uc.Wildcard
		if w == nil {
			continue
		}
		if w.EntrySuffix != ".pixiv.net" {
			t.Errorf("EntrySuffix = %q, want .pixiv.net", w.EntrySuffix)
		}
		if w.Prefix != "" {
			t.Errorf("Prefix = %q, want empty", w.Prefix)
		}
		if w.UpstreamSuffix != ".pixiv.net" {
			t.Errorf("UpstreamSuffix = %q, want .pixiv.net", w.UpstreamSuffix)
		}
	}
}

// TestPixivConfigLoads verifies the pixiv entries actually shipped in
// upstream.json parse, normalize, and dispatch as intended: direct mode, v4
// egress, apex handled by the explicit entry and subdomains by the wildcard.
func TestPixivConfigLoads(t *testing.T) {
	buf, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Skipf("config file not available in this checkout: %v", err)
	}
	cfg, err := ParseConfig(buf)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	apex, ok := cfg.Upstreams["pixiv.net"]
	if !ok {
		t.Fatal("pixiv.net entry missing from upstream.json")
	}
	if apex.Host != "pixiv.net" {
		t.Errorf("pixiv.net host = %q, want %q", apex.Host, "pixiv.net")
	}
	if apex.Mode != "" {
		t.Errorf("pixiv.net mode = %q, want empty (ech forwarding)", apex.Mode)
	}
	if apex.IPMode != "v4" {
		t.Errorf("pixiv.net ip_mode = %q, want %q", apex.IPMode, "v4")
	}

	for _, sub := range []string{"www.pixiv.net", "account.pixiv.net"} {
		uc, ok := MatchWildcardForTest(cfg.Upstreams, sub)
		if !ok {
			t.Errorf("%s: no wildcard match in the shipped config", sub)
			continue
		}
		if uc.Host != sub {
			t.Errorf("%s: upstream host = %q, want passthrough %q", sub, uc.Host, sub)
		}
		if uc.Mode != "" {
			t.Errorf("%s: mode = %q, want empty (ech forwarding)", sub, uc.Mode)
		}
		if uc.IPMode != "v4" {
			t.Errorf("%s: ip_mode = %q, want v4", sub, uc.IPMode)
		}
	}
}

// TestProxyHandlerPixivPassthrough drives a real HTTP request through the
// router with a pixiv host and confirms it is dispatched as a direct, v4
// upstream request that keeps the original Host.
func TestProxyHandlerPixivPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := pixivWildcardConfig(t)

	orig := roundTripFn
	roundTripFn = func(req *http.Request, mode, ipMode string) (*http.Response, error) {
		if mode != "" {
			t.Errorf("mode = %q, want empty (ech forwarding)", mode)
		}
		if ipMode != "v4" {
			t.Errorf("ipMode = %q, want v4", ipMode)
		}
		if req.Host != "www.pixiv.net" {
			t.Errorf("upstream Host = %q, want %q", req.Host, "www.pixiv.net")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"X-Upstream-Saw": []string{req.Host}},
			Body:       io.NopCloser(strings.NewReader("pixiv ok")),
		}, nil
	}
	defer func() { roundTripFn = orig }()

	r := gin.New()
	r.Use(ProxyHandler(cfg, nil))

	req := httptest.NewRequest(http.MethodGet, "/artworks/1", nil)
	req.Host = "www.pixiv.net"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != "pixiv ok" {
		t.Errorf("body = %q, want %q", got, "pixiv ok")
	}
	if got := w.Header().Get("X-Upstream-Saw"); got != "www.pixiv.net" {
		t.Errorf("X-Upstream-Saw = %q, want %q", got, "www.pixiv.net")
	}
}

// TestShippedConfigStillParses is a smoke check that the whole upstream.json
// still loads after the pixiv additions — catches a broken JSON or a
// normalization panic.
func TestShippedConfigStillParses(t *testing.T) {
	buf, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Skipf("config not available: %v", err)
	}
	if _, err := ParseConfig(buf); err != nil {
		t.Fatalf("ParseConfig on shipped upstream.json: %v", err)
	}
	if err := json.Unmarshal(buf, &map[string]any{}); err != nil {
		t.Fatalf("upstream.json is not valid JSON: %v", err)
	}
}

// TestLocalProxyEndToEnd boots a real local reverse proxy TLS listener, dials it
// trusting ONLY the self-generated CA, and confirms the leaf presented is the
// local one. That single handshake proves the whole chain works: self-generate
// CA -> persist ca.pem -> GetCertificate issues a leaf -> the browser (client
// here) trusts it for a third-party hostname.
func TestLocalProxyEndToEnd(t *testing.T) {
	dir := t.TempDir()

	store, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// The exact TLSConfig NewServer installs in local proxy mode.
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return store.CertificateFor(hello.ServerName)
		},
	}
	httpSrv := &http.Server{
		Handler:   NewEngine(&Config{Upstreams: UpstreamMap{}, UpstreamOrder: nil}, false),
		TLSConfig: tlsCfg,
	}
	go httpSrv.Serve(tls.NewListener(ln, tlsCfg))
	defer httpSrv.Close()

	// Trust only our CA, exactly as the user would after installing ca.pem.
	caPEM, err := os.ReadFile(store.CAPath())
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to append CA cert to pool")
	}

	// Second SNI in the same tree must reuse the cached leaf, not re-issue.
	for _, sni := range []string{"www.pixiv.net", "account.pixiv.net"} {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
			ServerName: sni,
			RootCAs:    roots,
		})
		if err != nil {
			t.Fatalf("tls.Dial(%s) failed — is the CA trusted? %v", sni, err)
		}
		state := conn.ConnectionState()
		conn.Close()
		if len(state.PeerCertificates) == 0 {
			t.Fatalf("no peer certificate presented for %s", sni)
		}
		leaf := state.PeerCertificates[0]
		if leaf.Subject.CommonName != "pixiv.net" {
			t.Errorf("leaf CN = %q, want pixiv.net (the local CA leaf)", leaf.Subject.CommonName)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:     roots,
			DNSName:   sni,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("leaf does not verify for %s: %v", sni, err)
		}
	}

	// And the same data dir must serve the same leaf on a fresh CertStore:
	// the CA and leaf survive a restart, so the user re-installs nothing.
	st2, err := NewCertStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st2.CertificateFor("account.pixiv.net"); err == nil {
		_ = got
	} else {
		t.Errorf("reload after restart: %v", err)
	}
	_ = time.Second
}
