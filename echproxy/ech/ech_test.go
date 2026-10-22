package cloudflare_ech

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetIPModeNormalizesAndSNIServerNameContext(t *testing.T) {
	defer SetIPMode("")

	SetIPMode("V4")
	if got := GetIPMode(); got != "v4" {
		t.Errorf("GetIPMode() after SetIPMode(V4) = %q, want v4", got)
	}
	SetIPMode("IPV6")
	if got := GetIPMode(); got != "v6" {
		t.Errorf("GetIPMode() after SetIPMode(IPV6) = %q, want v6", got)
	}
	SetIPMode("DUAL")
	if got := GetIPMode(); got != "dual" {
		t.Errorf("GetIPMode() after SetIPMode(DUAL) = %q, want dual", got)
	}

	if PrimaryDoHURL() != "https://4545810.xyz/doh" {
		t.Errorf("default PrimaryDoHURL = %q, want https://4545810.xyz/doh", PrimaryDoHURL())
	}
	if SecondaryDoHURL() != "https://1.1.1.1/dns-query" {
		t.Errorf("default SecondaryDoHURL = %q, want https://1.1.1.1/dns-query", SecondaryDoHURL())
	}

	ctx := context.Background()
	gotDefault := SNIServerNameFromContext(ctx)
	if gotDefault == "" {
		t.Errorf("default SNIServerName should not be empty, got %q", gotDefault)
	}
	gotNext := SNIServerNameFromContext(ctx)
	if gotNext == "" || gotNext == gotDefault {
		t.Errorf("next SNIServerName should rotate to different domain, got %q (prev: %q)", gotNext, gotDefault)
	}
	ctxCustom := WithSNIServerName(ctx, "custom.sni.example")
	if got := SNIServerNameFromContext(ctxCustom); got != "custom.sni.example" {
		t.Errorf("custom SNIServerName = %q, want custom.sni.example", got)
	}
	ctxNone := WithSNIServerName(ctx, "none")
	if got := SNIServerNameFromContext(ctxNone); got != "" {
		t.Errorf("none SNIServerName = %q, want empty", got)
	}
	if HasCustomSNIServerName(ctx) {
		t.Errorf("HasCustomSNIServerName(ctx) = true, want false")
	}
	if !HasCustomSNIServerName(ctxCustom) {
		t.Errorf("HasCustomSNIServerName(ctxCustom) = false, want true")
	}
	if HasCustomSNIServerName(ctxNone) {
		t.Errorf("HasCustomSNIServerName(ctxNone) = true, want false")
	}
}

func TestDefaultSNIDomainsRotation(t *testing.T) {
	seen := make(map[string]bool)
	hasWildcardResolved := false
	for i := 0; i < len(DefaultSNIDomains)*2; i++ {
		sni := NextDefaultSNIServerName()
		if sni == "" {
			t.Fatalf("NextDefaultSNIServerName() returned empty string at index %d", i)
		}
		if strings.Contains(sni, "*") {
			t.Fatalf("NextDefaultSNIServerName() returned unexpanded wildcard: %q", sni)
		}
		if strings.HasSuffix(sni, ".windowsupdate.com") {
			hasWildcardResolved = true
		}
		seen[sni] = true
	}
	if len(seen) < 5 {
		t.Errorf("expected diverse rotated domains, only got %d unique: %v", len(seen), seen)
	}
	if !hasWildcardResolved {
		t.Errorf("expected *.windowsupdate.com to be resolved into valid subdomains")
	}
}

func TestResolveHostIPsByModeViaMockDoHAndFallback(t *testing.T) {
	primaryFail := false
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if primaryFail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		qtype := r.URL.Query().Get("type")
		qname := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(qname, "noncf") {
			_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"62.112.8.152"}]}`))
			return
		}
		switch qtype {
		case "1":
			_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"104.16.10.20"}]}`))
		case "28":
			_, _ = w.Write([]byte(`{"Answer":[{"type":28,"TTL":120,"data":"2606:4700::10"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer primarySrv.Close()

	secondarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"104.16.99.88"}]}`))
	}))
	defer secondarySrv.Close()

	SetDohURL(primarySrv.URL + "/doh")
	SetFallbackDohURL(secondarySrv.URL + "/dns-query")
	defer func() {
		SetDohURL(defaultDohURL)
		SetFallbackDohURL(fallbackDohURL)
	}()

	v4IPs, err := ResolveHostIPsByMode(context.Background(), "cf-test.example.org", "v4")
	if err != nil || len(v4IPs) != 1 || v4IPs[0] != "104.16.10.20" {
		t.Fatalf("ResolveHostIPsByMode v4 = %v, %v", v4IPs, err)
	}
	v6IPs, err := ResolveHostIPsByMode(context.Background(), "cf-test.example.org", "v6")
	if err != nil || len(v6IPs) != 1 || v6IPs[0] != "2606:4700::10" {
		t.Fatalf("ResolveHostIPsByMode v6 = %v, %v", v6IPs, err)
	}

	mode, confident := DetectTransportModeWithStatus(context.Background(), "cf-test.example.org", "v4")
	if mode != "ech" || !confident {
		t.Errorf("DetectTransportModeWithStatus for CF IP = (%q, %v), want (ech, true)", mode, confident)
	}

	modeNonCF, confidentNonCF := DetectTransportModeWithStatus(context.Background(), "noncf.example.org", "v4")
	if modeNonCF != "fragment" || !confidentNonCF {
		t.Errorf("DetectTransportModeWithStatus for non-CF IP = (%q, %v), want (fragment, true)", modeNonCF, confidentNonCF)
	}

	ctxCustomSNI := WithSNIServerName(context.Background(), "custom.sni.example")
	modeCustomSNI, confidentCustomSNI := DetectTransportModeWithStatus(ctxCustomSNI, "noncf.example.org", "v4")
	if modeCustomSNI != "sni" || !confidentCustomSNI {
		t.Errorf("DetectTransportModeWithStatus with custom SNI = (%q, %v), want (sni, true)", modeCustomSNI, confidentCustomSNI)
	}

	// 验证当首选 DoH (https://4545810.xyz/doh) 故障时自动回退至次选 DoH (https://1.1.1.1/dns-query)
	primaryFail = true
	fbIPs, err := ResolveHostIPsByMode(context.Background(), "fallback-test.example.org", "v4")
	if err != nil || len(fbIPs) != 1 || fbIPs[0] != "104.16.99.88" {
		t.Fatalf("ResolveHostIPsByMode via secondary DoH fallback = %v, %v; want [104.16.99.88]", fbIPs, err)
	}
}

func TestRaceModesConcurrentWinnerSelection(t *testing.T) {
	clearCachedRoute("race.example.org")
	defer clearCachedRoute("race.example.org")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("winner"))
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Host = "race.example.org"

	resp, err := raceModes(req, []string{"direct"}, "v4", "race.example.org")
	if err != nil {
		t.Fatalf("raceModes failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("raceModes status = %d, want 200", resp.StatusCode)
	}
	if cached, ok := getCachedRoute("race.example.org"); !ok || cached != "direct" {
		t.Errorf("getCachedRoute = (%q, %v), want (direct, true)", cached, ok)
	}
}

func TestNyaaFragmentDo(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://nyaa.si/favicon.ico", nil)
	resp, err := FragmentDo(req, "v4")
	if err != nil {
		t.Fatalf("FragmentDo to nyaa.si failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 0 {
		t.Errorf("expected valid HTTP response, got status %d", resp.StatusCode)
	}
}

