package cloudflare_ech

import (
	"context"
	"net/http"
	"net/http/httptest"
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

	ctx := context.Background()
	if got := SNIServerNameFromContext(ctx); got != shellDomain {
		t.Errorf("default SNIServerName = %q, want %q", got, shellDomain)
	}
	ctxCustom := WithSNIServerName(ctx, "custom.sni.example")
	if got := SNIServerNameFromContext(ctxCustom); got != "custom.sni.example" {
		t.Errorf("custom SNIServerName = %q, want custom.sni.example", got)
	}
	ctxNone := WithSNIServerName(ctx, "none")
	if got := SNIServerNameFromContext(ctxNone); got != "" {
		t.Errorf("none SNIServerName = %q, want empty", got)
	}
}

func TestResolveHostIPsByModeViaMockDoH(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		qtype := r.URL.Query().Get("type")
		w.Header().Set("Content-Type", "application/json")
		switch qtype {
		case "1":
			_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"104.16.10.20"}]}`))
		case "28":
			_, _ = w.Write([]byte(`{"Answer":[{"type":28,"TTL":120,"data":"2606:4700::10"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	SetDohURL(srv.URL)
	defer SetDohURL(defaultDohURL)

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
}
