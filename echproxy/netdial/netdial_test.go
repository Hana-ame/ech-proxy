package netdial

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsCloudflareIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"104.16.132.229", true},
		{"172.67.1.1", true},
		{"2606:4700::6810:84e5", true},
		{"8.8.8.8", false},
		{"127.0.0.1", false},
		{"199.232.69.194", false}, // Fastly (pximg)
	}
	for _, tc := range cases {
		if got := IsCloudflareIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsCloudflareIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if IsCloudflareIP(nil) {
		t.Error("IsCloudflareIP(nil) should be false")
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // Cloud metadata SSRF target
		{"100.64.0.1", true},      // CGNAT
		{"::1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"104.16.1.1", false},
		{"2606:4700::1", false},
	}
	for _, tc := range cases {
		if got := IsPrivateOrReservedIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("IsPrivateOrReservedIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if !IsPrivateOrReservedIP(nil) {
		t.Error("IsPrivateOrReservedIP(nil) should be true")
	}
}

func TestNormalizeValidateIPModeAndFilterIPs(t *testing.T) {
	// Default (empty) and 4/v4/ipv4 all validate to "v4" (ipv4 only)
	for _, v := range []string{"", "4", "v4", "V4", "ipv4", "IPV4"} {
		if got, err := ValidateIPMode(v); err != nil || got != "v4" {
			t.Errorf("ValidateIPMode(%q) = (%q, %v), want (v4, nil)", v, got, err)
		}
	}
	for _, v := range []string{"6", "v6", " ipv6 "} {
		if got, err := ValidateIPMode(v); err != nil || got != "v6" {
			t.Errorf("ValidateIPMode(%q) = (%q, %v), want (v6, nil)", v, got, err)
		}
	}
	for _, v := range []string{"dual", "DUAL", "auto"} {
		if got, err := ValidateIPMode(v); err != nil || got != "dual" {
			t.Errorf("ValidateIPMode(%q) = (%q, %v), want ('dual', nil)", v, got, err)
		}
	}
	if _, err := ValidateIPMode("5"); err == nil {
		t.Error("ValidateIPMode(5) should return error")
	}

	if got := EffectiveIPMode(""); got != "v4" {
		t.Errorf("EffectiveIPMode('') = %q, want v4 (default ipv4)", got)
	}

	ips := []net.IP{
		net.ParseIP("104.16.0.1"),
		net.ParseIP("2606:4700::1"),
		net.ParseIP("104.16.0.1"), // duplicate
	}
	// Default empty mode filters to IPv4 only
	v4Default := FilterIPsByMode(ips, "")
	if len(v4Default) != 1 || v4Default[0] != "104.16.0.1" {
		t.Errorf("FilterIPsByMode default ('') = %v, want [104.16.0.1]", v4Default)
	}
	v4 := FilterIPsByMode(ips, "4")
	if len(v4) != 1 || v4[0] != "104.16.0.1" {
		t.Errorf("FilterIPsByMode 4 = %v, want [104.16.0.1]", v4)
	}
	v6 := FilterIPsByMode(ips, "6")
	if len(v6) != 1 || v6[0] != "2606:4700::1" {
		t.Errorf("FilterIPsByMode 6 = %v, want [2606:4700::1]", v6)
	}
	all := FilterIPsByMode(ips, "dual")
	if len(all) != 2 {
		t.Errorf("FilterIPsByMode dual = %v, want 2 unique IPs", all)
	}
}

func TestFetchBytesLocalAndRetry(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.json")
	if err := os.WriteFile(p, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b1, err := FetchBytes(p)
	if err != nil || string(b1) != `{"ok":true}` {
		t.Fatalf("FetchBytes(path) = %q, %v", string(b1), err)
	}
	b2, err := FetchBytes("file://" + p)
	if err != nil || string(b2) != `{"ok":true}` {
		t.Fatalf("FetchBytes(file://) = %q, %v", string(b2), err)
	}

	calls := 0
	val, err := Retry(context.Background(), 3, 5*time.Millisecond, func() (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("temporary")
		}
		return 42, nil
	})
	if err != nil || val != 42 || calls != 3 {
		t.Errorf("Retry got (%d, %v) after %d calls, want (42, nil) after 3 calls", val, err, calls)
	}
}
