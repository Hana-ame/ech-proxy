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

func TestNormalizeIPModeAndFilterIPs(t *testing.T) {
	if got := NormalizeIPMode("V4"); got != "v4" {
		t.Errorf("NormalizeIPMode(V4) = %q, want v4", got)
	}
	if got := NormalizeIPMode(" ipv6 "); got != "v6" {
		t.Errorf("NormalizeIPMode(ipv6) = %q, want v6", got)
	}
	if got := NormalizeIPMode("auto"); got != "" {
		t.Errorf("NormalizeIPMode(auto) = %q, want empty", got)
	}

	ips := []net.IP{
		net.ParseIP("104.16.0.1"),
		net.ParseIP("2606:4700::1"),
		net.ParseIP("104.16.0.1"), // duplicate
	}
	v4 := FilterIPsByMode(ips, "V4")
	if len(v4) != 1 || v4[0] != "104.16.0.1" {
		t.Errorf("FilterIPsByMode v4 = %v, want [104.16.0.1]", v4)
	}
	v6 := FilterIPsByMode(ips, "v6")
	if len(v6) != 1 || v6[0] != "2606:4700::1" {
		t.Errorf("FilterIPsByMode v6 = %v, want [2606:4700::1]", v6)
	}
	all := FilterIPsByMode(ips, "auto")
	if len(all) != 2 {
		t.Errorf("FilterIPsByMode auto = %v, want 2 unique IPs", all)
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
