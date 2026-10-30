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

func TestIsGitHubResourceURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		// 真 GitHub 资源：必须进竞速
		{"https://github.com/Hana-ame/ech-proxy/releases/latest/download/checksums.txt", true},
		{"https://objects.githubusercontent.com/production-release-asset", true},
		{"https://raw.githubusercontent.com/o/r/main/f.txt", true},
		{"https://api.github.com/repos/o/r", true},
		{"https://codeload.github.com/o/r/zip/refs/heads/main", true},
		{"https://GITHUB.COM/o/r", true}, // 主机名大小写不敏感
		// 查询串里带 github 主机名、但主机本身不是 GitHub：必须走直连。
		// 旧实现用整串 substring 判定，此例被误判为 GitHub 资源——镜像前缀一个
		// 非 GitHub URL 只会 404/超时（v3.5.25 实证：check/hosts-print 时好时坏）。
		{"https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/upstream.json?proxy_host=raw.githubusercontent.com", false},
		{"https://4545810.xyz/pac.txt", false},
		{"http://127.0.0.1:8443/proxy.pac", false},
		{"https://ghfast.top/https://github.com/x", false},
		{"", false},
		{"::not a url::", false},
	}
	for _, c := range cases {
		if got := isGitHubResourceURL(c.url); got != c.want {
			t.Errorf("isGitHubResourceURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestGitHubFetchCandidatesOrder(t *testing.T) {
	const raw = "https://github.com/Hana-ame/ech-proxy/releases/latest/download/checksums.txt"
	got := gitHubFetchCandidates(raw)
	want := []string{
		"https://ghproxy.imciel.com/" + raw,
		"https://gh-proxy.com/" + raw,
		"https://ghfast.top/" + raw,
		"https://gh.llkk.cc/" + raw,
		raw,
	}
	if len(got) != len(want) {
		t.Fatalf("gitHubFetchCandidates returned %d candidates, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// 硬性契约：直连必须排最后。国内网络直连 github.com:443 在 TCP 层即被阻断，
	// 若直连排在前面，二进制下载（并发度 3）的槽位会被挂死的直连候选占满，
	// 唯一可用镜像被饿死，更新下载必然整体超时失败。
	if got[len(got)-1] != raw {
		t.Errorf("direct GitHub URL must be the LAST candidate, got %q", got[len(got)-1])
	}
	// 所有镜像候选必须排在直连之前。
	directIdx := len(got) - 1
	for i, c := range got {
		if i < directIdx && c == raw {
			t.Errorf("mirror candidate[%d] equals the direct URL", i)
		}
	}
	// 硬性契约（v3.5.25）：ghproxy.imciel.com 必须置首位。实证它是国内唯一
	// 能完成下载的镜像；二进制并发度只有 3，排第 4 要先等槽位——386 冷资产
	// 实测等 22s 后自身 90s 超时即耗尽（RELEASE.md v3.5.25）。
	if got[0] != "https://ghproxy.imciel.com/"+raw {
		t.Errorf("ghproxy.imciel.com must be the FIRST candidate, got %q", got[0])
	}
}

func TestWithInsideDoHPreventsDoHResolverRecursion(t *testing.T) {
	origResolver := DoHResolver
	defer func() { DoHResolver = origResolver }()

	resolverCalls := 0
	DoHResolver = func(ctx context.Context, host, mode string) ([]string, error) {
		resolverCalls++
		if resolverCalls > 1 {
			t.Fatalf("DoHResolver recursively re-entered (%d calls)", resolverCalls)
		}
		// Simulate DoHResolver dialing the DoH server (4545810.xyz) via ResolveIPs:
		// because ResolveIPs passed WithInsideDoH(ctx), this nested ResolveIPs call must NOT re-enter DoHResolver.
		if !IsInsideDoH(ctx) {
			t.Errorf("expected IsInsideDoH(ctx) == true inside DoHResolver")
		}
		cCtx, cancel := context.WithCancel(ctx)
		cancel()
		_, _ = ResolveIPs(cCtx, DefaultSiteHost, mode)
		return []string{"104.16.1.2"}, nil
	}

	ips, err := ResolveIPs(context.Background(), "example.com", "v4")
	if err != nil || len(ips) != 1 || ips[0] != "104.16.1.2" {
		t.Fatalf("ResolveIPs = %v, %v; want [104.16.1.2]", ips, err)
	}
	if resolverCalls != 1 {
		t.Errorf("expected DoHResolver to be called exactly once, got %d", resolverCalls)
	}
}

// TestDomesticBootstrapFallbackGate 验证 issue #41：
// 国内 DoH 端点默认只作为「主端点优先窗口」失败后的最后兜底，可显式禁用。
func TestDomesticBootstrapFallbackGate(t *testing.T) {
	t.Setenv("ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP", "")
	if !domesticBootstrapAllowed() {
		t.Error("domestic last-resort fallback must be allowed by default (needed behind blocked 1.1.1.1)")
	}
	for _, v := range []string{"1", "true", "YES", "on"} {
		t.Setenv("ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP", v)
		if domesticBootstrapAllowed() {
			t.Errorf("ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP=%q must disable domestic fallback", v)
		}
	}
	t.Setenv("ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP", "0")
	if !domesticBootstrapAllowed() {
		t.Error("value '0' must keep domestic fallback enabled")
	}
}
