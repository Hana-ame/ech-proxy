// Package netdial 提供基础网络拨号、公共 DNS 解析、IPv4/IPv6 协议族绑定、
// Cloudflare IP 识别、内网/保留地址识别（SSRF 防护）、远程/本地文件拉取与通用重试工具。
// 本模块处于架构最底层，不依赖项目内任何其他包。
package netdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DialTimeout 是单次 TCP 连接建立超时时间（避免单个不可达 IP 阻塞数分钟）。
	DialTimeout = 10 * time.Second
	// DoHTimeout 是单次 DoH / DNS 查询超时时间。
	DoHTimeout = 10 * time.Second
	// OpTimeout 是流式传输或大文件拉取的整体操作超时上限。
	OpTimeout = 5 * time.Minute

	RetryAttempts = 3
	RetryBackoff  = 1500 * time.Millisecond

	// DefaultIPMode 是全局默认的出口 IP 协议族（默认 ipv4 = "v4"）。
	DefaultIPMode = "v4"
)

var dnsServers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"223.5.5.5:53",
	"114.114.114.114:53",
}

// 统一维护的 Cloudflare IPv4 / IPv6 网段列表，用于全自动判断目标站点应走 ECH 还是 SNI 伪装。
var cloudflareCIDRs = []string{
	"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "141.101.64.0/18",
	"173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "108.162.192.0/18", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var cloudflareNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cloudflareCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// 保留与特殊用途网段（CGNAT、基准测试、链路本地、云元数据等），用于 CONNECT 隧道 SSRF 拦截。
var reservedCIDRs = []string{
	"0.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

var reservedNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range reservedCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsCloudflareIP 判断给定 IP 是否属于 Cloudflare 边缘节点网段。
func IsCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateOrReservedIP 判断 IP 是否属于环回、内网、链路本地（如 169.254.169.254）或保留地址。
func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// NormalizeIPMode 将显式出口协议族字符串归一化：
//   - "4" / "v4" / "ipv4" -> "v4" (ipv4 only)
//   - "6" / "v6" / "ipv6" -> "v6" (ipv6 only)
//   - "dual" / "auto"     -> "dual" (dual-stack)
//   - ""                  -> "" (未显式指定，交由上层继承或取默认值 DefaultIPMode="v4")
func NormalizeIPMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "4", "v4", "ipv4":
		return "v4"
	case "6", "v6", "ipv6":
		return "v6"
	case "dual", "auto":
		return "dual"
	default:
		return ""
	}
}

// EffectiveIPMode 返回最终生效的出口 IP 协议族（未指定时默认返回 DefaultIPMode = "v4"，即默认 ipv4）。
func EffectiveIPMode(mode string) string {
	norm := NormalizeIPMode(mode)
	if norm == "" {
		return DefaultIPMode
	}
	return norm
}

// ValidateIPMode 校验并归一化命令行或配置传入的 ipmode 值：
//   - "" / "4" / "v4" / "ipv4" -> "v4" (默认 ipv4 only)
//   - "dual" / "auto"          -> "dual" (双栈)
//   - "6" / "v6" / "ipv6"      -> "v6" (ipv6 only)
func ValidateIPMode(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "4", "v4", "ipv4":
		return "v4", nil
	case "dual", "auto":
		return "dual", nil
	case "6", "v6", "ipv6":
		return "v6", nil
	default:
		return "", fmt.Errorf("invalid ipmode %q (valid: ipv4/4 [default], dual, ipv6/6)", raw)
	}
}

// FormatIPMode 返回出口协议族的可读描述（默认 "ipv4 (4 = ipv4 only)" / "dual" / "ipv6 (6 = ipv6 only)"）。
func FormatIPMode(mode string) string {
	switch EffectiveIPMode(mode) {
	case "v4":
		return "ipv4 (4 = ipv4 only)"
	case "v6":
		return "ipv6 (6 = ipv6 only)"
	default:
		return "dual"
	}
}

var (
	resolverOnce    sync.Once
	resolver        *net.Resolver
	rootPoolOnce    sync.Once
	rootPool        *x509.CertPool
	transportOnce   sync.Once
	cachedTransport *http.Transport
)

func getResolver() *net.Resolver {
	resolverOnce.Do(func() {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: DoHTimeout}
				var lastErr error
				for _, dns := range dnsServers {
					conn, err := d.DialContext(ctx, network, dns)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				return nil, lastErr
			},
		}
	})
	return resolver
}

func getRootPool() *x509.CertPool {
	rootPoolOnce.Do(func() {
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		for _, p := range []string{
			"/data/data/com.termux/files/usr/etc/tls/cert.pem",
			os.Getenv("PREFIX") + "/etc/tls/cert.pem",
		} {
			if p != "" && p != "/etc/tls/cert.pem" {
				if pem, err := os.ReadFile(p); err == nil {
					pool.AppendCertsFromPEM(pem)
				}
			}
		}
		rootPool = pool
	})
	return rootPool
}

// Dialer 返回绑定了公共 DNS 的拨号器（兼容 Android/Termux 等无 /etc/resolv.conf 的环境）。
func Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   DialTimeout,
		KeepAlive: 30 * time.Second,
		Resolver:  getResolver(),
	}
}

// FilterIPsByMode 按指定的协议族（默认 "v4"、"v6" 或 "dual"）过滤 IP 列表。
func FilterIPsByMode(ips []net.IP, mode string) []string {
	norm := EffectiveIPMode(mode)
	var out []string
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil
		if norm == "v4" && !isV4 {
			continue
		}
		if norm == "v6" && (isV4 || ip.To16() == nil) {
			continue
		}
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ResolveIPs 按指定的协议族（默认 "v4"、"v6" 或 "dual"）解析域名并返回所有匹配的 IP。
func ResolveIPs(ctx context.Context, host, mode string) ([]string, error) {
	norm := EffectiveIPMode(mode)
	if ip := net.ParseIP(host); ip != nil {
		filtered := FilterIPsByMode([]net.IP{ip}, norm)
		if len(filtered) == 0 {
			return nil, fmt.Errorf("IP %s does not match ip_mode %q", host, norm)
		}
		return filtered, nil
	}
	addrs, err := getResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	filtered := FilterIPsByMode(ips, norm)
	if len(filtered) == 0 {
		if norm != "dual" {
			return nil, fmt.Errorf("no %s address for %s", norm, host)
		}
		return nil, fmt.Errorf("no IP address for %s", host)
	}
	return filtered, nil
}

// ResolvePreferredIP 按指定的协议族（默认 "v4"、"v6" 或 "dual"）解析域名并返回首个匹配的 IP。
func ResolvePreferredIP(ctx context.Context, host, mode string) (string, error) {
	ips, err := ResolveIPs(ctx, host, mode)
	if err != nil {
		return "", err
	}
	return ips[0], nil
}

// DialContextIPMode 根据 ipMode（默认 "v4"、"v6" 或 "dual"）向目标 host:port 发起 TCP 连接。
func DialContextIPMode(ctx context.Context, host, port, mode string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = DialTimeout
	}
	norm := EffectiveIPMode(mode)
	if norm == "v4" || norm == "v6" {
		ips, err := ResolveIPs(ctx, host, norm)
		if err != nil {
			return nil, err
		}
		network := "tcp"
		if norm == "v4" {
			network = "tcp4"
		} else {
			network = "tcp6"
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return (&net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Resolver:  getResolver(),
	}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
}

// Transport 返回全局复用的 HTTP Transport。
func Transport() *http.Transport {
	transportOnce.Do(func() {
		cachedTransport = &http.Transport{
			DialContext:       Dialer().DialContext,
			TLSClientConfig:   &tls.Config{RootCAs: getRootPool()},
			MaxIdleConns:      100,
			IdleConnTimeout:   90 * time.Second,
			ForceAttemptHTTP2: true,
		}
	})
	return cachedTransport
}

// TransportWithIPMode 返回锁定出口 IP 协议族（默认 "v4"、"v6" 或 "dual"）的 HTTP Transport。
func TransportWithIPMode(mode string) *http.Transport {
	norm := EffectiveIPMode(mode)
	if norm != "v4" && norm != "v6" {
		return Transport()
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return DialContextIPMode(ctx, host, port, norm, DialTimeout)
		},
		TLSClientConfig:   &tls.Config{RootCAs: getRootPool()},
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
	}
}

// Client 返回不自动跟随重定向的默认 HTTP 客户端（默认走 IPv4）。
func Client(timeout time.Duration) *http.Client {
	return ClientWithIPMode(DefaultIPMode, timeout)
}

// ClientWithIPMode 返回按指定 IP 协议族拨号、不自动跟随重定向的 HTTP 客户端。
func ClientWithIPMode(mode string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: TransportWithIPMode(mode),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// FetchBytes 支持从 file://、本地文件路径或远程 HTTP(S) URL 读取字节数据（含自动重试）。
func FetchBytes(rawURL string) ([]byte, error) {
	if strings.HasPrefix(rawURL, "file://") {
		return os.ReadFile(strings.TrimPrefix(rawURL, "file://"))
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if data, err := os.ReadFile(rawURL); err == nil {
			return data, nil
		}
	}
	client := Client(OpTimeout)
	resp, err := Retry(context.Background(), RetryAttempts, RetryBackoff, func() (*http.Response, error) {
		r, e := client.Get(rawURL)
		if e != nil {
			if r != nil {
				r.Body.Close()
			}
			return nil, e
		}
		return r, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// Retry 在遇到临时错误时按指定次数和退避间隔重试 fn。
func Retry[T any](ctx context.Context, attempts int, backoff time.Duration, fn func() (T, error)) (T, error) {
	var zero T
	var last error
	if attempts <= 0 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if i > 0 {
			t := time.NewTimer(backoff)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return zero, ctx.Err()
			}
		}
		v, err := fn()
		if err == nil {
			return v, nil
		}
		last = err
	}
	return zero, last
}
