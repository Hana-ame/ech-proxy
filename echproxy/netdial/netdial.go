// Package netdial 提供基础网络拨号、公共 DNS 解析、IPv4/IPv6 协议族绑定、主机端口与域名归一化、
// Cloudflare IP 识别、内网/保留地址识别（SSRF 防护）、远程/本地文件拉取与通用重试工具。
// 本模块处于架构最底层，不依赖项目内任何其他包，供上层所有模块高内聚复用。
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
	DialTimeout   = 10 * time.Second
	DoHTimeout    = 10 * time.Second
	OpTimeout     = 5 * time.Minute
	RetryAttempts = 3
	RetryBackoff  = 1500 * time.Millisecond
	DefaultIPMode = "v4"

	// DefaultSiteHost 是项目自有服务域名（DoH / ads.js / pac.txt 共用）的**唯一 true source**。
	// 其它包（ech、rewrite、server、flutter）必须引用它派生，不得再各自硬编码该域名。
	DefaultSiteHost = "4545810.xyz"
)

var dnsServers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"223.5.5.5:53",
	"114.114.114.114:53",
}

var cloudflareCIDRs = []string{
	"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "141.101.64.0/18",
	"173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "108.162.192.0/18", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var cloudflareNets = parseCIDRList(cloudflareCIDRs)

var reservedCIDRs = []string{
	"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
}

var reservedNets = parseCIDRList(reservedCIDRs)

func parseCIDRList(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// CleanHost 归一化主机名（转小写、去空白、剥离端口号与末尾点号），供全项目复用。
func CleanHost(hostport string) string {
	h := strings.ToLower(strings.TrimSpace(hostport))
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return strings.TrimSuffix(h, ".")
}

// ExtractPort 提取 host:port 中的端口号（无端口时返回空字符串）。
func ExtractPort(hostport string) string {
	if _, p, err := net.SplitHostPort(strings.TrimSpace(hostport)); err == nil {
		return p
	}
	return ""
}

// IsPort443 判断地址是否指向 443 端口。
func IsPort443(addr string) bool {
	addr = strings.TrimSpace(addr)
	if p := ExtractPort(addr); p != "" {
		return p == "443"
	}
	return strings.HasSuffix(addr, ":443")
}

// NormalizeLoopbackHostPort 将监听地址（如 ":8443" 或 "0.0.0.0:8443"）转换为客户端可访问的 "127.0.0.1:<port>"。
func NormalizeLoopbackHostPort(listenAddr, defaultAddr string) string {
	if defaultAddr == "" {
		defaultAddr = "127.0.0.1:8443"
	}
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return defaultAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return defaultAddr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// NormalizeDomainEntry 将域名条目（支持剥离协议头、路径、端口与 *. 通配前缀）归一化为纯域名。
func NormalizeDomainEntry(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	for strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*.")
	}
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, " \t\r\n/\\:*?<>\"'") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}

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

func EffectiveIPMode(mode string) string {
	if norm := NormalizeIPMode(mode); norm != "" {
		return norm
	}
	return DefaultIPMode
}

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

func RootPool() *x509.CertPool { return getRootPool() }

func Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   DialTimeout,
		KeepAlive: 30 * time.Second,
		Resolver:  getResolver(),
	}
}

func FilterIPsByMode(ips []net.IP, mode string) []string {
	norm := EffectiveIPMode(mode)
	var out []string
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		isV4 := ip.To4() != nil
		if (norm == "v4" && !isV4) || (norm == "v6" && (isV4 || ip.To16() == nil)) {
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

func ResolvePreferredIP(ctx context.Context, host, mode string) (string, error) {
	ips, err := ResolveIPs(ctx, host, mode)
	if err != nil {
		return "", err
	}
	return ips[0], nil
}

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
		network := "tcp4"
		if norm == "v6" {
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

func TransportWithIPModeAndCertCheck(mode string, certCheck func(host string, peerCerts []*x509.Certificate) error) *http.Transport {
	norm := EffectiveIPMode(mode)
	if norm != "v4" && norm != "v6" {
		norm = DefaultIPMode
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			rawConn, err := DialContextIPMode(ctx, host, port, norm, DialTimeout)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				NextProtos:         []string{"h2", "http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = tlsConn.Close()
				return nil, err
			}
			if certCheck != nil {
				if cerr := certCheck(host, tlsConn.ConnectionState().PeerCertificates); cerr != nil {
					_ = tlsConn.Close()
					return nil, cerr
				}
			}
			return tlsConn, nil
		},
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
	}
}

func Client(timeout time.Duration) *http.Client {
	return ClientWithIPMode(DefaultIPMode, timeout)
}

func ClientWithIPMode(mode string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: TransportWithIPMode(mode),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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
		if e != nil && r != nil {
			r.Body.Close()
		}
		return r, e
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
