// Package netdial 提供基础网络拨号、公共 DNS 解析、IPv4/IPv6 协议族绑定、
// Cloudflare IP 识别、远程/本地文件拉取与通用重试工具。本模块不依赖项目内任何其他包。
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
	OpTimeout     = 5 * time.Minute
	RetryAttempts = 3
	RetryBackoff  = 2 * time.Second
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
				d := net.Dialer{Timeout: OpTimeout}
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
		Timeout:   OpTimeout,
		KeepAlive: 30 * time.Second,
		Resolver:  getResolver(),
	}
}

// ResolvePreferredIP 按指定的协议族（"v4" 或 "v6"）解析域名并返回首个匹配的 IP。
func ResolvePreferredIP(ctx context.Context, host, mode string) (string, error) {
	ips, err := getResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, addr := range ips {
		if mode == "v4" && addr.IP.To4() != nil {
			return addr.IP.String(), nil
		}
		if mode == "v6" && addr.IP.To4() == nil && addr.IP.To16() != nil {
			return addr.IP.String(), nil
		}
	}
	return "", fmt.Errorf("no %s address for %s", mode, host)
}

// DialContextIPMode 根据 ipMode（"v4"、"v6" 或 ""/"auto"）向目标 host:port 发起 TCP 连接。
func DialContextIPMode(ctx context.Context, host, port, mode string, timeout time.Duration) (net.Conn, error) {
	if mode == "v4" || mode == "v6" {
		ip, err := ResolvePreferredIP(ctx, host, mode)
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	}
	return (&net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Resolver:  getResolver(),
	}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
}

// Transport 返回全局复用的默认 HTTP Transport。
func Transport() *http.Transport {
	transportOnce.Do(func() {
		cachedTransport = &http.Transport{
			DialContext:       Dialer().DialContext,
			TLSClientConfig:   &tls.Config{RootCAs: getRootPool()},
			MaxIdleConns:      100,
			IdleConnTimeout:   OpTimeout,
			ForceAttemptHTTP2: true,
		}
	})
	return cachedTransport
}

// TransportWithIPMode 返回锁定出口 IP 协议族（"v4" 或 "v6"）的 HTTP Transport。
func TransportWithIPMode(mode string) *http.Transport {
	if mode != "v4" && mode != "v6" {
		return Transport()
	}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return DialContextIPMode(ctx, host, port, mode, OpTimeout)
		},
		TLSClientConfig:   &tls.Config{RootCAs: getRootPool()},
		MaxIdleConns:      100,
		IdleConnTimeout:   OpTimeout,
		ForceAttemptHTTP2: true,
	}
}

// Client 返回不自动跟随重定向的 HTTP 客户端。
func Client(timeout time.Duration) *http.Client {
	return ClientWithIPMode("", timeout)
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
