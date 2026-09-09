// Package netdial 提供在 Android/Termux 等无标准 /etc/resolv.conf 环境下
// 可用的网络拨号工具。
//
// 背景: Termux 没有 /etc/resolv.conf, Go 内置解析器(pure Go)会默认尝试
// [::1]:53, 导致 DNS lookup 失败 ("read udp [::1]:53: connection refused")。
// 且 Termux 的 CA 证书位于 $PREFIX/etc/tls/cert.pem, 不在 Go 默认搜索的
// 系统路径里, https 请求会报 "certificate signed by unknown authority"。
// 在 Termux 上运行的 proxy 都必须用本包提供的 Dialer/Transport。
package netdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// 操作级超时与重试: DoH 拉取 / 拨号 / DNS / 配置抓取统一放宽到 5 分钟,
// 瞬时失败时重试, 避免 moonchan.xyz DoH 端点偶发慢或抖动直接 context
// deadline exceeded 导致 ECH 初始化 / SNI 解析失败。
const (
	OpTimeout     = 5 * time.Minute
	RetryAttempts = 3
	RetryBackoff  = 2 * time.Second
)

// dnsServers 公共 DNS 列表, 依次尝试。
var dnsServers = []string{
	"8.8.8.8:53",
	"1.1.1.1:53",
	"223.5.5.5:53",
	"114.114.114.114:53",
}

// newResolver 构造固定走公共 DNS 的解析器 (绕过本机 [::1]:53)。
// 按 Go 解析器要求的 network 参数拨号 (udp/tcp): 收到 TC (截断) 响应时
// Resolver 会以 tcp 重试, 之前忽略 network 参数总是 UDP, 截断响应
// 无法 fallback 导致解析失败。
func newResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: OpTimeout}
			var err error
			for _, dns := range dnsServers {
				var conn net.Conn
				conn, err = d.DialContext(ctx, network, dns)
				if err == nil {
					return conn, nil
				}
			}
			return nil, err
		},
	}
}

// resolver 与 rootPool 全局缓存: Dialer()/Transport() 每次调用都新建
// 解析器/证书池, 证书池加载 (SystemCertPool + 读文件) 在热路径上不便宜,
// 且它们都是并发安全的, 全局复用一个即可。
var (
	resolverOnce sync.Once
	resolver     *net.Resolver

	rootPoolOnce sync.Once
	rootPool     *x509.CertPool
)

func getResolver() *net.Resolver {
	resolverOnce.Do(func() { resolver = newResolver() })
	return resolver
}

func getRootPool() *x509.CertPool {
	rootPoolOnce.Do(func() { rootPool = rootCAs() })
	return rootPool
}

// Dialer 返回使用公共 DNS 的 net.Dialer, 适用于 Termux 等无 resolv.conf 的环境。
func Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   OpTimeout,
		KeepAlive: 30 * time.Second,
		Resolver:  getResolver(),
	}
}

// rootCAs 加载系统根证书, 并附加 Termux 的 CA bundle (若存在)。
func rootCAs() *x509.CertPool {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	paths := []string{
		"/data/data/com.termux/files/usr/etc/tls/cert.pem",
		os.Getenv("PREFIX") + "/etc/tls/cert.pem",
	}
	for _, p := range paths {
		if p == "/etc/tls/cert.pem" || p == "" {
			continue
		}
		if pem, err := os.ReadFile(p); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	return pool
}

// Transport 返回适用于 Termux 的 http.Transport (公共 DNS + Termux CA)。
// 证书池全局缓存复用 (SystemCertPool 加载不便宜)。
func Transport() *http.Transport {
	return &http.Transport{
		DialContext: Dialer().DialContext,
		TLSClientConfig: &tls.Config{
			RootCAs: getRootPool(),
		},
	}
}

// Client 返回适用于 Termux 的 http.Client。
func Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: Transport(),
	}
}

// WebsocketDialOptions 返回适用于 Termux 的 websocket.DialOptions。
func WebsocketDialOptions() *websocket.DialOptions {
	return &websocket.DialOptions{
		HTTPClient: Client(OpTimeout),
	}
}

// sleepCtx 休眠 d，期间响应 ctx 取消；返回 false 表示 ctx 已取消。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Retry 重试 fn 直到成功、ctx 取消或达到 attempts 次；每次失败后 sleep backoff
// （受 ctx 取消）。用于 DoH / 拨号 / 配置抓取等易因瞬时网络抖动失败的操作。
// 返回最后一次错误；ctx 取消时立即返回 ctx.Err()。
func Retry[T any](ctx context.Context, attempts int, backoff time.Duration, fn func() (T, error)) (T, error) {
	var zero T
	var last error
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if i > 0 && !sleepCtx(ctx, backoff) {
			return zero, ctx.Err()
		}
		v, err := fn()
		if err == nil {
			return v, nil
		}
		last = err
	}
	return zero, last
}
