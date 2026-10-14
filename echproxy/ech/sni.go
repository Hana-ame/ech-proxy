package cloudflare_ech

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const routeCacheTTL = 30 * time.Minute

type routeEntry struct {
	mode   string
	expiry time.Time
}

var (
	routeMu sync.RWMutex
	routes  = map[string]routeEntry{}
)

func getCachedRoute(host string) (string, bool) {
	routeMu.RLock()
	defer routeMu.RUnlock()
	e, ok := routes[host]
	if !ok || time.Now().After(e.expiry) {
		return "", false
	}
	return e.mode, true
}

func setCachedRoute(host, mode string) {
	routeMu.Lock()
	routes[host] = routeEntry{mode: mode, expiry: time.Now().Add(routeCacheTTL)}
	routeMu.Unlock()
}

func clearCachedRoute(host string) {
	routeMu.Lock()
	delete(routes, host)
	routeMu.Unlock()
}

// DetectTransportMode 全自动无干预判断目标主机应使用 "ech" 还是 "sni"：
//  1. 优先读取已验证成功的路由缓存；
//  2. 通过 DoH（或公共 DNS 回退）解析目标主机 IP，检查是否属于 Cloudflare 网段（netdial.IsCloudflareIP）：
//     - 属于 Cloudflare 网段 -> 返回 "ech"（走 Cloudflare ECH 加密 ClientHello）
//     - 不属于 Cloudflare 网段 -> 返回 "sni"（走真实 IP + 伪造 SNI 直连，如 sukebei.nyaa.si、i.pximg.net 等）
func DetectTransportMode(ctx context.Context, host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if cached, ok := getCachedRoute(host); ok {
		return cached
	}
	ips, err := ResolveHostIPs(ctx, host)
	if err == nil && len(ips) > 0 {
		for _, ipStr := range ips {
			if netdial.IsCloudflareIP(net.ParseIP(ipStr)) {
				return "ech"
			}
		}
		return "sni"
	}
	return "ech"
}

// RoundTrip 全自动无干预执行上游请求分发：
//   - "direct": 仅用于门户自身（reminder.moonchan.xyz）或显式指定直连的站点；
//   - 其他所有情况（"" / "auto" / "ech" / "sni"）：
//     自动根据目标 IP 是否属于 Cloudflare 选择最优模式（ECH 或 SNI），并在首选模式失败时自动无感切换备选模式。
func RoundTrip(req *http.Request, mode, ipMode string) (*http.Response, error) {
	if mode == "direct" {
		return netdial.ClientWithIPMode(ipMode, netdial.OpTimeout).Do(req)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	// 确定首选传输模式：若已缓存或自动识别出 Cloudflare / 非 Cloudflare，优先按识别结果执行
	primary := mode
	if primary == "" || primary == "auto" {
		primary = DetectTransportMode(req.Context(), host)
	} else if cached, ok := getCachedRoute(host); ok {
		primary = cached
	}

	resp, err := doSingleMode(req, primary, ipMode)
	if err == nil && !isCloudflareRouteRejection(resp, primary) {
		setCachedRoute(host, primary)
		return resp, nil
	}
	if resp != nil {
		resp.Body.Close()
	}
	clearCachedRoute(host)

	// 首选模式失败（例如配置成了 ech 但目标子域实际在非 Cloudflare CDN，或反之）：自动无感切换另一模式
	secondary := "sni"
	if primary == "sni" {
		secondary = "ech"
	}
	if resp2, err2 := doSingleMode(req, secondary, ipMode); err2 == nil {
		setCachedRoute(host, secondary)
		return resp2, nil
	}

	// 兜底尝试标准直连
	if resp3, err3 := netdial.ClientWithIPMode(ipMode, netdial.OpTimeout).Do(req); err3 == nil {
		return resp3, nil
	}
	return nil, err
}

func doSingleMode(req *http.Request, mode, ipMode string) (*http.Response, error) {
	switch mode {
	case "sni":
		return SNIFrontDo(req, ipMode)
	case "direct":
		return netdial.ClientWithIPMode(ipMode, netdial.OpTimeout).Do(req)
	default:
		return Do(req, ipMode)
	}
}

// isCloudflareRouteRejection 判断 ECH 响应是否为 Cloudflare 边缘因域名未托管在 CF 而返回的网关拒绝状态码。
func isCloudflareRouteRejection(resp *http.Response, mode string) bool {
	if mode != "ech" && mode != "" {
		return false
	}
	switch resp.StatusCode {
	case 521, 522, 523, 525, 530, 421:
		return true
	}
	return false
}

type ipCacheEntry struct {
	ips    []string
	expiry time.Time
}

var (
	ipCacheMu    sync.Mutex
	ipCache      = map[string]ipCacheEntry{}
	sniTransMu   sync.Mutex
	sniH2Trans   = map[string]*http2.Transport{}
	sniH1Clients = map[string]*http.Client{}
)

// ResolveHostIPs 通过 DoH（及公共 DNS 兜底）查询目标域名的 IPv4 A 记录并按 TTL 缓存。
func ResolveHostIPs(ctx context.Context, host string) ([]string, error) {
	ipCacheMu.Lock()
	if e, ok := ipCache[host]; ok && time.Now().Before(e.expiry) {
		ipCacheMu.Unlock()
		return e.ips, nil
	}
	ipCacheMu.Unlock()

	resp, err := netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() (*http.Response, error) {
		r, e := QueryDoH(ctx, host, 1)
		if e != nil && r != nil {
			r.Body.Close()
		}
		return r, e
	})
	var ips []string
	ttl := 300
	if err == nil && resp != nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var d dohResponse
			if json.NewDecoder(resp.Body).Decode(&d) == nil {
				seen := make(map[string]bool)
				for _, ans := range d.Answer {
					if ans.Type == 1 && net.ParseIP(ans.Data) != nil && !seen[ans.Data] {
						seen[ans.Data] = true
						ips = append(ips, ans.Data)
						if ans.TTL > 0 && ans.TTL < ttl {
							ttl = ans.TTL
						}
					}
				}
			}
		}
	}

	// 若 DoH 未返回结果，回退使用 netdial 公共 DNS 解析器
	if len(ips) == 0 {
		if ipStr, rerr := netdial.ResolvePreferredIP(ctx, host, "v4"); rerr == nil && ipStr != "" {
			ips = append(ips, ipStr)
		} else {
			return nil, fmt.Errorf("no A record for %s", host)
		}
	}

	if ttl > 86400 {
		ttl = 86400
	}
	ipCacheMu.Lock()
	ipCache[host] = ipCacheEntry{ips: ips, expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
	ipCacheMu.Unlock()
	return ips, nil
}

func dialUTLS(ctx context.Context, ip string, nextProtos []string) (*utls.UConn, error) {
	rawConn, err := netdial.Dialer().DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         shellDomain,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
	}, utls.HelloChrome_120)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uConn, nil
}

func getSNIH2Transport(ip string) *http2.Transport {
	sniTransMu.Lock()
	defer sniTransMu.Unlock()
	if t, ok := sniH2Trans[ip]; ok {
		return t
	}
	t := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			uConn, err := dialUTLS(ctx, ip, []string{"h2", "http/1.1"})
			if err != nil {
				return nil, err
			}
			if uConn.ConnectionState().NegotiatedProtocol != "h2" {
				uConn.Close()
				return nil, fmt.Errorf("upstream negotiated %q, not h2", uConn.ConnectionState().NegotiatedProtocol)
			}
			return uConn, nil
		},
	}
	if len(sniH2Trans) >= 256 {
		for k, old := range sniH2Trans {
			old.CloseIdleConnections()
			delete(sniH2Trans, k)
			break
		}
	}
	sniH2Trans[ip] = t
	return t
}

func getSNIH1Client(ip string) *http.Client {
	sniTransMu.Lock()
	defer sniTransMu.Unlock()
	if c, ok := sniH1Clients[ip]; ok {
		return c
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialUTLS(ctx, ip, []string{"http/1.1"})
		},
		MaxIdleConns:    32,
		IdleConnTimeout: 90 * time.Second,
	}
	c := &http.Client{
		Transport: tr,
		Timeout:   netdial.OpTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	sniH1Clients[ip] = c
	return c
}

// SNIFrontDo 使用 SNI 伪装直连目标主机（同时兼容 HTTP/2 与 HTTP/1.1 源站）。
func SNIFrontDo(req *http.Request, _ ...string) (*http.Response, error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ips, err := ResolveHostIPs(req.Context(), strings.ToLower(host))
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		resp, err := getSNIH2Transport(ip).RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// 若源站仅支持 HTTP/1.1，自动回退至 uTLS HTTP/1.1 传输
		if strings.Contains(err.Error(), "not h2") {
			if resp1, err1 := getSNIH1Client(ip).Do(req); err1 == nil {
				return resp1, nil
			} else {
				err = err1
			}
		}
		lastErr = err
		sniTransMu.Lock()
		if old, ok := sniH2Trans[ip]; ok {
			old.CloseIdleConnections()
			delete(sniH2Trans, ip)
		}
		sniTransMu.Unlock()
	}
	ipCacheMu.Lock()
	delete(ipCache, host)
	ipCacheMu.Unlock()
	return nil, fmt.Errorf("all IPs failed for %s: %w", host, lastErr)
}
