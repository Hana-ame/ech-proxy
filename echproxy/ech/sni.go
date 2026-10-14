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

// RoundTrip 统一执行上游请求分发：
//   - "direct": 直接通过标准 HTTPS 请求目标（支持 ip_mode 锁定 v4/v6）
//   - "sni":    通过 DoH 解析真实 IP + 伪造 SNI (cloudflare-ech.com) 直连
//   - ""/"ech": 默认走 Cloudflare ECH 域前置隧道；若目标非 Cloudflare 节点则自动降级尝试 SNI 与 Direct。
func RoundTrip(req *http.Request, mode, ipMode string) (*http.Response, error) {
	switch mode {
	case "direct":
		return netdial.ClientWithIPMode(ipMode, netdial.OpTimeout).Do(req)
	case "sni":
		return SNIFrontDo(req)
	default:
		resp, err := Do(req, ipMode)
		if err == nil {
			return resp, nil
		}
		// 若默认 ECH 握手失败（如泛域名下的子站点未托管在 Cloudflare），自动降级尝试 SNI 伪装与直连
		if resp2, err2 := SNIFrontDo(req); err2 == nil {
			return resp2, nil
		}
		if resp3, err3 := netdial.ClientWithIPMode(ipMode, netdial.OpTimeout).Do(req); err3 == nil {
			return resp3, nil
		}
		return nil, err
	}
}

type ipCacheEntry struct {
	ips    []string
	expiry time.Time
}

var (
	ipCacheMu     sync.Mutex
	ipCache       = map[string]ipCacheEntry{}
	sniTransMu    sync.Mutex
	sniTransports = map[string]*http2.Transport{}
)

// ResolveHostIPs 通过 DoH 查询目标域名的 A 记录并按 TTL 缓存。
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
	if err != nil {
		return nil, fmt.Errorf("DoH %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s status %d", host, resp.StatusCode)
	}

	var d dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	ttl := 300
	seen := make(map[string]bool)
	var ips []string
	for _, ans := range d.Answer {
		if ans.Type == 1 && net.ParseIP(ans.Data) != nil && !seen[ans.Data] {
			seen[ans.Data] = true
			ips = append(ips, ans.Data)
			if ans.TTL > 0 && ans.TTL < ttl {
				ttl = ans.TTL
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A record for %s", host)
	}
	if ttl > 86400 {
		ttl = 86400
	}
	ipCacheMu.Lock()
	ipCache[host] = ipCacheEntry{ips: ips, expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
	ipCacheMu.Unlock()
	return ips, nil
}

func getSNITransport(ip string) *http2.Transport {
	sniTransMu.Lock()
	defer sniTransMu.Unlock()
	if t, ok := sniTransports[ip]; ok {
		return t
	}
	t := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			rawConn, err := netdial.Dialer().DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			if err != nil {
				return nil, err
			}
			uConn := utls.UClient(rawConn, &utls.Config{
				ServerName:         shellDomain,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
			}, utls.HelloChrome_120)
			if err := uConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			if uConn.ConnectionState().NegotiatedProtocol != "h2" {
				rawConn.Close()
				return nil, fmt.Errorf("upstream did not negotiate h2")
			}
			return uConn, nil
		},
	}
	if len(sniTransports) >= 256 {
		for k, old := range sniTransports {
			old.CloseIdleConnections()
			delete(sniTransports, k)
			break
		}
	}
	sniTransports[ip] = t
	return t
}

// SNIFrontDo 使用 SNI 伪装直连目标主机（适用于仅被 SNI 阻断的非 Cloudflare 站点，如 sukebei.nyaa.si）。
func SNIFrontDo(req *http.Request) (*http.Response, error) {
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
		resp, err := getSNITransport(ip).RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sniTransMu.Lock()
		if old, ok := sniTransports[ip]; ok {
			old.CloseIdleConnections()
			delete(sniTransports, ip)
		}
		sniTransMu.Unlock()
	}
	ipCacheMu.Lock()
	delete(ipCache, host)
	ipCacheMu.Unlock()
	return nil, fmt.Errorf("all IPs failed for %s: %w", host, lastErr)
}
