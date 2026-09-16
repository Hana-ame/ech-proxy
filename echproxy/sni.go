package echproxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const fakeSNI = "cloudflare-ech.com"

type ipCacheEntry struct {
	ips    []string
	expiry time.Time
}

var (
	ipCacheMu sync.Mutex
	ipCache   = map[string]ipCacheEntry{}
)

func resolveHostIP(ctx context.Context, host string) (string, error) {
	ips, err := resolveHostIPs(ctx, host)
	if err != nil {
		return "", err
	}
	return ips[0], nil
}

func resolveHostIPs(ctx context.Context, host string) ([]string, error) {
	ipCacheMu.Lock()
	if e, ok := ipCache[host]; ok && time.Now().Before(e.expiry) {
		ipCacheMu.Unlock()
		return e.ips, nil
	}
	ipCacheMu.Unlock()

	resp, err := netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() (*http.Response, error) {
		r, e := cloudflare_ech.QueryDoH(ctx, host, 1)
		if e != nil {
			if r != nil {
				r.Body.Close()
			}
			return nil, e
		}
		return r, nil
	})
	if err != nil {
		return nil, fmt.Errorf("DoH %s: %w", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s status %d", host, resp.StatusCode)
	}
	var d struct {
		Answer []struct {
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	ttl := 300
	seen := make(map[string]bool)
	var ips []string
	for _, ans := range d.Answer {
		if ans.Type != 1 || net.ParseIP(ans.Data) == nil {
			continue
		}
		if seen[ans.Data] {
			continue
		}
		seen[ans.Data] = true
		ips = append(ips, ans.Data)
		if ans.TTL > 0 && ans.TTL < ttl {
			ttl = ans.TTL
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

var (
	sniTransportsMu sync.Mutex
	sniTransports   = map[string]*http2.Transport{}
)

func getSNITransport(ip string) *http2.Transport {
	sniTransportsMu.Lock()
	defer sniTransportsMu.Unlock()
	if t, ok := sniTransports[ip]; ok {
		return t
	}
	t := newSNIFrontTransport(ip)
	sniTransports[ip] = t
	return t
}

func newSNIFrontTransport(ip string) *http2.Transport {
	return &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			rawConn, err := netdial.Dialer().DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			if err != nil {
				return nil, fmt.Errorf("dial %s: %w", ip, err)
			}
			uConn := utls.UClient(rawConn, &utls.Config{
				ServerName:         fakeSNI,
				InsecureSkipVerify: true,
				NextProtos:         []string{"h2", "http/1.1"},
			}, utls.HelloChrome_120)
			if err := uConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("TLS handshake %s: %w", ip, err)
			}
			if uConn.ConnectionState().NegotiatedProtocol != "h2" {
				rawConn.Close()
				return nil, fmt.Errorf("upstream did not negotiate h2")
			}
			return uConn, nil
		},
	}
}

func sniFrontDo(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ips, err := resolveHostIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	var lastErr error
	for _, ip := range ips {
		t := getSNITransport(ip)
		resp, err := t.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		sniTransportsMu.Lock()
		delete(sniTransports, ip)
		sniTransportsMu.Unlock()
	}
	clearIPCache(host)
	return nil, fmt.Errorf("all IPs failed for %s: %w", host, lastErr)
}

func clearIPCache(host string) {
	ipCacheMu.Lock()
	delete(ipCache, host)
	ipCacheMu.Unlock()
}
