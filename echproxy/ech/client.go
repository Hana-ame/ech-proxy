// Package cloudflare_ech 封装上游传输隧道：
//  1. Cloudflare ECH 域前置（Encrypted Client Hello + uTLS Chrome 指纹）
//  2. SNI 伪装直连（DoH 解析真实 IP + 伪造 SNI + HTTP/2 传输）
//  3. Direct 明文/标准 TLS 直连（支持 IPv4/IPv6 协议族锁定）
//
// 本模块仅依赖标准库、netdial、utls 与 x/net/http2。
package cloudflare_ech

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	shellDomain   = "cloudflare-ech.com"
	defaultDohURL = "https://moonchan.xyz/doh"
	dialTimeout   = netdial.OpTimeout
	dohTimeout    = netdial.OpTimeout
	minTTL        = 60
	maxTTL        = 24 * 3600
)

// Client 是基于 cloudflare-ech.com ECH 域前置的 HTTP 客户端。
type Client struct {
	inner *http.Client
}

type echEntry struct {
	config []byte
	expiry time.Time
}

type runtimeConfig struct {
	dohURL string
	dialIP string
	ipMode string
}

var (
	cfgPtr        atomic.Pointer[runtimeConfig]
	cacheMu       sync.Mutex
	cache         = map[string]*echEntry{}
	clientsMu     sync.Mutex
	clients       = map[string]*Client{}
	lastECHConfig []byte
	refreshOnce   sync.Once

	echSvcParamRE = regexp.MustCompile(`ech="?([A-Za-z0-9+/=]+)"?`)
	wsvcWireRE    = regexp.MustCompile(`\\#\s+(\d+)\s+([0-9a-fA-F\s]+)`)
	nonHexRE      = regexp.MustCompile(`[^0-9a-fA-F]`)
)

func currentConfig() *runtimeConfig {
	if c := cfgPtr.Load(); c != nil {
		return c
	}
	c := &runtimeConfig{dohURL: defaultDohURL}
	cfgPtr.Store(c)
	return c
}

// SetDohURL 设置 DoH 服务端完整 URL。
func SetDohURL(u string) {
	nc := *currentConfig()
	nc.dohURL = u
	nc.dialIP = ""
	cfgPtr.Store(&nc)
}

// SetDoHConfig 通过域名与引导 IP 配置 DoH（跳过对 DoH 域名的本地 DNS 解析）。
func SetDoHConfig(host, bootstrapIP string) {
	nc := *currentConfig()
	nc.dohURL = fmt.Sprintf("https://%s/doh", host)
	nc.dialIP = bootstrapIP
	cfgPtr.Store(&nc)
}

// SetIPMode 设置全局默认上游出口 IP 协议族（"v4"、"v6" 或 ""）。
func SetIPMode(mode string) {
	nc := *currentConfig()
	if mode == "v4" || mode == "v6" {
		nc.ipMode = mode
	} else {
		nc.ipMode = ""
	}
	cfgPtr.Store(&nc)

	clientsMu.Lock()
	defer clientsMu.Unlock()
	for _, c := range clients {
		if tr, ok := c.inner.Transport.(*http2.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	clients = map[string]*Client{}
}

// CheckDualStack 检查 moonchan.xyz 是否发布 A / AAAA 记录。
func CheckDualStack(ctx context.Context) (hasV4, hasV6 bool) {
	ips, err := netdial.Dialer().Resolver.LookupIPAddr(ctx, "moonchan.xyz")
	if err != nil {
		return false, false
	}
	for _, addr := range ips {
		if addr.IP.To4() != nil {
			hasV4 = true
		} else if addr.IP.To16() != nil {
			hasV6 = true
		}
	}
	return
}

// QueryDoH 向当前配置的 DoH 节点发起 DNS 查询（JSON 格式）。
func QueryDoH(ctx context.Context, name string, qtype int) (*http.Response, error) {
	u := fmt.Sprintf("%s?name=%s&type=%d", currentConfig().dohURL, url.QueryEscape(name), qtype)
	return doDohRequest(ctx, u)
}

func doDohRequest(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	cfg := currentConfig()
	tr := netdial.Transport()
	if cfg.dialIP != "" {
		tr = tr.Clone()
		dialIP := cfg.dialIP
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{Timeout: dohTimeout}).DialContext(ctx, network, net.JoinHostPort(dialIP, port))
		}
		if uParsed, err := url.Parse(urlStr); err == nil && uParsed != nil {
			tr.TLSClientConfig = &tls.Config{ServerName: uParsed.Host}
		}
	} else if cfg.ipMode != "" {
		tr = netdial.TransportWithIPMode(cfg.ipMode)
	}
	return (&http.Client{Transport: tr, Timeout: dohTimeout}).Do(req)
}

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func fetchECHConfig(ctx context.Context, domain string) ([]byte, error) {
	cacheMu.Lock()
	if e, ok := cache[domain]; ok && time.Now().Before(e.expiry) {
		cacheMu.Unlock()
		return e.config, nil
	}
	cacheMu.Unlock()

	dohURL := currentConfig().dohURL
	return netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() ([]byte, error) {
		resp, err := QueryDoH(ctx, domain, 65)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH %s status %d", dohURL, resp.StatusCode)
		}
		var d dohResponse
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			return nil, err
		}
		for _, ans := range d.Answer {
			if ans.Type != 65 {
				continue
			}
			var cfg []byte
			if m := echSvcParamRE.FindStringSubmatch(ans.Data); len(m) > 1 {
				cfg, err = base64.StdEncoding.DecodeString(m[1])
			} else if m := wsvcWireRE.FindStringSubmatch(ans.Data); len(m) > 1 {
				var wire []byte
				wire, err = hex.DecodeString(nonHexRE.ReplaceAllString(m[2], ""))
				if err == nil {
					cfg, err = parseSVCBWire(wire)
				}
			}
			if err != nil {
				return nil, err
			}
			if len(cfg) > 0 {
				ttl := ans.TTL
				if ttl < minTTL {
					ttl = minTTL
				} else if ttl > maxTTL {
					ttl = maxTTL
				}
				cacheMu.Lock()
				cache[domain] = &echEntry{config: cfg, expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
				cacheMu.Unlock()
				return cfg, nil
			}
		}
		return nil, fmt.Errorf("no ECH config found for %s", domain)
	})
}

func parseSVCBWire(wire []byte) ([]byte, error) {
	if len(wire) < 2 {
		return nil, fmt.Errorf("wire too short")
	}
	off := 2
	for off < len(wire) {
		l := int(wire[off])
		off++
		if l == 0 {
			break
		}
		if off+l > len(wire) {
			return nil, fmt.Errorf("truncated target name")
		}
		off += l
	}
	for off+4 <= len(wire) {
		key := int(wire[off])<<8 | int(wire[off+1])
		valLen := int(wire[off+2])<<8 | int(wire[off+3])
		off += 4
		if off+valLen > len(wire) {
			return nil, fmt.Errorf("truncated SvcParam")
		}
		if key == 5 {
			return wire[off : off+valLen], nil
		}
		off += valLen
	}
	return nil, fmt.Errorf("ECH SvcParam not found")
}

func newTransport(echConfig []byte, ipMode string) *http2.Transport {
	return &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, _, addr string, _ *tls.Config) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			uCfg := &utls.Config{
				ServerName:                     host,
				EncryptedClientHelloConfigList: echConfig,
				MinVersion:                     tls.VersionTLS13,
				NextProtos:                     []string{"h2", "http/1.1"},
			}
			mode := ipMode
			if mode == "" || mode == "auto" {
				mode = currentConfig().ipMode
			}
			return netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() (net.Conn, error) {
				rawConn, err := netdial.DialContextIPMode(ctx, shellDomain, "443", mode, dialTimeout)
				if err != nil {
					return nil, err
				}
				uConn := utls.UClient(rawConn, uCfg, utls.HelloChrome_120)
				if err := uConn.HandshakeContext(ctx); err != nil {
					rawConn.Close()
					return nil, err
				}
				if uConn.ConnectionState().NegotiatedProtocol != "h2" {
					rawConn.Close()
					return nil, fmt.Errorf("upstream did not negotiate h2")
				}
				return uConn, nil
			})
		},
	}
}

func newClient(echConfig []byte, ipMode string) *Client {
	return &Client{
		inner: &http.Client{
			Transport: newTransport(echConfig, ipMode),
			Timeout:   0,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// New 创建并初始化一个新的 ECH 客户端实例。
func New() (*Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
	defer cancel()
	echConfig, err := fetchECHConfig(ctx, shellDomain)
	if err != nil {
		return nil, err
	}
	return newClient(echConfig, ""), nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	return c.inner.Do(req)
}

func getECHClient(ipMode string) (*Client, error) {
	mode := strings.ToLower(strings.TrimSpace(ipMode))
	if mode == "" || mode == "auto" {
		mode = currentConfig().ipMode
	}
	if mode != "v4" && mode != "v6" {
		mode = "auto"
	}
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[mode]; ok {
		return c, nil
	}
	if len(lastECHConfig) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
		defer cancel()
		cfg, err := fetchECHConfig(ctx, shellDomain)
		if err != nil {
			return nil, err
		}
		lastECHConfig = cfg
	}
	c := newClient(lastECHConfig, mode)
	clients[mode] = c
	return c, nil
}

// Do 通过 Cloudflare ECH 隧道发送请求（可选指定 "v4" 或 "v6" 出口协议族）。
func Do(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	c, err := getECHClient(mode)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// InitDefault 初始化全局默认 ECH 客户端并启动后台定期刷新协程。
func InitDefault() error {
	ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
	defer cancel()
	cfg, err := fetchECHConfig(ctx, shellDomain)
	if err != nil {
		return err
	}
	clientsMu.Lock()
	lastECHConfig = cfg
	clientsMu.Unlock()
	if _, err := getECHClient(""); err != nil {
		return err
	}
	refreshOnce.Do(func() { go refreshLoop() })
	return nil
}

func refreshLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
		echConfig, err := fetchECHConfig(ctx, shellDomain)
		cancel()
		if err != nil {
			continue
		}
		clientsMu.Lock()
		lastECHConfig = echConfig
		var oldClients []*Client
		for mode, old := range clients {
			oldClients = append(oldClients, old)
			clients[mode] = newClient(echConfig, mode)
		}
		clientsMu.Unlock()
		for _, old := range oldClients {
			if tr, ok := old.inner.Transport.(*http2.Transport); ok {
				tr.CloseIdleConnections()
			}
		}
	}
}
