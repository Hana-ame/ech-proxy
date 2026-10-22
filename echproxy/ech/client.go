// Package cloudflare_ech 封装三种上游 GFW 绕过与传输隧道模块：
//  1. 方式一（SNI 伪装）：通过 DoH 解析真实 IP + SNI 伪装绕过请求 + 核对服务端回传证书是否与伪装前真实域名（truedomain.com）一致、是否过期（见 sni.go）
//  2. 方式二（ECH 加密）：通过 DoH 解析域名与 HTTPS/ECH 配置 + 使用 Cloudflare ECH 请求 + 核对服务端回传证书（见 client.go）
//  3. 方式三（TLS 分片绕过 GFW）：通过 DoH 解析真实 IP + TLS ClientHello 记录分片（Fragmentation）绕过 GFW DPI + 核对服务端回传证书（见 fragment.go）
//  4. 上游证书校验与强行访问放行控制（见 certcheck.go）
//
// 本模块仅依赖标准库、netdial、logger、utls 与 x/net/http2。
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

	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	shellDomain = "cloudflare-ech.com"

	// DefaultDoHHost 是首选 DoH 端点的主机名 —— 引用 netdial.DefaultSiteHost（全项目唯一 true source）。
	DefaultDoHHost = netdial.DefaultSiteHost
	// DefaultPrimaryDoHURL 是首选 DoH 端点，由 DefaultDoHHost 派生。
	DefaultPrimaryDoHURL = "https://" + DefaultDoHHost + "/doh"
	// DefaultSecondaryDoHURL 是次选兜底 DoH 端点（Cloudflare 1.1.1.1 官方 DoH JSON/Wire 路径：https://1.1.1.1/dns-query）。
	DefaultSecondaryDoHURL = "https://1.1.1.1/dns-query"

	defaultDohURL   = DefaultPrimaryDoHURL
	fallbackDohURL  = DefaultSecondaryDoHURL
	dialTimeout     = netdial.DialTimeout
	dohTimeout      = netdial.DoHTimeout
	minTTL          = 60
	maxTTL          = 24 * 3600
	maxECHCacheSize = 256
)

func init() {
	netdial.DoHResolver = ResolveHostIPsByMode
}

// Client 是基于 cloudflare-ech.com ECH 域前置的 HTTP 客户端。
type Client struct {
	inner *http.Client
}

type echEntry struct {
	config []byte
	expiry time.Time
}

type echFlightCall struct {
	done chan struct{}
	cfg  []byte
	err  error
}

type runtimeConfig struct {
	dohURL      string
	fallbackURL string
	dialIP      string
	ipMode      string
}

var (
	cfgPtr        atomic.Pointer[runtimeConfig]
	cacheMu       sync.Mutex
	cache         = map[string]*echEntry{}
	echFlightMu   sync.Mutex
	echFlights    = map[string]*echFlightCall{}
	clientsMu     sync.Mutex
	clients       = map[string]*Client{}
	lastECHConfig []byte
	refreshOnce   sync.Once

	dohTransMu        sync.Mutex
	dohDialTransports = map[string]*http.Transport{}

	echSvcParamRE = regexp.MustCompile(`ech="?([A-Za-z0-9+/=]+)"?`)
	wsvcWireRE    = regexp.MustCompile(`\\#\s+(\d+)\s+([0-9a-fA-F\s]+)`)
	nonHexRE      = regexp.MustCompile(`[^0-9a-fA-F]`)
)

func currentConfig() *runtimeConfig {
	if c := cfgPtr.Load(); c != nil {
		return c
	}
	c := &runtimeConfig{
		dohURL:      defaultDohURL,
		fallbackURL: fallbackDohURL,
		ipMode:      netdial.DefaultIPMode, // 默认 ipv4 ("v4")
	}
	cfgPtr.Store(c)
	return c
}

func clearDoHDialTransports() {
	dohTransMu.Lock()
	defer dohTransMu.Unlock()
	for _, tr := range dohDialTransports {
		tr.CloseIdleConnections()
	}
	dohDialTransports = map[string]*http.Transport{}
}

func getDoHDialTransport(dialIP, serverName string) *http.Transport {
	key := dialIP + "|" + serverName
	dohTransMu.Lock()
	defer dohTransMu.Unlock()
	if tr, ok := dohDialTransports[key]; ok {
		return tr
	}
	tr := netdial.Transport().Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: dohTimeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(dialIP, port))
	}
	if serverName != "" {
		tr.TLSClientConfig = &tls.Config{
			ServerName: serverName,
			RootCAs:    netdial.RootPool(),
		}
	}
	dohDialTransports[key] = tr
	return tr
}

// PrimaryDoHURL 返回当前配置的首选 DoH URL。
func PrimaryDoHURL() string {
	return currentConfig().dohURL
}

// SecondaryDoHURL 返回当前配置的次选 DoH URL。
func SecondaryDoHURL() string {
	return currentConfig().fallbackURL
}

// SetDohURL 设置首选 DoH 服务端完整 URL（次选默认保留 https://1.1.1.1/dns-query）。
func SetDohURL(u string) {
	nc := *currentConfig()
	if u == "" {
		u = defaultDohURL
	}
	nc.dohURL = u
	if nc.fallbackURL == "" {
		nc.fallbackURL = fallbackDohURL
	}
	nc.dialIP = ""
	cfgPtr.Store(&nc)
	clearDoHDialTransports()
}

// SetFallbackDohURL 设置次选（兜底）DoH 服务端完整 URL。
func SetFallbackDohURL(u string) {
	nc := *currentConfig()
	nc.fallbackURL = u
	cfgPtr.Store(&nc)
}

// SetDoHConfig 通过域名与引导 IP 配置首选 DoH（跳过对首选 DoH 域名的本地 DNS 解析，次选仍为 https://1.1.1.1/dns-query）。
func SetDoHConfig(host, bootstrapIP string) {
	nc := *currentConfig()
	if host == "" {
		host = DefaultDoHHost
	}
	nc.dohURL = fmt.Sprintf("https://%s/doh", host)
	if nc.fallbackURL == "" {
		nc.fallbackURL = fallbackDohURL
	}
	nc.dialIP = bootstrapIP
	cfgPtr.Store(&nc)
	clearDoHDialTransports()
}

// SetIPMode 设置全局默认上游出口 IP 协议族（默认 "v4"、"v6" 或 "dual"，大小写不敏感）。
func SetIPMode(mode string) {
	nc := *currentConfig()
	nc.ipMode = netdial.EffectiveIPMode(mode)
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

// GetIPMode 返回当前全局默认出口协议族（默认 "v4"、"v6" 或 "dual"）。
func GetIPMode() string {
	return currentConfig().ipMode
}

// CheckDualStack 检查 4545810.xyz 是否发布 A / AAAA 记录。
func CheckDualStack(ctx context.Context) (hasV4, hasV6 bool) {
	ips, err := ResolveHostIPsByMode(ctx, DefaultDoHHost, "dual")
	if err != nil {
		return false, false
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			if ip.To4() != nil {
				hasV4 = true
			} else if ip.To16() != nil {
				hasV6 = true
			}
		}
	}
	return
}

// QueryDoH 向当前配置的 DoH 节点发起 DNS 查询（JSON 格式）：
//   - 首选请求 https://4545810.xyz/doh；
//   - 若首选请求失败或返回非 200 状态码，自动无缝切换次选 https://1.1.1.1/dns-query。
func isSelfDoHHost(name string, cfg *runtimeConfig) bool {
	if cfg == nil || cfg.dialIP != "" || cfg.dohURL == "" {
		return false
	}
	u, err := url.Parse(cfg.dohURL)
	if err != nil || u == nil {
		return false
	}
	dohHost := netdial.CleanHost(u.Hostname())
	if dohHost == "" || net.ParseIP(dohHost) != nil {
		return false
	}
	return strings.EqualFold(dohHost, netdial.CleanHost(name))
}

func QueryDoH(ctx context.Context, name string, qtype int) (*http.Response, error) {
	cfg := currentConfig()
	// 当查询的目标域名恰好是首选 DoH 节点自身域名（如 4545810.xyz）且未配置引导 IP 时，
	// 优先直接查询次选 IP DoH（https://1.1.1.1/dns-query），避免先连接自身域名才能解析自身域名的循环依赖。
	if isSelfDoHHost(name, cfg) && cfg.fallbackURL != "" && cfg.fallbackURL != cfg.dohURL {
		ctxSec, cancelSec := context.WithTimeout(ctx, 2*time.Second)
		secondaryURL := fmt.Sprintf("%s?name=%s&type=%d", cfg.fallbackURL, url.QueryEscape(name), qtype)
		resp2, err2 := doDohRequest(ctxSec, secondaryURL, "", cfg.ipMode)
		cancelSec()
		if err2 == nil && resp2 != nil && resp2.StatusCode == http.StatusOK {
			return resp2, nil
		} else if resp2 != nil && resp2.Body != nil {
			_ = resp2.Body.Close()
		}
	}

	primaryURL := fmt.Sprintf("%s?name=%s&type=%d", cfg.dohURL, url.QueryEscape(name), qtype)
	resp, err := doDohRequest(ctx, primaryURL, cfg.dialIP, cfg.ipMode)
	if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
		return resp, nil
	}

	// 首选失败：若配置了次选 DoH（默认 https://1.1.1.1/dns-query），自动回退请求次选
	if cfg.fallbackURL != "" && cfg.fallbackURL != cfg.dohURL {
		secondaryURL := fmt.Sprintf("%s?name=%s&type=%d", cfg.fallbackURL, url.QueryEscape(name), qtype)
		resp2, err2 := doDohRequest(ctx, secondaryURL, "", cfg.ipMode)
		if err2 == nil && resp2 != nil && resp2.StatusCode == http.StatusOK {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			return resp2, nil
		}
		if resp2 != nil && resp2.Body != nil {
			_ = resp2.Body.Close()
		}
	}

	// 兜底备用：若前序 DoH 均失败（如国内阻断 1.1.1.1:443），回退请求国内高速无污染 DoH（阿里云 223.5.5.5）
	aliyunURL := fmt.Sprintf("https://223.5.5.5/resolve?name=%s&type=%d", url.QueryEscape(name), qtype)
	resp3, err3 := doDohRequest(ctx, aliyunURL, "", cfg.ipMode)
	if err3 == nil && resp3 != nil && resp3.StatusCode == http.StatusOK {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return resp3, nil
	}
	if resp3 != nil && resp3.Body != nil {
		_ = resp3.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("all DoH endpoints failed (primary: %v, aliyun: %v)", err, err3)
	}
	return resp, err
}

func doDohRequest(ctx context.Context, urlStr, dialIP, ipMode string) (*http.Response, error) {
	// 注入 WithInsideDoH 标记：当底层 Transport 拨号连接 DoH 域名（如 4545810.xyz）时，
	// netdial.ResolveIPs 会直接通过 Bootstrap DoH (1.1.1.1) 解析 DoH 节点 IP，绝不再次回调 DoHResolver 造成无限递归与内存爆炸。
	dohCtx := netdial.WithInsideDoH(ctx)
	req, err := http.NewRequestWithContext(dohCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	tr := netdial.Transport()
	if dialIP != "" {
		serverName := ""
		if uParsed, err := url.Parse(urlStr); err == nil && uParsed != nil {
			serverName = uParsed.Host
		}
		tr = getDoHDialTransport(dialIP, serverName)
	} else if ipMode != "" {
		// 若 URL 主机本身是 IPv4 字面量（如次选 1.1.1.1）而当前处于 v6 模式，允许直连该 IP 字面量以防 DoH 死锁
		useMode := ipMode
		if uParsed, err := url.Parse(urlStr); err == nil && uParsed != nil {
			h := uParsed.Hostname()
			if ip := net.ParseIP(h); ip != nil && ip.To4() != nil && ipMode == "v6" {
				useMode = "dual"
			}
		}
		tr = netdial.TransportWithIPMode(useMode)
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
	domain = netdial.CleanHost(domain)
	cacheMu.Lock()
	if e, ok := cache[domain]; ok && time.Now().Before(e.expiry) {
		cacheMu.Unlock()
		return e.config, nil
	}
	cacheMu.Unlock()

	echFlightMu.Lock()
	if call, inFlight := echFlights[domain]; inFlight {
		echFlightMu.Unlock()
		select {
		case <-call.done:
			return call.cfg, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &echFlightCall{done: make(chan struct{})}
	echFlights[domain] = call
	echFlightMu.Unlock()

	defer func() {
		echFlightMu.Lock()
		delete(echFlights, domain)
		close(call.done)
		echFlightMu.Unlock()
	}()

	dohURL := currentConfig().dohURL
	cfgBytes, err := netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() ([]byte, error) {
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
				if len(cache) >= maxECHCacheSize {
					now := time.Now()
					for k, v := range cache {
						if now.After(v.expiry) {
							delete(cache, k)
						}
					}
					if len(cache) >= maxECHCacheSize {
						for k := range cache {
							delete(cache, k)
							break
						}
					}
				}
				cache[domain] = &echEntry{config: cfg, expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
				cacheMu.Unlock()
				return cfg, nil
			}
		}
		return nil, fmt.Errorf("no ECH config found for %s", domain)
	})
	call.cfg, call.err = cfgBytes, err
	return cfgBytes, err
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
		AllowHTTP:       false,
		IdleConnTimeout: 15 * time.Second,
		PingTimeout:     5 * time.Second,
		ReadIdleTimeout: 10 * time.Second,
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
				// 不由 utls 做自动证书校验，改由下方 validateUpstreamCert 统一核对回传证书与真实域名 host（时间 + 域名一致性 + 信任链）
				InsecureSkipVerify: true,
			}
			mode := netdial.NormalizeIPMode(ipMode)
			if mode == "" {
				mode = currentConfig().ipMode
			}
			mode = netdial.EffectiveIPMode(mode)

			// 优先通过 DoH 解析 ECH 接入节点 IP（防止本地 UDP 53 DNS 被污染）
			dialTarget := shellDomain
			if dohIPs, derr := ResolveHostIPsByMode(ctx, shellDomain, mode); derr == nil && len(dohIPs) > 0 {
				dialTarget = dohIPs[0]
			}

			var permanentErr error
			conn, err := netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() (net.Conn, error) {
				if permanentErr != nil {
					return nil, permanentErr
				}
				echDialTimeout := 3500 * time.Millisecond
				rawConn, err := netdial.DialContextIPMode(ctx, dialTarget, "443", mode, echDialTimeout)
				if err != nil {
					return nil, err
				}
				uConn := utls.UClient(rawConn, uCfg, utls.HelloChrome_120)
				hsCtx, hsCancel := context.WithTimeout(ctx, 4*time.Second)
				hsErr := uConn.HandshakeContext(hsCtx)
				hsCancel()
				if hsErr != nil {
					rawConn.Close()
					permanentErr = hsErr
					return nil, hsErr
				}
				// 核对服务端回传证书是否与伪装前访问的真实域名 host 一致、是否过期
				if cerr := validateUpstreamCert(ctx, host, uConn.ConnectionState().PeerCertificates); cerr != nil {
					rawConn.Close()
					permanentErr = cerr
					return nil, cerr
				}
				if uConn.ConnectionState().NegotiatedProtocol != "h2" {
					rawConn.Close()
					return nil, fmt.Errorf("upstream did not negotiate h2")
				}
				return uConn, nil
			})
			if permanentErr != nil {
				return nil, permanentErr
			}
			return conn, err
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
	return newClient(echConfig, netdial.DefaultIPMode), nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	return c.inner.Do(req)
}

func getECHClient(ipMode string) (*Client, error) {
	mode := netdial.NormalizeIPMode(ipMode)
	if mode == "" {
		mode = currentConfig().ipMode
	}
	mode = netdial.EffectiveIPMode(mode)
	clientsMu.Lock()
	if c, ok := clients[mode]; ok {
		clientsMu.Unlock()
		return c, nil
	}
	hasCfg := len(lastECHConfig) > 0
	clientsMu.Unlock()

	if !hasCfg {
		ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
		cfg, err := fetchECHConfig(ctx, shellDomain)
		cancel()
		if err != nil {
			return nil, err
		}
		clientsMu.Lock()
		lastECHConfig = cfg
		clientsMu.Unlock()
	}

	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[mode]; ok {
		return c, nil
	}
	c := newClient(lastECHConfig, mode)
	clients[mode] = c
	return c, nil
}

// Do（方式 2）通过 DoH 解析域名与 ECH 配置，使用 Cloudflare ECH 隧道发送请求，并校验回传证书。
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
	refreshOnce.Do(func() {
		logger.SafeGo("ECH-RefreshLoop", refreshLoop)
	})
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
