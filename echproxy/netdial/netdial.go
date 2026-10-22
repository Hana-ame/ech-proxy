// Package netdial 提供基础网络拨号、公共 DNS 解析、IPv4/IPv6 协议族绑定、主机端口与域名归一化、
// Cloudflare IP 识别、内网/保留地址识别（SSRF 防护）、远程/本地文件拉取与通用重试工具。
// 本模块处于架构最底层，不依赖项目内任何其他包，供上层所有模块高内聚复用。
package netdial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

	// DefaultSiteHost 是项目自有服务域名（DoH / ads.js / pac.txt / block.json 共用）的
	// **唯一 true source**。其它包必须引用它派生，不得再各自硬编码该域名。
	DefaultSiteHost = "4545810.xyz"

	bootstrapCacheTTL      = 5 * time.Minute
	maxBootstrapCacheItems = 512
)

type insideDoHKey struct{}

// WithInsideDoH 在 Context 中标记当前调用链正处于 DoH 请求内部。
// 当拨号处于 DoH 查询内部时，ResolveIPs 严禁再次回调 DoHResolver，彻底阻断 DoH 域名自解析的无限递归与协程爆炸。
func WithInsideDoH(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, insideDoHKey{}, true)
}

// IsInsideDoH 报告当前 Context 是否正处于 DoH 查询内部。
func IsInsideDoH(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(insideDoHKey{}).(bool)
	return v
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

type bootstrapCacheEntry struct {
	ips    []string
	expiry time.Time
}

type bootstrapFlightCall struct {
	done chan struct{}
	ips  []string
	err  error
}

var (
	DoHResolver func(ctx context.Context, host, mode string) ([]string, error)

	// GitHubRoundTripper 提供免翻墙绕过 GFW DPI 访问 GitHub 的 RoundTripper（由上层 echproxy 模块注入 FragmentDo）
	GitHubRoundTripper func(req *http.Request) (*http.Response, error)

	rootPoolOnce sync.Once
	rootPool     *x509.CertPool

	ipTransportMu sync.Mutex
	ipTransports  = map[string]*http.Transport{}

	bootstrapClientMu sync.Mutex
	bootstrapClients  = map[string]*http.Client{}

	bootstrapCacheMu  sync.Mutex
	bootstrapCache    = map[string]bootstrapCacheEntry{}
	bootstrapFlightMu sync.Mutex
	bootstrapFlights  = map[string]*bootstrapFlightCall{}
)

// TransportPoolStats 返回 netdial 内部缓存的各模式 Transport 数量与标识。
func TransportPoolStats() (count int, modes []string) {
	ipTransportMu.Lock()
	defer ipTransportMu.Unlock()
	count = len(ipTransports)
	for k := range ipTransports {
		modes = append(modes, k)
	}
	return
}

func getBootstrapClient(bIP string) *http.Client {
	bootstrapClientMu.Lock()
	defer bootstrapClientMu.Unlock()
	if c, ok := bootstrapClients[bIP]; ok {
		return c
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			if port == "" {
				port = "443"
			}
			return (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(bIP, port))
		},
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3500 * time.Millisecond,
		ForceAttemptHTTP2:     true,
	}
	c := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	bootstrapClients[bIP] = c
	return c
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

type dohJSONAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohJSONResponse struct {
	Status int             `json:"Status"`
	Answer []dohJSONAnswer `json:"Answer"`
}

type bootstrapEndpoint struct {
	ip         string
	urlPattern string
}

var primaryBootstrapEndpoints = []bootstrapEndpoint{
	{ip: "1.1.1.1", urlPattern: "https://%s/dns-query?name=%s&type=%d"},
	{ip: "1.0.0.1", urlPattern: "https://%s/dns-query?name=%s&type=%d"},
}

var fallbackBootstrapEndpoints = []bootstrapEndpoint{
	{ip: "223.5.5.5", urlPattern: "https://%s/resolve?name=%s&type=%d"},
	{ip: "223.6.6.6", urlPattern: "https://%s/resolve?name=%s&type=%d"},
	{ip: "1.12.12.12", urlPattern: "https://%s/dns-query?name=%s&type=%d"},
}

func queryBootstrapEndpoint(ctx context.Context, ep bootstrapEndpoint, host string, qt int) ([]net.IP, error) {
	reqURL := fmt.Sprintf(ep.urlPattern, ep.ip, url.QueryEscape(host), qt)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	client := getBootstrapClient(ep.ip)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var d dohJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, ans := range d.Answer {
		if ans.Type == qt {
			if parsed := net.ParseIP(ans.Data); parsed != nil && !parsed.IsLoopback() && !parsed.IsUnspecified() {
				ips = append(ips, parsed)
			}
		}
	}
	return ips, nil
}

// ResolveViaBootstrapDoH 仅通过 HTTPS（端口 443）向 IP 直连 DoH 端点查询，绝不发起任何 UDP/TCP 53 端口连接，
// 且絕不回调上层 DoHResolver，内置内存缓存与 Singleflight 并发合并。
func ResolveViaBootstrapDoH(ctx context.Context, host, mode string) ([]string, error) {
	return resolveViaBootstrapDoH(ctx, host, mode)
}

// resolveViaBootstrapDoH 仅通过 HTTPS（端口 443）向 IP 直连 DoH 端点查询，绝不发起任何 UDP/TCP 53 端口连接。
func resolveViaBootstrapDoH(ctx context.Context, host, mode string) ([]string, error) {
	host = CleanHost(host)
	norm := EffectiveIPMode(mode)
	if ip := net.ParseIP(host); ip != nil {
		filtered := FilterIPsByMode([]net.IP{ip}, norm)
		if len(filtered) == 0 {
			return nil, fmt.Errorf("IP %s does not match ip_mode %q", host, norm)
		}
		return filtered, nil
	}

	cacheKey := host + "|" + norm
	now := time.Now()
	bootstrapCacheMu.Lock()
	if e, ok := bootstrapCache[cacheKey]; ok && now.Before(e.expiry) {
		bootstrapCacheMu.Unlock()
		return e.ips, nil
	}
	bootstrapCacheMu.Unlock()

	bootstrapFlightMu.Lock()
	call, inFlight := bootstrapFlights[cacheKey]
	if !inFlight {
		call = &bootstrapFlightCall{done: make(chan struct{})}
		bootstrapFlights[cacheKey] = call
		go func() {
			defer func() {
				bootstrapFlightMu.Lock()
				delete(bootstrapFlights, cacheKey)
				close(call.done)
				bootstrapFlightMu.Unlock()
			}()

			resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer resolveCancel()

			call.ips, call.err = doResolveViaBootstrapDoH(resolveCtx, host, norm, cacheKey)
		}()
	}
	bootstrapFlightMu.Unlock()

	select {
	case <-call.done:
		return call.ips, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func doResolveViaBootstrapDoH(ctx context.Context, host, norm, cacheKey string) ([]string, error) {
	qtypes := []int{1}
	if norm == "v6" {
		qtypes = []int{28}
	} else if norm == "dual" {
		qtypes = []int{1, 28}
	}

	var ips []net.IP

	for _, qt := range qtypes {
		allEPs := append(append([]bootstrapEndpoint(nil), primaryBootstrapEndpoints...), fallbackBootstrapEndpoints...)
		resCh := make(chan []net.IP, len(allEPs))
		raceCtx, raceCancel := context.WithCancel(ctx)
		for _, ep := range allEPs {
			targetEP := ep
			go func() {
				res, err := queryBootstrapEndpoint(raceCtx, targetEP, host, qt)
				if err == nil && len(res) > 0 {
					resCh <- res
				} else {
					resCh <- nil
				}
			}()
		}
		var won []net.IP
		for i := 0; i < len(allEPs); i++ {
			select {
			case r := <-resCh:
				if len(r) > 0 && len(won) == 0 {
					won = r
					raceCancel()
				}
			case <-ctx.Done():
				raceCancel()
				break
			}
			if len(won) > 0 {
				break
			}
		}
		raceCancel()
		if len(won) > 0 {
			ips = append(ips, won...)
		}
	}

	filtered := FilterIPsByMode(ips, norm)
	if len(filtered) == 0 {
		return nil, fmt.Errorf("DoH resolve %s (%s) failed", host, norm)
	}

	bootstrapCacheMu.Lock()
	if len(bootstrapCache) >= maxBootstrapCacheItems {
		pruneTime := time.Now()
		for k, v := range bootstrapCache {
			if pruneTime.After(v.expiry) {
				delete(bootstrapCache, k)
			}
		}
		if len(bootstrapCache) >= maxBootstrapCacheItems {
			for k := range bootstrapCache {
				delete(bootstrapCache, k)
				break
			}
		}
	}
	bootstrapCache[cacheKey] = bootstrapCacheEntry{
		ips:    filtered,
		expiry: time.Now().Add(bootstrapCacheTTL),
	}
	bootstrapCacheMu.Unlock()

	return filtered, nil
}

// ResolveIPs 严格全链路采用 DoH 协议解析域名（优先调用 DoHResolver，兜底使用 1.1.1.1:443 HTTPS 直连），绝不触碰本地 53 端口。
// 当 ctx 处于 DoH 请求内部（IsInsideDoH(ctx) == true）时，跳过 DoHResolver 直接走 Bootstrap DoH，杜绝自解析死循环。
func ResolveIPs(ctx context.Context, host, mode string) ([]string, error) {
	host = CleanHost(host)
	norm := EffectiveIPMode(mode)
	if ip := net.ParseIP(host); ip != nil {
		filtered := FilterIPsByMode([]net.IP{ip}, norm)
		if len(filtered) == 0 {
			return nil, fmt.Errorf("IP %s does not match ip_mode %q", host, norm)
		}
		return filtered, nil
	}
	if DoHResolver != nil && !IsInsideDoH(ctx) {
		if ips, err := DoHResolver(WithInsideDoH(ctx), host, norm); err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return resolveViaBootstrapDoH(ctx, host, norm)
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
	resolveCtx, cancel := context.WithTimeout(ctx, DoHTimeout)
	ips, err := ResolveIPs(resolveCtx, host, norm)
	cancel()
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		network := "tcp"
		parsed := net.ParseIP(ip)
		if parsed != nil {
			if parsed.To4() != nil {
				network = "tcp4"
			} else {
				network = "tcp6"
			}
		}
		conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func Transport() *http.Transport {
	return TransportWithIPMode(DefaultIPMode)
}

func TransportWithIPMode(mode string) *http.Transport {
	norm := EffectiveIPMode(mode)
	ipTransportMu.Lock()
	defer ipTransportMu.Unlock()
	if tr, ok := ipTransports[norm]; ok {
		return tr
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return DialContextIPMode(ctx, host, port, norm, DialTimeout)
		},
		TLSClientConfig:       &tls.Config{RootCAs: getRootPool()},
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	ipTransports[norm] = tr
	return tr
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
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		MaxConnsPerHost:     64,
		IdleConnTimeout:     15 * time.Second,
		ForceAttemptHTTP2:   true,
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

type gitHubProxyTransport struct {
	base http.RoundTripper
}

func (g *gitHubProxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil {
		if GitHubRoundTripper != nil {
			resp, err := GitHubRoundTripper(req)
			if err == nil && resp != nil {
				return resp, nil
			}
		}
	}
	if g.base != nil {
		return g.base.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// gitHubFetchCandidates 返回 GitHub 资源的竞速候选列表，顺序即优先级。
//
// 国内加速镜像一律排在直连之前：实证（2026-10-22，Windows/国内网络，
// 见 RELEASE.md v3.5.24 与 updtest 诊断 exe）直连 github.com:443 在 TCP 层
// 即被阻断（i/o timeout），而镜像可达。直连保留在末位——海外用户没有
// 镜像时它仍是唯一通路，且排在最后不会给国内用户增加任何等待。
//
// ghproxy.imciel.com 置首位：实证（2026-10-22，v3.5.24 端到端实测）它是国内
// 唯一能真正完成下载的镜像——amd64 资产 41s 成功、386 冷资产 112s 超时失败，
// 两次都只有它进入实质传输。二进制竞速并发度只有 3，排第 4 的候选要先等槽位：
// 386 实测白白等待 22s 后自身 90s candTimeout 即耗尽。置首位后它 t=0 占槽，
// 拿满单候选超时预算；竞速语义不变——其他网络上最快的成功候选仍然先返回。
//
// 该顺序是硬性契约：二进制下载的并发度只有 3，一旦某个"挂死但排前面"的
// 候选占住槽位，唯一可用镜像就会被饿死（总超时先到）。TestGitHubFetchCandidatesOrder
// 锁定此顺序，回归即红。
func gitHubFetchCandidates(rawURL string) []string {
	return []string{
		"https://ghproxy.imciel.com/" + rawURL,
		"https://gh-proxy.com/" + rawURL,
		"https://ghfast.top/" + rawURL,
		"https://gh.llkk.cc/" + rawURL,
		rawURL,
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
	client := &http.Client{
		Timeout:   OpTimeout,
		Transport: TransportWithIPMode(DefaultIPMode),
	}

	// 针对 GitHub 资源，国内直连经常被 GFW 阻断或 DNS 污染，并发竞速国内加速镜像源与直连（FragmentDo 绕过 GFW）
	if strings.Contains(rawURL, "github.com") || strings.Contains(rawURL, "githubusercontent.com") {
		type fetchResult struct {
			target string
			data   []byte
			err    error
		}
		candidates := gitHubFetchCandidates(rawURL)

		isBinary := strings.HasSuffix(rawURL, ".exe") || strings.HasSuffix(rawURL, ".zip") ||
			strings.HasSuffix(rawURL, ".tar.gz") || strings.HasSuffix(rawURL, ".bin")
		candTimeout := 25 * time.Second
		overallTimeout := 45 * time.Second
		var maxReadBytes int64 = 8 << 20
		maxConcurrent := len(candidates)
		if isBinary {
			// 冷资产镜像拉取实测 >90s：v3.5.24 386 资产在 imciel 上 112s 才超时
			// （其中 22s 浪费在等槽位，见 RELEASE.md v3.5.25）。单候选预算
			// 90s->150s、总预算 180s->300s，给镜像的回源拉取留足时间。
			candTimeout = 150 * time.Second
			overallTimeout = 300 * time.Second
			maxReadBytes = 64 << 20
			// 二进制大文件限制并发下载数，避免多个镜像同时在内存缓冲数十 MB 的可执行文件。
			// 必须 >= 3：实证（2026-10-22，Windows/国内网络）4 个镜像中只有 ghproxy.imciel.com
			// 能真正完成下载，若只放行 2 路，排在前面的挂死候选各占槽，唯一可用镜像
			// 永远抢不到槽，总超时先到——更新下载 100% 失败（见 RELEASE.md v3.5.24）。
			maxConcurrent = 3
		}

		sem := make(chan struct{}, maxConcurrent)
		ch := make(chan fetchResult, len(candidates))
		raceCtx, raceCancel := context.WithTimeout(context.Background(), overallTimeout)
		defer raceCancel()

		ghClient := &http.Client{
			Transport: &gitHubProxyTransport{
				base: TransportWithIPMode(DefaultIPMode),
			},
		}

		for _, cand := range candidates {
			go func(target string) {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-raceCtx.Done():
					ch <- fetchResult{target: target, err: raceCtx.Err()}
					return
				}

				cCtx, cCancel := context.WithTimeout(raceCtx, candTimeout)
				defer cCancel()

				req, err := http.NewRequestWithContext(cCtx, http.MethodGet, target, nil)
				if err != nil {
					ch <- fetchResult{target: target, err: err}
					return
				}
				req.Header.Set("User-Agent", "ech-proxy-updater")
				resp, err := ghClient.Do(req)
				if err != nil {
					ch <- fetchResult{target: target, err: err}
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					ch <- fetchResult{target: target, err: fmt.Errorf("unexpected status: %s", resp.Status)}
					return
				}
				b, err := io.ReadAll(io.LimitReader(resp.Body, maxReadBytes))
				if err == nil && len(b) > 0 {
					ch <- fetchResult{target: target, data: b, err: nil}
				} else {
					if err == nil {
						err = fmt.Errorf("empty body from %s", target)
					}
					ch <- fetchResult{target: target, err: err}
				}
			}(cand)
		}

		var lastErr error
		for i := 0; i < len(candidates); i++ {
			select {
			case res := <-ch:
				if res.err == nil && len(res.data) > 0 {
					raceCancel()
					return res.data, nil
				}
				lastErr = res.err
			case <-raceCtx.Done():
				if lastErr == nil {
					lastErr = raceCtx.Err()
				}
				return nil, fmt.Errorf("fetch %s timed out after %v: %w", rawURL, overallTimeout, lastErr)
			}
		}
		return nil, lastErr
	}

	return fetchWithClient(client, rawURL)
}

func fetchWithClient(client *http.Client, targetURL string) ([]byte, error) {
	resp, err := Retry(context.Background(), RetryAttempts, RetryBackoff, func() (*http.Response, error) {
		r, e := client.Get(targetURL)
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
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
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
