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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	bootstrapNegCacheTTL   = 15 * time.Second
	maxBootstrapCacheItems = 512

	badIPCooldown            = 3 * time.Minute
	maxBadIPEntries          = 1024
	happyEyeballsMaxParallel = 3
	happyEyeballsStagger     = 100 * time.Millisecond
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
	err    error
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

	// 主端点连续不可达后的冷却期：冷却期内直接走国内兜底，避免每次解析都白等
	// bootstrapPrimaryPreferWindow（3 次重试下会耗尽上层 10s 预算）。
	primaryBootstrapMu      sync.Mutex
	primaryBootstrapRetryAt time.Time

	// badIPUntil 记录近期连接超时/失败的 IP 及其冷却截止时间，
	// 晚高峰拥塞时自动将其排到末尾，避免所有请求死磕同一个高丢包节点。
	badIPMu    sync.Mutex
	badIPUntil = map[string]time.Time{}

	// defaultSiteUseBuiltinCF 是一次性开关：解析 4545810.xyz（DefaultSiteHost）时不再走 DoH，
	// 优先使用系统 DNS；一旦系统 DNS 失败，置位此标志并在本次进程生命周期内直接使用内置 Cloudflare 广播 IP。
	defaultSiteUseBuiltinCF atomic.Bool

	// builtinCloudflareAnycastIPs 为 cloudflare.com 的内置 Anycast 广播 IP（nslookup cloudflare.com）。
	builtinCloudflareAnycastIPs = []net.IP{
		net.ParseIP("104.16.132.229"),
		net.ParseIP("104.16.133.229"),
		net.ParseIP("2606:4700::6810:84e5"),
		net.ParseIP("2606:4700::6810:85e5"),
	}

	// systemLookupIPFn 默认调用系统 DNS（供单元测试替换注入）。
	systemLookupIPFn = func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			if a.IP != nil && !a.IP.IsLoopback() && !a.IP.IsUnspecified() && !IsPrivateOrReservedIP(a.IP) {
				out = append(out, a.IP)
			}
		}
		return out, nil
	}
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
		// 引导 DoH 端点全部持有带 IP SAN 的合法公网证书
		// （Cloudflare 1.1.1.1/1.0.0.1、AliDNS、DNSPod），必须校验证书链：
		// 原先 InsecureSkipVerify: true 等于允许路径上的中间人伪造解析结果（issue #41）。
		TLSClientConfig: &tls.Config{
			RootCAs:    getRootPool(),
			MinVersion: tls.VersionTLS12,
		},
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

// bootstrapPrimaryPreferWindow 是「主端点优先窗口」：主端点（1.1.1.1 / 1.0.0.1）在此窗口内
// 未返回结果时才启用国内兜底端点。窗口足够覆盖正常 Cloudflare anycast 往返，
// 又不会在 1.1.1.1 被封锁时把每次重试都拖到超时（否则 3 次重试会耗尽上层 10s 预算）。
const bootstrapPrimaryPreferWindow = 800 * time.Millisecond

// bootstrapPrimaryCooldown 是主端点判定不可达后的冷却期：冷却期内跳过主端点直接走国内兜底，
// 避免每次解析都白等一个优先窗口。冷却结束会重新尝试主端点（网络可能恢复）。
const bootstrapPrimaryCooldown = 10 * time.Minute

// primaryBootstrapUsable 报告当前是否仍需给主端点优先尝试机会（冷却期外）。
func primaryBootstrapUsable(now time.Time) bool {
	primaryBootstrapMu.Lock()
	defer primaryBootstrapMu.Unlock()
	return now.After(primaryBootstrapRetryAt)
}

// markPrimaryBootstrapUnreachable 记录主端点不可达，进入冷却期。
// 返回 entered=true 表示本次调用刚从「可用/已过冷却」切换进入新一轮冷却期，
// 调用方据此仅在状态切换时打一次告警日志，避免冷却期内每次解析反复刷屏。
func markPrimaryBootstrapUnreachable(now time.Time) (entered bool) {
	primaryBootstrapMu.Lock()
	if !now.Before(primaryBootstrapRetryAt) {
		entered = true
	}
	primaryBootstrapRetryAt = now.Add(bootstrapPrimaryCooldown)
	primaryBootstrapMu.Unlock()
	return entered
}

// domesticBootstrapAllowed 报告是否允许把国内公共 DoH 作为「最后兜底」。
//
// 默认允许：这是墙内保证可用的必要取舍——1.1.1.1 / 1.0.0.1 被完全阻断时，
// 只有国内 DoH 还能解析项目自有 DoH 域名。但它绝不与主端点并发竞速：
// 主端点只要在 bootstrapPrimaryPreferWindow 内返回就绝不使用国内端点，
// 因此 README「引导 IP 仅限 1.1.1.1 / 1.0.0.1」在正常网络下严格成立。
// 如需彻底禁用（严格隐私模式，代价是 1.1.1.1 被封锁时无法解析），
// 设置 ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP=1。
func domesticBootstrapAllowed() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP"))) {
	case "1", "true", "yes", "on":
		return false
	}
	return true
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


func builtinCloudflareIPsForMode(mode string) ([]string, error) {
	filtered := FilterIPsByMode(builtinCloudflareAnycastIPs, mode)
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no built-in Cloudflare anycast IP matches ip_mode %q", EffectiveIPMode(mode))
	}
	return filtered, nil
}

// ResolveDefaultSiteHost 解析项目自有域名（4545810.xyz）：
//  1. 不再通过 DoH（1.1.1.1/1.0.0.1 或国内 DoH）查询，彻底避免引导循环与刷屏；
//  2. 优先使用系统 DNS（net.DefaultResolver）解析并缓存；
//  3. 一旦系统 DNS 失败或无有效公网记录，置位一次性标志 defaultSiteUseBuiltinCF，
//     后续直接使用内置 Cloudflare Anycast 广播 IP（nslookup cloudflare.com）。
func ResolveDefaultSiteHost(ctx context.Context, mode string) ([]string, error) {
	norm := EffectiveIPMode(mode)
	if defaultSiteUseBuiltinCF.Load() {
		return builtinCloudflareIPsForMode(norm)
	}

	cacheKey := "sysdns|" + DefaultSiteHost + "|" + norm
	now := time.Now()
	bootstrapCacheMu.Lock()
	if e, ok := bootstrapCache[cacheKey]; ok && now.Before(e.expiry) && len(e.ips) > 0 {
		bootstrapCacheMu.Unlock()
		return e.ips, nil
	}
	bootstrapCacheMu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	rawIPs, err := systemLookupIPFn(lookupCtx, DefaultSiteHost)
	cancel()

	if err == nil {
		if filtered := FilterIPsByMode(rawIPs, norm); len(filtered) > 0 {
			bootstrapCacheMu.Lock()
			bootstrapCache[cacheKey] = bootstrapCacheEntry{
				ips:    filtered,
				expiry: time.Now().Add(bootstrapCacheTTL),
			}
			bootstrapCacheMu.Unlock()
			return filtered, nil
		}
		err = fmt.Errorf("system DNS returned no valid %s IP for %s", norm, DefaultSiteHost)
	}

	if defaultSiteUseBuiltinCF.CompareAndSwap(false, true) {
		log.Printf("[netdial] system DNS failed for %q (%v); one-time flag set, falling back to built-in Cloudflare anycast IPs", DefaultSiteHost, err)
	}
	return builtinCloudflareIPsForMode(norm)
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
	if host == DefaultSiteHost {
		return ResolveDefaultSiteHost(ctx, norm)
	}
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
		if e.err != nil {
			return nil, e.err
		}
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

// raceBootstrapEndpoints 在给定端点集合内并发竞速，返回首个有非空结果的解析结果。
// 只在该集合内竞速，不跨集合混合——用于把「主端点」与「国内兜底端点」严格分层。
func raceBootstrapEndpoints(ctx context.Context, eps []bootstrapEndpoint, host string, qt int) []net.IP {
	if len(eps) == 0 {
		return nil
	}
	resCh := make(chan []net.IP, len(eps))
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	for _, ep := range eps {
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
	for i := 0; i < len(eps); i++ {
		select {
		case r := <-resCh:
			if len(r) > 0 {
				return r
			}
		case <-ctx.Done():
			return nil
		}
	}
	return nil
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
		var won []net.IP
		enteredCooldown := false
		// 第一阶段：只竞速主端点（1.1.1.1 / 1.0.0.1），并给它们一个「优先窗口」。
		// 正常网络下主端点在窗口内返回即直接采用，国内端点全程不参与，
		// 严格符合 README「引导 IP 仅限 1.1.1.1 / 1.0.0.1」。
		// 主端点一旦被判定不可达则进入冷却期，后续解析不再重复等待优先窗口。
		if primaryBootstrapUsable(time.Now()) {
			preferCtx, preferCancel := context.WithTimeout(ctx, bootstrapPrimaryPreferWindow)
			won = raceBootstrapEndpoints(preferCtx, primaryBootstrapEndpoints, host, qt)
			preferCancel()
			if len(won) == 0 {
				enteredCooldown = markPrimaryBootstrapUnreachable(time.Now())
			}
		}
		if len(won) == 0 && domesticBootstrapAllowed() {
			// 第二阶段（最后兜底）：主端点全部失败后才串行启用国内端点。
			// 原实现把国内端点与主端点放进同一并发竞速，国内延迟更低会几乎总是胜出，
			// 导致实际用的是 223.5.5.5 等国内 DoH，违背 README 承诺（issue #41）。
			// 仅在刚触发进入冷却期时打一次日志，冷却期内静默走国内兜底，避免对 4545810.xyz 等域名高频刷屏。
			if enteredCooldown {
				log.Printf("[netdial] bootstrap DoH primary endpoints (1.1.1.1/1.0.0.1) unreachable for %q, switching to domestic fallback quietly for %s", host, bootstrapPrimaryCooldown)
			}
			won = raceBootstrapEndpoints(ctx, fallbackBootstrapEndpoints, host, qt)
		}
		if len(won) > 0 {
			ips = append(ips, won...)
		}
	}

	filtered := FilterIPsByMode(ips, norm)
	if len(filtered) == 0 {
		var resolveErr error
		if domesticBootstrapAllowed() {
			resolveErr = fmt.Errorf("DoH resolve %s (%s) failed (primary and domestic bootstrap endpoints both unreachable)", host, norm)
		} else {
			resolveErr = fmt.Errorf("DoH resolve %s (%s) failed (primary bootstrap endpoints unreachable; domestic fallback disabled by ECH_PROXY_DISABLE_DOMESTIC_BOOTSTRAP)", host, norm)
		}
		// 写入短时负缓存（15s），防止高并发请求在网络异常或某协议族无记录时反复打爆引导 DoH 与日志。
		bootstrapCacheMu.Lock()
		bootstrapCache[cacheKey] = bootstrapCacheEntry{
			err:    resolveErr,
			expiry: time.Now().Add(bootstrapNegCacheTTL),
		}
		bootstrapCacheMu.Unlock()
		return nil, resolveErr
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
	if host == DefaultSiteHost {
		return ResolveDefaultSiteHost(ctx, norm)
	}
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

// MarkBadIP 将近期超时或建连失败的 IP 标记进入短暂冷却期（3 分钟），后续拨号优先避开。
func MarkBadIP(ip string) {
	ip = CleanHost(ip)
	if ip == "" {
		return
	}
	now := time.Now()
	badIPMu.Lock()
	if len(badIPUntil) >= maxBadIPEntries {
		for k, exp := range badIPUntil {
			if !now.Before(exp) {
				delete(badIPUntil, k)
			}
		}
	}
	badIPUntil[ip] = now.Add(badIPCooldown)
	badIPMu.Unlock()
}

// ClearBadIP 在某 IP 成功恢复建连后立即移出冷却表。
func ClearBadIP(ip string) {
	ip = CleanHost(ip)
	if ip == "" {
		return
	}
	badIPMu.Lock()
	delete(badIPUntil, ip)
	badIPMu.Unlock()
}

// IsBadIP 报告该 IP 当前是否处于故障冷却期内。
func IsBadIP(ip string) bool {
	ip = CleanHost(ip)
	if ip == "" {
		return false
	}
	now := time.Now()
	badIPMu.Lock()
	exp, ok := badIPUntil[ip]
	if ok && !now.Before(exp) {
		delete(badIPUntil, ip)
		ok = false
	}
	badIPMu.Unlock()
	return ok
}

// OrderIPsHealthyFirst 将未处于故障冷却期的 IP 排在前面、冷却中的 IP 排到末尾（保序），
// 既避免死磕故障节点，又保留全部 IP 作为最终兜底。
func OrderIPsHealthyFirst(ips []string) []string {
	if len(ips) <= 1 {
		return append([]string(nil), ips...)
	}
	now := time.Now()
	badIPMu.Lock()
	healthy := make([]string, 0, len(ips))
	degraded := make([]string, 0)
	for _, ip := range ips {
		if exp, ok := badIPUntil[CleanHost(ip)]; ok && now.Before(exp) {
			degraded = append(degraded, ip)
		} else {
			healthy = append(healthy, ip)
		}
	}
	badIPMu.Unlock()
	return append(healthy, degraded...)
}

func dialSingleIP(ctx context.Context, ip, port string, timeout time.Duration) (net.Conn, error) {
	network := "tcp"
	if parsed := net.ParseIP(ip); parsed != nil {
		if parsed.To4() != nil {
			network = "tcp4"
		} else {
			network = "tcp6"
		}
	}
	return (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip, port))
}

// DialContextHappyEyeballs 对候选 IP 执行多路并发竞速拨号（最多并发 3 路，间隔 100ms 阶梯发起）：
//   - 健康 IP 优先（OrderIPsHealthyFirst）；
//   - 首个完成 TCP 握手的连接立即胜出返回，其余迟到连接自动关闭避免泄漏；
//   - 超时或建连失败的 IP 自动记入 3 分钟故障冷却表，避免晚高峰死磕拥塞节点。
func DialContextHappyEyeballs(ctx context.Context, ips []string, port string, timeout time.Duration) (net.Conn, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no candidate IPs to dial port %s", port)
	}
	if timeout <= 0 {
		timeout = DialTimeout
	}
	ordered := OrderIPsHealthyFirst(ips)
	if len(ordered) == 1 {
		conn, err := dialSingleIP(ctx, ordered[0], port, timeout)
		if err != nil {
			if ctx.Err() == nil {
				MarkBadIP(ordered[0])
			}
			return nil, err
		}
		ClearBadIP(ordered[0])
		return conn, nil
	}

	raceCount := len(ordered)
	if raceCount > happyEyeballsMaxParallel {
		raceCount = happyEyeballsMaxParallel
	}

	type dialResult struct {
		conn net.Conn
		ip   string
		err  error
	}
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	resCh := make(chan dialResult, raceCount)
	for i := 0; i < raceCount; i++ {
		targetIP := ordered[i]
		delay := time.Duration(i) * happyEyeballsStagger
		go func() {
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-raceCtx.Done():
					timer.Stop()
					resCh <- dialResult{ip: targetIP, err: raceCtx.Err()}
					return
				}
			}
			conn, err := dialSingleIP(raceCtx, targetIP, port, timeout)
			if err != nil {
				if raceCtx.Err() == nil {
					MarkBadIP(targetIP)
				}
				resCh <- dialResult{ip: targetIP, err: err}
				return
			}
			resCh <- dialResult{conn: conn, ip: targetIP}
		}()
	}

	var lastErr error
	var winner net.Conn
	for i := 0; i < raceCount; i++ {
		r := <-resCh
		if r.err == nil && r.conn != nil {
			if winner == nil {
				winner = r.conn
				ClearBadIP(r.ip)
				raceCancel()
			} else {
				_ = r.conn.Close()
			}
		} else if r.err != nil {
			lastErr = r.err
		}
	}
	if winner != nil {
		return winner, nil
	}

	// 若前 raceCount 个并发候选全败，继续顺延尝试剩余候选 IP。
	for i := raceCount; i < len(ordered); i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		conn, err := dialSingleIP(ctx, ordered[i], port, timeout)
		if err == nil {
			ClearBadIP(ordered[i])
			return conn, nil
		}
		if ctx.Err() == nil {
			MarkBadIP(ordered[i])
		}
		lastErr = err
	}
	return nil, lastErr
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
	return DialContextHappyEyeballs(ctx, ips, port, timeout)
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

// isGitHubResourceURL 按**主机名**判定 URL 是否指向 GitHub。
//
// 不能用整串 substring 判定：DefaultUpstreamConfigURL 的查询串里带有
// proxy_host=raw.githubusercontent.com，按 substring 判定会把非 GitHub 资源
// 也送进镜像竞速——给镜像前缀一个非 GitHub URL 只会得到 404/超时。实证
// （v3.5.25 CI 产物 function 测试）：同一 config URL，amd64 check 2.3s 成功、
// -check-config 18.8s 失败、386 check 15.8s 失败、hosts-print 时好时坏
// （48 条目 vs 缓存 15 条目），全部由这一次误判引发。
func isGitHubResourceURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "github.com" || strings.HasSuffix(host, ".github.com") ||
		host == "githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
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

	// 针对 GitHub 资源（按主机名判定，见 isGitHubResourceURL——整串 substring 会把
	// 查询串里带 github 主机名的非 GitHub 资源误送进竞速），国内直连经常被 GFW
	// 阻断或 DNS 污染，并发竞速国内加速镜像源与直连（FragmentDo 绕过 GFW）
	if isGitHubResourceURL(rawURL) {
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
