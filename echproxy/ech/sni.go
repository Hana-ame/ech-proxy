package cloudflare_ech

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

const (
	routeCacheTTL      = 30 * time.Minute
	maxSNICacheEntries = 256
)

type sniServerNameKey struct{}

// WithSNIServerName 在请求 Context 中注入自定义 SNI 伪装域名（若传 "none" 则发送空 SNI，留空则默认使用 cloudflare-ech.com）。
func WithSNIServerName(ctx context.Context, serverName string) context.Context {
	if strings.TrimSpace(serverName) == "" {
		return ctx
	}
	return context.WithValue(ctx, sniServerNameKey{}, strings.TrimSpace(serverName))
}

// SNIServerNameFromContext 读取请求 Context 中配置的 SNI 伪装域名。
func SNIServerNameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(sniServerNameKey{}).(string); ok && v != "" {
		if strings.EqualFold(v, "none") {
			return ""
		}
		return v
	}
	return shellDomain
}

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

// DetectTransportMode 全自动无干预判断目标主机应优先使用 "ech" 还是 "sni"：
//  1. 优先读取已验证成功的路由缓存；
//  2. 通过 DoH（或公共 DNS 回退）解析目标主机 IP，检查是否属于 Cloudflare 网段（netdial.IsCloudflareIP）：
//     - 属于 Cloudflare 网段 -> 返回 "ech"（走方式 2：Cloudflare ECH 加密 ClientHello）
//     - 不属于 Cloudflare 网段 -> 返回 "sni"（走方式 1：DoH 解析 + 伪造 SNI 直连）
func DetectTransportMode(ctx context.Context, host string) string {
	mode, _ := DetectTransportModeWithStatus(ctx, host, "")
	return mode
}

// DetectTransportModeWithStatus 返回探测到的模式以及该结论是否来自成功的 DNS 解析（修复 Issue #6 瞬时故障负缓存）。
func DetectTransportModeWithStatus(ctx context.Context, host, ipMode string) (mode string, confident bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if cached, ok := getCachedRoute(host); ok {
		return cached, true
	}
	ips, err := ResolveHostIPsByMode(ctx, host, ipMode)
	if err == nil && len(ips) > 0 {
		for _, ipStr := range ips {
			if netdial.IsCloudflareIP(net.ParseIP(ipStr)) {
				return "ech", true
			}
		}
		return "sni", true
	}
	// DNS 解析瞬时失败时回退尝试 ech，但标记 confident=false 避免将未验证猜测负缓存
	return "ech", false
}

// RoundTrip 统一调度三种上游请求方案，并在所有 HTTPS 路径上严格校验服务端回传证书（与 truedomain.com 比对域名一致性与过期时间）：
//   - 当 req.URL.Scheme == "http" 时：通过 DoH 解析真实 IP 并执行明文 HTTP 请求（PlainHTTPDo），支持纯 HTTP 站点与自定义 HTTP 端口；
//   - 方式 1 ("sni")：通过 DoH 解析域名 -> SNI 伪装绕过请求 -> 核对回传证书与伪装前真实域名一致且未过期；
//   - 方式 2 ("ech")：通过 DoH 解析域名 -> 使用 ECH 请求 -> 核对回传证书与真实域名一致且未过期；
//   - 方式 3 ("fragment" / 其他)：通过 DoH 解析域名 -> 使用 TLS ClientHello 分片方案绕过 GFW DPI -> 核对回传证书；
//   - "direct"：仅用于门户自身或显式指定直连的站点（同样核对回传证书）。
func RoundTrip(req *http.Request, mode, ipMode string) (*http.Response, error) {
	normIPMode := netdial.NormalizeIPMode(ipMode)
	if normIPMode == "" {
		normIPMode = currentConfig().ipMode
	}
	normIPMode = netdial.EffectiveIPMode(normIPMode)

	// 若请求显式为明文 http:// 协议，使用基于 DoH 解析的明文 HTTP 传输
	if req != nil && req.URL != nil && strings.EqualFold(req.URL.Scheme, "http") {
		return PlainHTTPDo(req, normIPMode)
	}

	trimmedMode := strings.ToLower(strings.TrimSpace(mode))
	if trimmedMode == "direct" {
		return directDo(req, normIPMode)
	}
	if trimmedMode == "fragment" || trimmedMode == "bypass" || trimmedMode == "gfw" {
		return FragmentDo(req, normIPMode)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	primary := trimmedMode
	confident := true
	if primary == "" || primary == "auto" {
		primary, confident = DetectTransportModeWithStatus(req.Context(), host, normIPMode)
	} else if cached, ok := getCachedRoute(host); ok {
		primary = cached
	}

	// 第 1 步：执行首选方式（方式 1 SNI 伪装 或 方式 2 ECH）
	resp, err := doSingleMode(req, primary, normIPMode)
	if err == nil && !isCloudflareRouteRejection(resp, primary) {
		if confident || resp.StatusCode < 500 {
			setCachedRoute(host, primary)
		}
		return resp, nil
	}
	if resp != nil {
		resp.Body.Close()
	}
	// 上游证书校验失败（过期/不一致/不可信）：立即上抛走警告页，绝不切换备选模式掩盖
	if IsCertError(err) {
		return nil, err
	}
	clearCachedRoute(host)

	// 第 2 步：首选模式连接失败时，自动切换另一核心模式（SNI <-> ECH）
	secondary := "sni"
	if primary == "sni" {
		secondary = "ech"
	}
	resp2, err2 := doSingleMode(req, secondary, normIPMode)
	if err2 == nil && !isCloudflareRouteRejection(resp2, secondary) {
		setCachedRoute(host, secondary)
		return resp2, nil
	}
	if resp2 != nil {
		resp2.Body.Close()
	}
	if IsCertError(err2) {
		return nil, err2
	}

	// 第 3 步（方式 3）：当 ECH 与假 SNI 均无法连通（例如源站非 Cloudflare 且拒绝假 SNI）时，
	// 使用 DoH 解析真实 IP + TLS ClientHello 记录分片（FragmentDo）绕过 GFW DPI！
	respFrag, errFrag := FragmentDo(req, normIPMode)
	if errFrag == nil {
		setCachedRoute(host, "fragment")
		return respFrag, nil
	}
	if respFrag != nil {
		respFrag.Body.Close()
	}
	if IsCertError(errFrag) {
		return nil, errFrag
	}

	// 第 4 步：最后兜底尝试标准直连（同样带证书校验，失败上抛 CertError 走警告页）
	resp3, err3 := directDo(req, normIPMode)
	if err3 == nil {
		return resp3, nil
	}
	if IsCertError(err3) {
		return nil, err3
	}
	return nil, err
}

// PlainHTTPDo 通过 DoH 解析目标域名真实 IP（防 DNS 污染），并发起明文 HTTP 请求（支持仅提供 HTTP 80 或自定义端口的目标站点）。
func PlainHTTPDo(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	normMode := netdial.NormalizeIPMode(mode)
	if normMode == "" {
		normMode = currentConfig().ipMode
	}
	normMode = netdial.EffectiveIPMode(normMode)

	hostPort := req.URL.Host
	if hostPort == "" {
		hostPort = req.Host
	}
	host := hostPort
	port := "80"
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		host = h
		if p != "" {
			port = p
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))

	dialTarget := host
	if ips, err := ResolveHostIPsByMode(req.Context(), host, normMode); err == nil && len(ips) > 0 {
		dialTarget = ips[0]
	}

	tr := netdial.TransportWithIPMode(normMode).Clone()
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return netdial.DialContextIPMode(ctx, dialTarget, port, normMode, dialTimeout)
	}
	c := &http.Client{
		Transport: tr,
		Timeout:   netdial.OpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c.Do(req)
}

// directDo 经标准 TLS 直连上游（Direct 模式），并在握手后手动校验上游证书
// （时间 + 主机名 + 信任链），使证书失败统一走 CertError 警告页，且 WithAllowBadCert（强行访问）可跳过。
func directDo(req *http.Request, ipMode string) (*http.Response, error) {
	tr := netdial.TransportWithIPModeAndCertCheck(ipMode, func(host string, peerCerts []*x509.Certificate) error {
		return validateUpstreamCert(req.Context(), host, peerCerts)
	})
	c := &http.Client{
		Transport: tr,
		Timeout:   netdial.OpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c.Do(req)
}

func doSingleMode(req *http.Request, mode, ipMode string) (*http.Response, error) {
	switch mode {
	case "sni":
		return SNIFrontDo(req, ipMode)
	case "fragment", "bypass", "gfw":
		return FragmentDo(req, ipMode)
	case "direct":
		return directDo(req, ipMode)
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

// ResolveHostIPs 通过 DoH（及公共 DNS 兜底）查询目标域名的 IP 记录并按 TTL 缓存。
func ResolveHostIPs(ctx context.Context, host string) ([]string, error) {
	return ResolveHostIPsByMode(ctx, host, "")
}

// ResolveHostIPsByMode 按指定的 ipMode（默认 "v4"、"v6" 或 "dual"）通过 DoH 查询 A/AAAA 记录并缓存（修复 S3 与 Issue #9）。
func ResolveHostIPsByMode(ctx context.Context, host, ipMode string) ([]string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	normMode := netdial.NormalizeIPMode(ipMode)
	if normMode == "" {
		normMode = currentConfig().ipMode
	}
	normMode = netdial.EffectiveIPMode(normMode)

	if parsed := net.ParseIP(host); parsed != nil {
		filtered := netdial.FilterIPsByMode([]net.IP{parsed}, normMode)
		if len(filtered) == 0 {
			return nil, fmt.Errorf("IP %s does not match ip_mode %q", host, normMode)
		}
		return filtered, nil
	}

	cacheKey := host + "|" + normMode
	ipCacheMu.Lock()
	if e, ok := ipCache[cacheKey]; ok && time.Now().Before(e.expiry) {
		ipCacheMu.Unlock()
		return e.ips, nil
	}
	ipCacheMu.Unlock()

	var qtypes []int
	switch normMode {
	case "v4":
		qtypes = []int{1} // A (IPv4 only, default)
	case "v6":
		qtypes = []int{28} // AAAA (IPv6 only)
	default:
		qtypes = []int{1, 28} // dual: A 优先，AAAA 补充
	}

	var ips []string
	seen := make(map[string]bool)
	ttl := 300

	for _, qt := range qtypes {
		resp, err := netdial.Retry(ctx, netdial.RetryAttempts, netdial.RetryBackoff, func() (*http.Response, error) {
			r, e := QueryDoH(ctx, host, qt)
			if e != nil && r != nil {
				r.Body.Close()
			}
			return r, e
		})
		if err == nil && resp != nil {
			if resp.StatusCode == http.StatusOK {
				var d dohResponse
				if json.NewDecoder(resp.Body).Decode(&d) == nil {
					for _, ans := range d.Answer {
						if ans.Type == qt {
							if parsed := net.ParseIP(ans.Data); parsed != nil {
								matched := netdial.FilterIPsByMode([]net.IP{parsed}, normMode)
								for _, m := range matched {
									if !seen[m] {
										seen[m] = true
										ips = append(ips, m)
										if ans.TTL > 0 && ans.TTL < ttl {
											ttl = ans.TTL
										}
									}
								}
							}
						}
					}
				}
			}
			resp.Body.Close()
		}
		// 若 dual 模式下已拿到 IPv4 A 记录，无需再额外阻塞等待 AAAA
		if normMode == "dual" && len(ips) > 0 {
			break
		}
	}

	// 若 DoH 未返回结果，回退使用 netdial 公共 DNS 解析器（同样遵守 normMode）
	if len(ips) == 0 {
		if fallbackIPs, rerr := netdial.ResolveIPs(ctx, host, normMode); rerr == nil && len(fallbackIPs) > 0 {
			ips = fallbackIPs
		} else {
			if normMode != "dual" {
				return nil, fmt.Errorf("no %s record for %s", normMode, host)
			}
			return nil, fmt.Errorf("no A/AAAA record for %s", host)
		}
	}

	if ttl < minTTL {
		ttl = minTTL
	} else if ttl > maxTTL {
		ttl = maxTTL
	}
	ipCacheMu.Lock()
	ipCache[cacheKey] = ipCacheEntry{ips: ips, expiry: time.Now().Add(time.Duration(ttl) * time.Second)}
	ipCacheMu.Unlock()
	return ips, nil
}

func dialUTLS(ctx context.Context, ip, sniName, host string, nextProtos []string) (*utls.UConn, error) {
	rawConn, err := (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sniName, // 伪装 SNI（假域名），保持不变
		InsecureSkipVerify: true,    // 不由 utls 做假 SNI 主机名校验，改由下方手动核对真实域名 host
		NextProtos:         nextProtos,
	}, utls.HelloChrome_120)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	// 方式 1 核心校验：SNI 伪装请求握手后，立即核对服务端回传的证书是否正确，
	// 证书包含的 domain 必须与伪装之前访问的真实域名 host (truedomain.com) 符合条件，且未过期！
	if cerr := validateUpstreamCert(ctx, host, uConn.ConnectionState().PeerCertificates); cerr != nil {
		rawConn.Close()
		return nil, cerr
	}
	return uConn, nil
}

func getSNIH2Transport(ip, sniName, host string) *http2.Transport {
	key := ip + "|" + sniName + "|" + host
	sniTransMu.Lock()
	defer sniTransMu.Unlock()
	if t, ok := sniH2Trans[key]; ok {
		return t
	}
	t := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			uConn, err := dialUTLS(ctx, ip, sniName, host, []string{"h2", "http/1.1"})
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
	if len(sniH2Trans) >= maxSNICacheEntries {
		for k, old := range sniH2Trans {
			old.CloseIdleConnections()
			delete(sniH2Trans, k)
			break
		}
	}
	sniH2Trans[key] = t
	return t
}

func getSNIH1Client(ip, sniName, host string) *http.Client {
	key := ip + "|" + sniName + "|" + host
	sniTransMu.Lock()
	defer sniTransMu.Unlock()
	if c, ok := sniH1Clients[key]; ok {
		return c
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialUTLS(ctx, ip, sniName, host, []string{"http/1.1"})
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
	if len(sniH1Clients) >= maxSNICacheEntries {
		for k, old := range sniH1Clients {
			if oldTr, ok := old.Transport.(*http.Transport); ok {
				oldTr.CloseIdleConnections()
			}
			delete(sniH1Clients, k)
			break
		}
	}
	sniH1Clients[key] = c
	return c
}

// SNIFrontDo（方式 1）通过 DoH 解析真实 IP + SNI 伪装直连目标主机，
// 并在握手后核对服务端回传证书是否覆盖伪装前的真实域名 host（truedomain.com）且未过期。
func SNIFrontDo(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	normMode := netdial.NormalizeIPMode(mode)
	if normMode == "" {
		normMode = currentConfig().ipMode
	}
	normMode = netdial.EffectiveIPMode(normMode)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	ips, err := ResolveHostIPsByMode(req.Context(), host, normMode)
	if err != nil {
		return nil, err
	}
	sniName := SNIServerNameFromContext(req.Context())

	var lastErr error
	for _, ip := range ips {
		resp, err := getSNIH2Transport(ip, sniName, host).RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// 若命中证书校验错误（过期 / 域名不一致 / 不可信），立即上抛以渲染警告页
		if IsCertError(err) {
			return nil, err
		}
		// 若源站仅支持 HTTP/1.1，自动回退至 uTLS HTTP/1.1 传输
		if strings.Contains(err.Error(), "not h2") {
			if resp1, err1 := getSNIH1Client(ip, sniName, host).Do(req); err1 == nil {
				return resp1, nil
			} else {
				if IsCertError(err1) {
					return nil, err1
				}
				err = err1
			}
		}
		lastErr = err
		key := ip + "|" + sniName + "|" + host
		sniTransMu.Lock()
		if old, ok := sniH2Trans[key]; ok {
			old.CloseIdleConnections()
			delete(sniH2Trans, key)
		}
		sniTransMu.Unlock()
	}
	ipCacheMu.Lock()
	delete(ipCache, host+"|"+normMode)
	ipCacheMu.Unlock()
	return nil, fmt.Errorf("all IPs failed for %s: %w", host, lastErr)
}