package cloudflare_ech

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	routeCacheTTL      = 30 * time.Minute
	maxSNICacheEntries = 256
)

var (
	defaultSNIIndex         uint64
	windowsUpdateSubdomains = []string{
		"update",
		"download",
		"www",
		"ctldl",
		"tsfe",
		"msdl",
	}
	windowsUpdateIndex uint64

	// DefaultSNIDomains 是一组在国内完全不受影响、属于全球大型主流云与基础服务（Apple、Microsoft、Windows Update 等）的高信誉域名。
	// 当未指定自定义伪装 SNI 时，按轮询（Round-Robin）顺序轮换使用这些域名作为 TLS ClientHello 的伪装 ServerName，绝不留空。
	DefaultSNIDomains = []string{
		"apple.com",
		"icloud.com",
		"msa.apple.com",
		"microsoft.com",
		"azure.microsoft.com",
		"*.windowsupdate.com",
	}
)

// NextDefaultSNIServerName 线程安全地按轮询（Round-Robin）顺序返回下一个默认伪装 SNI 域名。
// 针对通配符规则（如 *.windowsupdate.com），自动转换为合法的常见子域名（如 update.windowsupdate.com, download.windowsupdate.com 等）。
func NextDefaultSNIServerName() string {
	if len(DefaultSNIDomains) == 0 {
		return "microsoft.com"
	}
	idx := atomic.AddUint64(&defaultSNIIndex, 1) - 1
	d := DefaultSNIDomains[idx%uint64(len(DefaultSNIDomains))]
	if strings.HasPrefix(d, "*.") {
		subIdx := atomic.AddUint64(&windowsUpdateIndex, 1) - 1
		sub := windowsUpdateSubdomains[subIdx%uint64(len(windowsUpdateSubdomains))]
		return sub + d[1:]
	}
	return d
}

type sniServerNameKey struct{}

func WithSNIServerName(ctx context.Context, serverName string) context.Context {
	if strings.TrimSpace(serverName) == "" {
		return ctx
	}
	return context.WithValue(ctx, sniServerNameKey{}, strings.TrimSpace(serverName))
}

// HasCustomSNIServerName 检查当前 Context 中是否显式注入了自定义的伪装 SNI（且非 "none"）。
func HasCustomSNIServerName(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if v, ok := ctx.Value(sniServerNameKey{}).(string); ok && v != "" {
		return !strings.EqualFold(v, "none")
	}
	return false
}

// SNIServerNameFromContext 从 Context 中获取 SNI 伪装域名。
// 若未显式指定自定义 SNI，则自动从大型服务不受影响的白名单域名中轮换选取一个，绝不留空。
// 若显式指定为 "none"，则明确返回空字符串以发送无 SNI 扩展的握手。
func SNIServerNameFromContext(ctx context.Context) string {
	if ctx != nil {
		if v, ok := ctx.Value(sniServerNameKey{}).(string); ok && v != "" {
			if strings.EqualFold(v, "none") {
				return ""
			}
			return v
		}
	}
	return NextDefaultSNIServerName()
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

func DetectTransportMode(ctx context.Context, host string) string {
	mode, _ := DetectTransportModeWithStatus(ctx, host, "")
	return mode
}

func DetectTransportModeWithStatus(ctx context.Context, host, ipMode string) (mode string, confident bool) {
	host = netdial.CleanHost(host)
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
		// 非 Cloudflare 节点：若配置了显式自定义伪装 SNI 则首选 sni，否则首选 fragment（TLS 记录分片绕过 GFW）
		if HasCustomSNIServerName(ctx) {
			return "sni", true
		}
		return "fragment", true
	}
	return "ech", false
}

func resolveEffectiveIPMode(ipMode string) string {
	norm := netdial.NormalizeIPMode(ipMode)
	if norm == "" {
		norm = currentConfig().ipMode
	}
	return netdial.EffectiveIPMode(norm)
}

func extractRequestHost(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.Host != "" {
		return netdial.CleanHost(req.Host)
	}
	if req.URL != nil {
		return netdial.CleanHost(req.URL.Host)
	}
	return ""
}

const maxBufferedReqBody = 1 << 20 // 1MB

func cloneRequestForRace(req *http.Request, ctx context.Context, bodyBytes []byte) *http.Request {
	clone := req.Clone(ctx)
	if len(bodyBytes) > 0 {
		clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else if req.Body == nil || req.Body == http.NoBody {
		clone.Body = http.NoBody
	}
	return clone
}

type raceResult struct {
	mode string
	resp *http.Response
	err  error
}

type bodyCloseNotifier struct {
	io.ReadCloser
	once    sync.Once
	onClose func()
}

func (b *bodyCloseNotifier) Close() error {
	var err error
	if b.ReadCloser != nil {
		err = b.ReadCloser.Close()
	}
	b.once.Do(func() {
		if b.onClose != nil {
			b.onClose()
		}
	})
	return err
}

func raceModes(req *http.Request, modes []string, normIPMode string, host string) (*http.Response, error) {
	if len(modes) == 0 {
		return nil, fmt.Errorf("no transport modes to race for %s", host)
	}
	if len(modes) == 1 {
		resp, err := doSingleMode(req, modes[0], normIPMode)
		if err == nil && !isCloudflareRouteRejection(resp, modes[0]) && resp.StatusCode < 500 {
			setCachedRoute(host, modes[0])
		}
		return resp, err
	}

	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		if b, err := io.ReadAll(io.LimitReader(req.Body, maxBufferedReqBody)); err == nil {
			bodyBytes = b
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	racers := make(map[string]context.CancelFunc, len(modes))
	resCh := make(chan raceResult, len(modes))

	for _, m := range modes {
		mode := m
		ctx, cancel := context.WithCancel(req.Context())
		racers[mode] = cancel
		go func() {
			cloneReq := cloneRequestForRace(req, ctx, bodyBytes)
			resp, err := doSingleMode(cloneReq, mode, normIPMode)
			if err != nil {
				resCh <- raceResult{mode: mode, resp: nil, err: err}
				return
			}
			if isCloudflareRouteRejection(resp, mode) {
				_ = resp.Body.Close()
				resCh <- raceResult{mode: mode, resp: nil, err: fmt.Errorf("cloudflare route rejection status %d", resp.StatusCode)}
				return
			}
			resCh <- raceResult{mode: mode, resp: resp, err: nil}
		}()
	}

	var lastErr error
	var fallback5xxResp *http.Response
	var fallback5xxMode string
	pending := len(modes)

	for pending > 0 {
		select {
		case <-req.Context().Done():
			for _, cancel := range racers {
				cancel()
			}
			return nil, req.Context().Err()
		case res := <-resCh:
			pending--
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if res.resp.StatusCode < 500 {
				// 取消落后/失败分支的 context，但保留优胜分支的 context 直到 Response.Body 被完全读取并 Close，
				// 避免在传输流读取期间因为取消上下文导致流中断（ERR_CONTENT_LENGTH_MISMATCH / 错误返回200）。
				winnerCancel := racers[res.mode]
				delete(racers, res.mode)
				for _, cancel := range racers {
					cancel()
				}
				if winnerCancel != nil && res.resp.Body != nil {
					res.resp.Body = &bodyCloseNotifier{
						ReadCloser: res.resp.Body,
						onClose:    winnerCancel,
					}
				}

				go func(rem int) {
					for i := 0; i < rem; i++ {
						r := <-resCh
						if r.resp != nil && r.resp.Body != nil {
							_ = r.resp.Body.Close()
						}
					}
				}(pending)

				setCachedRoute(host, res.mode)
				return res.resp, nil
			}
			if fallback5xxResp == nil {
				fallback5xxResp = res.resp
				fallback5xxMode = res.mode
			} else {
				_ = res.resp.Body.Close()
			}
		}
	}

	if fallback5xxResp != nil {
		winnerCancel := racers[fallback5xxMode]
		delete(racers, fallback5xxMode)
		for _, cancel := range racers {
			cancel()
		}
		if winnerCancel != nil && fallback5xxResp.Body != nil {
			fallback5xxResp.Body = &bodyCloseNotifier{
				ReadCloser: fallback5xxResp.Body,
				onClose:    winnerCancel,
			}
		}
		setCachedRoute(host, fallback5xxMode)
		return fallback5xxResp, nil
	}

	for _, cancel := range racers {
		cancel()
	}

	if respDir, errDir := directDo(req, normIPMode); errDir == nil {
		return respDir, nil
	} else if IsCertError(errDir) {
		return nil, errDir
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all transport modes (%s) failed for %s", strings.Join(modes, ", "), host)
}

// RoundTrip 统一调度上游请求通道（供 PAC 方案、443 方案、8443 方案共同复用），并在所有 HTTPS 路径核对上游证书。
func RoundTrip(req *http.Request, mode, ipMode string) (*http.Response, error) {
	normIPMode := resolveEffectiveIPMode(ipMode)

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
	if trimmedMode == "sni" {
		return SNIFrontDo(req, normIPMode)
	}
	if trimmedMode == "ech" {
		return Do(req, normIPMode)
	}

	host := extractRequestHost(req)

	// 1. 若当前域名已有命中的历史成功路由缓存，直接使用该模式，零并发开销
	if cached, ok := getCachedRoute(host); ok {
		resp, err := doSingleMode(req, cached, normIPMode)
		if err == nil && !isCloudflareRouteRejection(resp, cached) && resp.StatusCode < 500 {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if IsCertError(err) {
			return nil, err
		}
		clearCachedRoute(host)
	}

	// 2. 无缓存或缓存失效时：并发竞速三种方案（ECH、SNI 伪装、TLS 分片），选出最快成功返回的方案！
	return raceModes(req, []string{"ech", "sni", "fragment"}, normIPMode, host)
}

func PlainHTTPDo(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	normMode := resolveEffectiveIPMode(mode)

	hostPort := req.URL.Host
	if hostPort == "" {
		hostPort = req.Host
	}
	host := netdial.CleanHost(hostPort)
	port := netdial.ExtractPort(hostPort)
	if port == "" {
		port = "80"
	}

	dialTarget := host
	if ips, err := ResolveHostIPsByMode(req.Context(), host, normMode); err == nil && len(ips) > 0 {
		dialTarget = ips[0]
	}

	tr := netdial.TransportWithIPMode(normMode).Clone()
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return netdial.DialContextIPMode(ctx, dialTarget, port, normMode, dialTimeout)
	}
	c := &http.Client{
		Transport:     tr,
		Timeout:       netdial.OpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c.Do(req)
}

func directDo(req *http.Request, ipMode string) (*http.Response, error) {
	tr := netdial.TransportWithIPModeAndCertCheck(ipMode, func(host string, peerCerts []*x509.Certificate) error {
		return validateUpstreamCert(req.Context(), host, peerCerts)
	})
	c := &http.Client{
		Transport:     tr,
		Timeout:       netdial.OpTimeout,
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
	ipCacheMu     sync.Mutex
	ipCache       = map[string]ipCacheEntry{}
	utlsTransMu   sync.Mutex
	utlsH2Trans   = map[string]*http2.Transport{}
	utlsH1Clients = map[string]*http.Client{}
)

func ResolveHostIPs(ctx context.Context, host string) ([]string, error) {
	return ResolveHostIPsByMode(ctx, host, "")
}

func ResolveHostIPsByMode(ctx context.Context, host, ipMode string) ([]string, error) {
	host = netdial.CleanHost(host)
	normMode := resolveEffectiveIPMode(ipMode)

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

	qtypes := []int{1}
	switch normMode {
	case "v6":
		qtypes = []int{28}
	case "dual":
		qtypes = []int{1, 28}
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
								for _, m := range netdial.FilterIPsByMode([]net.IP{parsed}, normMode) {
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
		if normMode == "dual" && len(ips) > 0 {
			break
		}
	}

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

// dialUTLSWithWrapper 统一的 uTLS Chrome 指纹拨号与上游证书校验封装（供 SNI 伪装与 Fragment 分片模式共同复用）。
func dialUTLSWithWrapper(ctx context.Context, ip, sniName, verifyHost string, nextProtos []string, wrapConn func(net.Conn) net.Conn) (*utls.UConn, error) {
	rawConn, err := (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	var baseConn net.Conn = rawConn
	if wrapConn != nil {
		baseConn = wrapConn(rawConn)
	}
	uConn := utls.UClient(baseConn, &utls.Config{
		ServerName:         sniName,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
	}, utls.HelloChrome_120)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	if cerr := validateUpstreamCert(ctx, verifyHost, uConn.ConnectionState().PeerCertificates); cerr != nil {
		rawConn.Close()
		return nil, cerr
	}
	return uConn, nil
}

func getUTLSH2Transport(cacheKey string, dialFn func(ctx context.Context, nextProtos []string) (*utls.UConn, error)) *http2.Transport {
	utlsTransMu.Lock()
	defer utlsTransMu.Unlock()
	if t, ok := utlsH2Trans[cacheKey]; ok {
		return t
	}
	t := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			uConn, err := dialFn(ctx, []string{"h2", "http/1.1"})
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
	if len(utlsH2Trans) >= maxSNICacheEntries {
		for k, old := range utlsH2Trans {
			old.CloseIdleConnections()
			delete(utlsH2Trans, k)
			break
		}
	}
	utlsH2Trans[cacheKey] = t
	return t
}

func getUTLSH1Client(cacheKey string, dialFn func(ctx context.Context, nextProtos []string) (*utls.UConn, error)) *http.Client {
	utlsTransMu.Lock()
	defer utlsTransMu.Unlock()
	if c, ok := utlsH1Clients[cacheKey]; ok {
		return c
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialFn(ctx, []string{"http/1.1"})
		},
		MaxIdleConns:    32,
		IdleConnTimeout: 90 * time.Second,
	}
	c := &http.Client{
		Transport:     tr,
		Timeout:       netdial.OpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if len(utlsH1Clients) >= maxSNICacheEntries {
		for k, old := range utlsH1Clients {
			if oldTr, ok := old.Transport.(*http.Transport); ok {
				oldTr.CloseIdleConnections()
			}
			delete(utlsH1Clients, k)
			break
		}
	}
	utlsH1Clients[cacheKey] = c
	return c
}

// roundTripUTLS 复用 DoH 解析、H2/H1.1 自适应降级、证书错误透传与连接池淘汰逻辑（供 SNIFrontDo 与 FragmentDo 共用）。
func roundTripUTLS(req *http.Request, ipMode, tag, sniName string, wrapConn func(net.Conn) net.Conn) (*http.Response, error) {
	normMode := resolveEffectiveIPMode(ipMode)
	host := extractRequestHost(req)
	ips, err := ResolveHostIPsByMode(req.Context(), host, normMode)
	if err != nil {
		return nil, err
	}
	effectiveSNI := sniName
	if effectiveSNI == "" {
		if tag == "frag" {
			effectiveSNI = host
		} else if tag == "sni" {
			effectiveSNI = NextDefaultSNIServerName()
		}
	}

	var lastErr error
	for _, ip := range ips {
		cacheKey := tag + "|" + ip + "|" + effectiveSNI + "|" + host
		dialFn := func(ctx context.Context, nextProtos []string) (*utls.UConn, error) {
			return dialUTLSWithWrapper(ctx, ip, effectiveSNI, host, nextProtos, wrapConn)
		}
		resp, err := getUTLSH2Transport(cacheKey, dialFn).RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		if IsCertError(err) {
			return nil, err
		}
		if strings.Contains(err.Error(), "not h2") {
			if resp1, err1 := getUTLSH1Client(cacheKey, dialFn).Do(req); err1 == nil {
				return resp1, nil
			} else {
				if IsCertError(err1) {
					return nil, err1
				}
				err = err1
			}
		}
		lastErr = err
		utlsTransMu.Lock()
		if old, ok := utlsH2Trans[cacheKey]; ok {
			old.CloseIdleConnections()
			delete(utlsH2Trans, cacheKey)
		}
		utlsTransMu.Unlock()
	}
	ipCacheMu.Lock()
	delete(ipCache, host+"|"+normMode)
	ipCacheMu.Unlock()
	return nil, fmt.Errorf("all IPs failed for %s: %w", host, lastErr)
}

func SNIFrontDo(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	return roundTripUTLS(req, mode, "sni", SNIServerNameFromContext(req.Context()), nil)
}