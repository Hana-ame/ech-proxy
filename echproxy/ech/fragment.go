// Package cloudflare_ech 方式三（Mode 3）：通过 DoH 解析真实 IP + TLS ClientHello 分片（Record Fragmentation & TCP Segmentation）绕过 GFW DPI。
//
// 适用场景：
//   - 当目标站点未托管在 Cloudflare（无法使用方式 2 的 ECH），且源站严格校验 TLS SNI（拒绝方式 1 的假 SNI 伪装，要求发送真实域名 truedomain.com）时，
//     直接发送含明文 SNI 的单包 ClientHello 会被 GFW 的 DPI 状态检测阻断（TCP RST / 丢包）。
//   - 本模块通过 DoH 解析出无污染的真实源站 IP，然后在发送首个 TLS Handshake 记录（ClientHello, 0x16）时，
//     将其拆分为多个微小的 TLS Record 片段并开启 TCP_NODELAY 逐片写出，打碎明文 SNI 特征，从而绕过 GFW DPI；
//   - 握手完成后，同样调用 validateUpstreamCert 严格比对 truedomain.com 与服务端回传证书是否一致、是否过期。
package cloudflare_ech

import (
	"context"
	"crypto/tls"
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

var (
	fragTransMu   sync.Mutex
	fragH2Trans   = map[string]*http2.Transport{}
	fragH1Clients = map[string]*http.Client{}
)

// tlsFragmentConn 包装底层 TCP net.Conn，对首次写出的 TLS Handshake ClientHello 记录（0x16）执行 TLS 记录级分片（Record Fragmentation），
// 将原本完整的 ClientHello 握手负载切分为多个合法的小 TLS Record（打断 SNI 扩展中的明文域名连续字节），后续记录原样透传。
type tlsFragmentConn struct {
	net.Conn
	mu          sync.Mutex
	firstWrite  bool
	maxFragSize int
}

func newTLSFragmentConn(c net.Conn, maxFragSize int) *tlsFragmentConn {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if maxFragSize <= 0 {
		maxFragSize = 32
	}
	return &tlsFragmentConn{
		Conn:        c,
		firstWrite:  true,
		maxFragSize: maxFragSize,
	}
}

// FragmentTLSClientHelloRecord 将单条 TLS Handshake 记录（5 字节头: [0x16, major, minor, lenHi, lenLo] + payload）
// 拆分为多条共享相同协议版本号、但每条长度不超过 chunkSize 的合法 TLS Handshake 记录（供单元测试与线上分片共用）。
func FragmentTLSClientHelloRecord(pkt []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = 32
	}
	// 检查是否为单条完整的 TLS Handshake (0x16) 记录
	if len(pkt) <= 5 || pkt[0] != 0x16 || pkt[1] != 0x03 {
		return [][]byte{pkt}
	}
	recLen := int(pkt[3])<<8 | int(pkt[4])
	if 5+recLen != len(pkt) || recLen <= 4 {
		return [][]byte{pkt}
	}
	verMajor, verMinor := pkt[1], pkt[2]
	payload := pkt[5:]

	// 首片固定切在极小长度（如 4 字节，恰好拆开 Handshake 头部与后续扩展/SNI），其后按 chunkSize 分片
	firstSplit := 4
	if firstSplit >= len(payload) {
		firstSplit = len(payload) / 2
	}

	var fragments [][]byte
	appendRecord := func(chunk []byte) {
		if len(chunk) == 0 {
			return
		}
		rec := make([]byte, 5+len(chunk))
		rec[0] = 0x16
		rec[1] = verMajor
		rec[2] = verMinor
		rec[3] = byte(len(chunk) >> 8)
		rec[4] = byte(len(chunk))
		copy(rec[5:], chunk)
		fragments = append(fragments, rec)
	}

	appendRecord(payload[:firstSplit])
	rest := payload[firstSplit:]
	for len(rest) > 0 {
		n := chunkSize
		if n > len(rest) {
			n = len(rest)
		}
		appendRecord(rest[:n])
		rest = rest[n:]
	}
	return fragments
}

func (fc *tlsFragmentConn) Write(b []byte) (int, error) {
	fc.mu.Lock()
	isFirst := fc.firstWrite
	fc.firstWrite = false
	fc.mu.Unlock()

	if !isFirst || len(b) <= 5 || b[0] != 0x16 {
		return fc.Conn.Write(b)
	}

	records := FragmentTLSClientHelloRecord(b, fc.maxFragSize)
	for _, rec := range records {
		if _, err := fc.Conn.Write(rec); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func dialFragmentUTLS(ctx context.Context, ip, host string, nextProtos []string) (*utls.UConn, error) {
	rawConn, err := (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return nil, err
	}
	fragConn := newTLSFragmentConn(rawConn, 24)
	uConn := utls.UClient(fragConn, &utls.Config{
		ServerName:         host, // 发送真实域名，但经由 tlsFragmentConn 进行 TLS 记录分片以绕过 GFW SNI 检测
		InsecureSkipVerify: true, // 由下方 validateUpstreamCert 统一校验时间、真实域名与信任链
		NextProtos:         nextProtos,
	}, utls.HelloChrome_120)
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	if cerr := validateUpstreamCert(ctx, host, uConn.ConnectionState().PeerCertificates); cerr != nil {
		rawConn.Close()
		return nil, cerr
	}
	return uConn, nil
}

func getFragmentH2Transport(ip, host string) *http2.Transport {
	key := ip + "|" + host
	fragTransMu.Lock()
	defer fragTransMu.Unlock()
	if t, ok := fragH2Trans[key]; ok {
		return t
	}
	t := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			uConn, err := dialFragmentUTLS(ctx, ip, host, []string{"h2", "http/1.1"})
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
	if len(fragH2Trans) >= maxSNICacheEntries {
		for k, old := range fragH2Trans {
			old.CloseIdleConnections()
			delete(fragH2Trans, k)
			break
		}
	}
	fragH2Trans[key] = t
	return t
}

func getFragmentH1Client(ip, host string) *http.Client {
	key := ip + "|" + host
	fragTransMu.Lock()
	defer fragTransMu.Unlock()
	if c, ok := fragH1Clients[key]; ok {
		return c
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialFragmentUTLS(ctx, ip, host, []string{"http/1.1"})
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
	if len(fragH1Clients) >= maxSNICacheEntries {
		for k, old := range fragH1Clients {
			if oldTr, ok := old.Transport.(*http.Transport); ok {
				oldTr.CloseIdleConnections()
			}
			delete(fragH1Clients, k)
			break
		}
	}
	fragH1Clients[key] = c
	return c
}

// FragmentDo（方式 3）使用 DoH 解析目标真实 IP + TLS ClientHello 记录分片绕过 GFW DPI，
// 并在握手后核对服务端回传证书是否与真实域名一致、是否过期。
func FragmentDo(req *http.Request, ipMode ...string) (*http.Response, error) {
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

	var lastErr error
	for _, ip := range ips {
		resp, err := getFragmentH2Transport(ip, host).RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		if IsCertError(err) {
			return nil, err
		}
		if strings.Contains(err.Error(), "not h2") {
			if resp1, err1 := getFragmentH1Client(ip, host).Do(req); err1 == nil {
				return resp1, nil
			} else {
				if IsCertError(err1) {
					return nil, err1
				}
				err = err1
			}
		}
		lastErr = err
		key := ip + "|" + host
		fragTransMu.Lock()
		if old, ok := fragH2Trans[key]; ok {
			old.CloseIdleConnections()
			delete(fragH2Trans, key)
		}
		fragTransMu.Unlock()
	}
	ipCacheMu.Lock()
	delete(ipCache, host+"|"+normMode)
	ipCacheMu.Unlock()
	return nil, fmt.Errorf("fragment bypass failed for %s: %w", host, lastErr)
}
