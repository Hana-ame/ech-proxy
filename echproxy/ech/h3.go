package cloudflare_ech

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	// echH3Enabled 控制是否启用 HTTP/3 作为 ECH 通道的备选回退方案（默认关闭）。
	// 严格仅限 ECH 通道（client.go）使用，SNI 伪装与 Fragment 通道绝不使用 HTTP/3。
	echH3Enabled atomic.Bool

	h3ClientsMu sync.Mutex
	h3Clients   = map[string]*http.Client{}
)

// SetECHHTTP3 开启或关闭 ECH 通道的 HTTP/3 备选回退（热切换，无需重启）。
// 关闭时立即清理已缓存的 HTTP/3 QUIC 连接，避免残留 UDP 套接字。
func SetECHHTTP3(enabled bool) {
	prev := echH3Enabled.Swap(enabled)
	if prev != enabled {
		log.Printf("[ECH] HTTP/3 fallback for ECH channel set to: %v (SNI/Fragment never use HTTP/3)", enabled)
	}
	if !enabled {
		closeECHHTTP3Clients()
	}
}

// GetECHHTTP3 返回当前是否开启了 ECH 通道的 HTTP/3 备选方案（默认 false）。
func GetECHHTTP3() bool {
	return echH3Enabled.Load()
}

func closeECHHTTP3Clients() {
	h3ClientsMu.Lock()
	old := h3Clients
	h3Clients = map[string]*http.Client{}
	h3ClientsMu.Unlock()

	for _, cli := range old {
		if cli == nil {
			continue
		}
		if tr, ok := cli.Transport.(*http3.Transport); ok {
			_ = tr.Close()
		}
	}
}

func newECHHTTP3Client(echConfig []byte, ipMode string) *http.Client {
	cfgCopy := append([]byte(nil), echConfig...)
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:                     tls.VersionTLS13,
			EncryptedClientHelloConfigList: cfgCopy,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 4 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if port == "" {
				port = "443"
			}
			mode := netdial.NormalizeIPMode(ipMode)
			if mode == "" {
				mode = currentConfig().ipMode
			}
			mode = netdial.EffectiveIPMode(mode)

			dialIPs, derr := ResolveHostIPsByMode(ctx, shellDomain, mode)
			if derr != nil || len(dialIPs) == 0 {
				return nil, fmt.Errorf("ECH HTTP/3 resolve %s (%s): %w", shellDomain, mode, derr)
			}
			dialIPs = netdial.OrderIPsHealthyFirst(dialIPs)
			maxTry := len(dialIPs)
			if maxTry > 3 {
				maxTry = 3
			}

			perHostTLS := tlsCfg.Clone()
			if perHostTLS == nil {
				perHostTLS = &tls.Config{}
			}
			perHostTLS.ServerName = host
			perHostTLS.MinVersion = tls.VersionTLS13
			perHostTLS.EncryptedClientHelloConfigList = cfgCopy
			perHostTLS.NextProtos = []string{http3.NextProtoH3}
			// 交由统一证书核对函数 validateUpstreamCert 校验真实域名与有效期
			perHostTLS.InsecureSkipVerify = true
			perHostTLS.VerifyConnection = func(cs tls.ConnectionState) error {
				return validateUpstreamCert(ctx, host, cs.PeerCertificates)
			}

			var lastErr error
			for i := 0; i < maxTry; i++ {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				ip := dialIPs[i]
				dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				qConn, qErr := quic.DialAddrEarly(dialCtx, net.JoinHostPort(ip, port), perHostTLS, qCfg)
				cancel()
				if qErr == nil {
					netdial.ClearBadIP(ip)
					return qConn, nil
				}
				if IsCertError(qErr) {
					return nil, qErr
				}
				if ctx.Err() == nil {
					netdial.MarkBadIP(ip)
				}
				lastErr = qErr
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errors.New("ECH HTTP/3 dial failed for all candidate IPs")
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func getECHHTTP3Client(ipMode string) (*http.Client, error) {
	mode := netdial.NormalizeIPMode(ipMode)
	if mode == "" {
		mode = currentConfig().ipMode
	}
	mode = netdial.EffectiveIPMode(mode)

	h3ClientsMu.Lock()
	if c, ok := h3Clients[mode]; ok {
		h3ClientsMu.Unlock()
		return c, nil
	}
	h3ClientsMu.Unlock()

	clientsMu.Lock()
	cfg := append([]byte(nil), lastECHConfig...)
	clientsMu.Unlock()

	if len(cfg) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), dohTimeout)
		fetched, err := fetchECHConfig(ctx, shellDomain)
		cancel()
		if err != nil {
			return nil, err
		}
		cfg = fetched
		clientsMu.Lock()
		lastECHConfig = fetched
		clientsMu.Unlock()
	}

	h3ClientsMu.Lock()
	defer h3ClientsMu.Unlock()
	if c, ok := h3Clients[mode]; ok {
		return c, nil
	}
	c := newECHHTTP3Client(cfg, mode)
	h3Clients[mode] = c
	return c, nil
}

// doECHHTTP3 仅作为 ECH 通道在 HTTP/2 失败时的备选方案调用。
func doECHHTTP3(req *http.Request, ipMode string) (*http.Response, error) {
	c, err := getECHHTTP3Client(ipMode)
	if err != nil {
		return nil, err
	}
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	return c.Do(req)
}
