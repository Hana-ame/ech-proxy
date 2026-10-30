package echproxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/certstore"
	"github.com/Hana-ame/ech-proxy/echproxy/config"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/ech-proxy/echproxy/rewrite"
	"golang.org/x/net/http2"
)

const (
	DefaultPerPeerMaxTunnels = 128
	DefaultGlobalMaxTunnels  = 1024
	DefaultTunnelIdleTimeout = 60 * time.Second
	authFailureWindow        = 5 * time.Minute
	maxAuthFailures          = 10
	// authFailuresPurgeThreshold 是 failures map 的清扫触发阈值：达到该条目数时
	// 顺带删除所有已过窗口的条目，防止来自大量一次性来源 IP 的失败记录无界堆积。
	authFailuresPurgeThreshold = 4096

	ConnectModeAuto   = "auto"
	ConnectModeMITM   = "mitm"
	ConnectModeTunnel = "tunnel"
)

type AuthConfig struct {
	Token    string
	Username string
	Password string

	mu       sync.Mutex
	failures map[string]*authFailWindow
}

type authFailWindow struct {
	count     int
	windowEnd time.Time
}

func AuthConfigFromEnv() *AuthConfig {
	return &AuthConfig{
		Token:    strings.TrimSpace(os.Getenv("ECH_PROXY_TOKEN")),
		Username: strings.TrimSpace(os.Getenv("ECH_PROXY_USER")),
		Password: strings.TrimSpace(os.Getenv("ECH_PROXY_PASS")),
	}
}

func (a *AuthConfig) Enabled() bool {
	return a != nil && (a.Token != "" || a.Username != "" || a.Password != "")
}

var ErrAuthRateLimited = errors.New("too many failed authentication attempts")

func (a *AuthConfig) Check(req *http.Request, clientIP string) (bool, error) {
	if !a.Enabled() {
		return true, nil
	}
	now := time.Now()
	a.mu.Lock()
	if a.failures == nil {
		a.failures = make(map[string]*authFailWindow)
	}
	// 过期条目只在「同一 IP 再次失败/成功」时才被覆盖或删除，攻击来源 IP 一旦不再出现
	// 就永久滞留。这里在 map 达到阈值时顺带清扫所有已过窗口的条目，避免无界增长（issue #45）。
	if len(a.failures) >= authFailuresPurgeThreshold {
		for k, v := range a.failures {
			if !now.Before(v.windowEnd) {
				delete(a.failures, k)
			}
		}
	}
	fw, exists := a.failures[clientIP]
	if exists && now.Before(fw.windowEnd) && fw.count >= maxAuthFailures {
		a.mu.Unlock()
		return false, ErrAuthRateLimited
	}
	a.mu.Unlock()

	ok := a.verifyCredentials(req.Header.Get("Proxy-Authorization")) ||
		a.verifyCredentials(req.Header.Get("Authorization"))

	a.mu.Lock()
	defer a.mu.Unlock()
	if ok {
		delete(a.failures, clientIP)
		return true, nil
	}
	if !exists || !now.Before(fw.windowEnd) {
		a.failures[clientIP] = &authFailWindow{count: 1, windowEnd: now.Add(authFailureWindow)}
	} else {
		fw.count++
	}
	return false, nil
}

func (a *AuthConfig) verifyCredentials(headerVal string) bool {
	headerVal = strings.TrimSpace(headerVal)
	if headerVal == "" {
		return false
	}
	if a.Token != "" {
		if strings.HasPrefix(strings.ToLower(headerVal), "bearer ") {
			tok := strings.TrimSpace(headerVal[7:])
			if subtle.ConstantTimeCompare([]byte(tok), []byte(a.Token)) == 1 {
				return true
			}
		}
		if subtle.ConstantTimeCompare([]byte(headerVal), []byte(a.Token)) == 1 {
			return true
		}
	}
	if a.Username != "" || a.Password != "" {
		if strings.HasPrefix(strings.ToLower(headerVal), "basic ") {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(headerVal[6:])); err == nil {
				if parts := strings.SplitN(string(raw), ":", 2); len(parts) == 2 {
					uOK := subtle.ConstantTimeCompare([]byte(parts[0]), []byte(a.Username)) == 1
					pOK := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(a.Password)) == 1
					if uOK && pOK {
						return true
					}
				}
			}
		}
	}
	return false
}

type TunnelLimiter struct {
	PerPeerMax int
	GlobalMax  int
	globalCur  atomic.Int32
	peers      sync.Map
}

func NewTunnelLimiter(perPeerMax, globalMax int) *TunnelLimiter {
	if perPeerMax <= 0 {
		perPeerMax = DefaultPerPeerMaxTunnels
	}
	if globalMax <= 0 {
		globalMax = DefaultGlobalMaxTunnels
	}
	return &TunnelLimiter{PerPeerMax: perPeerMax, GlobalMax: globalMax}
}

func (l *TunnelLimiter) Acquire(peerIP string) (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	val, _ := l.peers.LoadOrStore(peerIP, &atomic.Int32{})
	peerCounter := val.(*atomic.Int32)

	if peerCounter.Add(1) > int32(l.PerPeerMax) {
		peerCounter.Add(-1)
		return nil, false
	}
	if l.globalCur.Add(1) > int32(l.GlobalMax) {
		l.globalCur.Add(-1)
		peerCounter.Add(-1)
		return nil, false
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			l.globalCur.Add(-1)
			// 计数归零时删除该 peer 条目：原先只 Add(-1) 不 Delete，每个出现过的客户端 IP
			// 都会在 sync.Map 里永久留下一个 *atomic.Int32，长期运行无界增长（issue #45）。
			if peerCounter.Add(-1) == 0 {
				l.peers.CompareAndDelete(peerIP, peerCounter)
			}
		})
	}, true
}

func (l *TunnelLimiter) ActiveCount() int {
	if l == nil {
		return 0
	}
	return int(l.globalCur.Load())
}

func (l *TunnelLimiter) Stats() (active int, perPeerMax int, globalMax int) {
	if l == nil {
		return 0, 0, 0
	}
	return int(l.globalCur.Load()), l.PerPeerMax, l.GlobalMax
}

var dialConnectFn = func(ctx context.Context, host, port, ipMode string) (net.Conn, error) {
	if net.ParseIP(host) == nil {
		if ips, err := cloudflare_ech.ResolveHostIPsByMode(ctx, host, ipMode); err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if c, derr := netdial.DialContextIPMode(ctx, ip, port, ipMode, netdial.DialTimeout); derr == nil {
					return c, nil
				}
			}
		}
	}
	return netdial.DialContextIPMode(ctx, host, port, ipMode, netdial.DialTimeout)
}

func isMITMCapablePort(port string) bool {
	switch port {
	case "443", "80", "8443", "2053", "2083", "2087", "2096":
		return true
	default:
		return false
	}
}

func parseConnectTarget(req *http.Request) (string, string, error) {
	raw := strings.TrimSpace(req.RequestURI)
	if raw == "" || strings.HasPrefix(raw, "/") {
		raw = strings.TrimSpace(req.Host)
	}
	if strings.Contains(raw, "://") {
		return "", "", fmt.Errorf("connect target must be authority host:port, got URI %q", raw)
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid connect authority %q: %w", raw, err)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || strings.ContainsAny(host, " \t\r\n/\\") {
		return "", "", fmt.Errorf("empty or malformed connect host in %q", raw)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", "", fmt.Errorf("connect port out of range in %q", raw)
	}
	return host, strconv.Itoa(portNum), nil
}

func checkConnectTarget(host string, blockedHosts []string, allowPrivate bool) error {
	if !allowPrivate {
		if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
			return fmt.Errorf("connect to loopback/local host %q is forbidden", host)
		}
		if ip := net.ParseIP(host); ip != nil && netdial.IsPrivateOrReservedIP(ip) {
			return fmt.Errorf("connect to private or reserved IP %s is forbidden", host)
		}
	}
	for _, b := range blockedHosts {
		bh := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(b), "https://"), "http://")
		if idx := strings.IndexByte(bh, '/'); idx >= 0 {
			bh = bh[:idx]
		}
		if bh != "" && (host == bh || strings.HasSuffix(host, "."+bh)) {
			return fmt.Errorf("connect target %q is in blocked_hosts", host)
		}
	}
	return nil
}

type ConnectOptions struct {
	Enabled             bool
	Mode                string
	IPMode              string
	AllowPrivateTargets bool
	IdleTimeout         time.Duration
	Auth                *AuthConfig
	Limiter             *TunnelLimiter
	CertStore           *certstore.Store
	PortalCert          *tls.Certificate
	Config              *config.Config
	AdScript            *rewrite.AdScriptManager
	HTTPHandler         http.Handler
}

func handleHTTPConnect(w http.ResponseWriter, r *http.Request, opts ConnectOptions) {
	if !opts.Enabled {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("CONNECT tunnel is disabled; pass -allow-connect (or use default smart mode) to enable"))
		return
	}

	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	if opts.Auth != nil && opts.Auth.Enabled() {
		ok, err := opts.Auth.Check(r, clientIP)
		if errors.Is(err, ErrAuthRateLimited) {
			http.Error(w, "too many authentication failures", http.StatusTooManyRequests)
			return
		}
		if !ok {
			w.Header().Set("Proxy-Authenticate", `Basic realm="ech-proxy"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}

	host, port, err := parseConnectTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// upstream.json 严格只与 8443 方案有关，在 PAC 方案下不耦合 upstream.json 的 blocked_hosts / upstreams
	var upstreams config.UpstreamMap
	var blocked []string
	if opts.AdScript == nil || config.IsPortalDomain(host) {
		upstreams, blocked = opts.Config.Snapshot()
	}
	if err := checkConnectTarget(host, blocked, opts.AllowPrivateTargets); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	release, ok := opts.Limiter.Acquire(clientIP)
	if !ok {
		http.Error(w, "tunnel concurrency limit exceeded", http.StatusTooManyRequests)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		release()
		http.Error(w, "HTTP version does not support hijacking for CONNECT", http.StatusHTTPVersionNotSupported)
		return
	}

	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	useMITM := (mode == "" || mode == ConnectModeAuto || mode == ConnectModeMITM) &&
		isMITMCapablePort(port) && opts.CertStore != nil && opts.HTTPHandler != nil && net.ParseIP(host) == nil

	if useMITM {
		clientConn, clientBuf, err := hj.Hijack()
		if err != nil {
			release()
			return
		}
		logger.SafeGo("serveMITMConnect", func() {
			defer release()
			serveMITMConnect(clientConn, clientBuf, host, port, opts)
		})
		return
	}

	ipMode := opts.IPMode
	if len(upstreams) > 0 {
		if uc, exists := config.Resolve(upstreams, host); exists && uc.IPMode != "" {
			ipMode = uc.IPMode
		}
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		release()
		return
	}

	upConn, dialErr := dialConnectFn(r.Context(), host, port, ipMode)
	if dialErr != nil {
		release()
		writeConnectError(clientConn, http.StatusBadGateway, "Bad Gateway: "+dialErr.Error())
		_ = clientConn.Close()
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		release()
		_ = upConn.Close()
		_ = clientConn.Close()
		return
	}

	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		pipelined := make([]byte, clientBuf.Reader.Buffered())
		if n, _ := io.ReadFull(clientBuf.Reader, pipelined); n > 0 {
			if _, werr := upConn.Write(pipelined[:n]); werr != nil {
				release()
				_ = upConn.Close()
				_ = clientConn.Close()
				return
			}
		}
	}

	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultTunnelIdleTimeout
	}
	logger.SafeGo("CONNECT-Relay", func() {
		defer release()
		relay(newDeadlineConn(clientConn, idleTimeout), newDeadlineConn(upConn, idleTimeout))
	})
}

func serveMITMConnect(clientConn net.Conn, clientBuf *bufio.ReadWriter, targetHost, targetPort string, opts ConnectOptions) {
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	wrapped := newPrefixConn(clientConn, clientBuf)
	_ = wrapped.SetReadDeadline(time.Now().Add(netdial.DialTimeout))
	br := bufio.NewReaderSize(wrapped, 4096)
	first, perr := br.Peek(1)
	_ = wrapped.SetReadDeadline(time.Time{})
	if perr != nil {
		return
	}
	peekedConn := &bufferedConn{Conn: wrapped, r: br}

	if first[0] != 0x16 {
		plainHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if isWebSocketUpgrade(req) {
				serveWebSocketMITM(w, req, targetHost, targetPort, false, opts)
				return
			}
			if req.Host == "" {
				if targetPort != "" && targetPort != "80" {
					req.Host = net.JoinHostPort(targetHost, targetPort)
				} else {
					req.Host = targetHost
				}
			}
			req.URL.Scheme = "http"
			if req.URL.Host == "" {
				req.URL.Host = req.Host
			}
			opts.HTTPHandler.ServeHTTP(w, req)
		})
		srv := &http.Server{Handler: plainHandler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
		_ = srv.Serve(newSingleConnListener(peekedConn))
		return
	}

	baseTLS := opts.CertStore.TLSConfig(opts.PortalCert)
	tlsCfg := baseTLS.Clone()
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			hello.ServerName = targetHost
		}
		return baseTLS.GetCertificate(hello)
	}

	tlsConn := tls.Server(peekedConn, tlsCfg)
	ctx, cancel := context.WithTimeout(context.Background(), netdial.DialTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		if !isExpectedConnError(err) && opts.CertStore != nil {
			log.Printf("[CONNECT MITM] TLS handshake for %s failed: %v", targetHost, err)
		}
		return
	}

	tlsState := tlsConn.ConnectionState()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// WebSocket over wss://：必须原样转发 Upgrade 逐跳头并做 101 之后的双向字节流 relay，
		// 不能交给普通 HTTP 代理链路（其会剥离 Connection/Upgrade 且无法处理 101 升级，
		// 导致 MITM 隧道内白名单站点的实时连接全部失败，issue #43）。
		if isWebSocketUpgrade(req) {
			serveWebSocketMITM(w, req, targetHost, targetPort, true, opts)
			return
		}
		if req.Host == "" {
			req.Host = targetHost
		}
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		if req.TLS == nil {
			st := tlsState
			req.TLS = &st
		}
		opts.HTTPHandler.ServeHTTP(w, req)
	})

	if tlsState.NegotiatedProtocol == "h2" {
		h2Srv := &http2.Server{
			IdleTimeout:          15 * time.Second,
			MaxConcurrentStreams: 64,
		}
		h2Srv.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
	_ = srv.Serve(newSingleConnListener(tlsConn))
}

// isWebSocketUpgrade 判断请求是否为 HTTP/1.1 WebSocket 升级（Upgrade: websocket）。
func isWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
}

// dialWebSocketUpstream 为 MITM 隧道内的 WebSocket 升级建立到上游的原始连接。
//   - TLS 目标（wss://，CONNECT 443）：优先走 ech.DialRawTLS（DoH 解析 + uTLS 指纹 + ClientHello 分片）；
//   - 明文目标（ws://）：直接走 dialConnectFn。
func dialWebSocketUpstream(ctx context.Context, host, port string, upstreamTLS bool, ipMode string) (net.Conn, error) {
	if !upstreamTLS {
		return dialConnectFn(ctx, host, port, ipMode)
	}
	if port == "" {
		port = "443"
	}
	if port == "443" && net.ParseIP(host) == nil {
		if c, err := cloudflare_ech.DialRawTLS(ctx, host, ipMode); err == nil {
			return c, nil
		}
	}
	raw, err := dialConnectFn(ctx, host, port, ipMode)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName: host,
		RootCAs:    netdial.RootPool(),
		MinVersion: tls.VersionTLS12,
	})
	hctx, cancel := context.WithTimeout(ctx, netdial.DialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// writeRawUpgradeRequest 把 WebSocket 升级请求原样写给上游。
// 与普通 HTTP 转发相反，这里必须保留 Connection / Upgrade / Sec-WebSocket-* 等逐跳头。
func writeRawUpgradeRequest(w io.Writer, req *http.Request, targetHost, targetPort string) error {
	uri := req.RequestURI
	if uri == "" && req.URL != nil {
		uri = req.URL.RequestURI()
	}
	if uri == "" {
		uri = "/"
	}
	host := req.Host
	if host == "" {
		if targetPort != "" && targetPort != "443" && targetPort != "80" {
			host = net.JoinHostPort(targetHost, targetPort)
		} else {
			host = targetHost
		}
	}
	var sb strings.Builder
	sb.WriteString(req.Method)
	sb.WriteByte(' ')
	sb.WriteString(uri)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(host)
	sb.WriteString("\r\n")
	for k, vs := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\r\n")
		}
	}
	sb.WriteString("\r\n")
	_, err := io.WriteString(w, sb.String())
	return err
}

// serveWebSocketMITM 在 CONNECT MITM 隧道内完成 WebSocket 升级并转入双向字节流 relay。
// 返回后该请求的生命周期完全由本函数接管。
func serveWebSocketMITM(w http.ResponseWriter, req *http.Request, targetHost, targetPort string, upstreamTLS bool, opts ConnectOptions) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket: connection hijacking unsupported", http.StatusNotImplemented)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		return
	}
	clientConn = newPrefixConn(clientConn, clientBuf)

	upConn, derr := dialWebSocketUpstream(req.Context(), targetHost, targetPort, upstreamTLS, opts.IPMode)
	if derr != nil {
		_ = clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		_ = clientConn.Close()
		return
	}

	if werr := writeRawUpgradeRequest(upConn, req, targetHost, targetPort); werr != nil {
		_ = upConn.Close()
		_ = clientConn.Close()
		return
	}

	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultTunnelIdleTimeout
	}
	relay(newDeadlineConn(clientConn, idleTimeout), newDeadlineConn(upConn, idleTimeout))
}

func writeConnectError(conn net.Conn, code int, body string) {
	statusText := http.StatusText(code)
	if statusText == "" {
		statusText = "Error"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, statusText, len(body), body)
	_, _ = conn.Write([]byte(resp))
}

func relay(a, b net.Conn) {
	done := make(chan error, 2)
	cp := func(dst, src net.Conn) {
		bufPtr := streamBufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(dst, src, *bufPtr)
		streamBufPool.Put(bufPtr)
		done <- err
	}
	go cp(a, b)
	go cp(b, a)
	err := <-done
	_ = a.Close()
	_ = b.Close()
	<-done
	if err != nil && !isExpectedConnError(err) {
		debugLogf("CONNECT relay error: %v", err)
	}
}

func isExpectedConnError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "certificate") || strings.Contains(s, "x509") || strings.Contains(s, "tls:") {
		return false
	}
	for _, pat := range []string{"connection reset by peer", "broken pipe", "use of closed network connection", "unexpected eof", "forcibly closed by the remote host"} {
		if strings.Contains(s, pat) {
			return true
		}
	}
	return false
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func newPrefixConn(c net.Conn, rw *bufio.ReadWriter) net.Conn {
	if rw != nil && rw.Reader.Buffered() > 0 {
		buf := make([]byte, rw.Reader.Buffered())
		if n, _ := io.ReadFull(rw.Reader, buf); n > 0 {
			return &prefixConn{Conn: c, r: io.MultiReader(strings.NewReader(string(buf[:n])), c)}
		}
	}
	return c
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

type deadlineConn struct {
	net.Conn
	idle time.Duration
}

func newDeadlineConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	_ = c.SetDeadline(time.Now().Add(idle))
	return &deadlineConn{Conn: c, idle: idle}
}

func (d *deadlineConn) Read(b []byte) (int, error) {
	n, err := d.Conn.Read(b)
	if n > 0 {
		_ = d.Conn.SetDeadline(time.Now().Add(d.idle))
	}
	return n, err
}

func (d *deadlineConn) Write(b []byte) (int, error) {
	n, err := d.Conn.Write(b)
	if n > 0 {
		_ = d.Conn.SetDeadline(time.Now().Add(d.idle))
	}
	return n, err
}

type singleConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed sync.Once
	done   chan struct{}
}

// newSingleConnListener 创建一个只接受单条连接的监听器。
// done 通道让第二次 Accept 阻塞到该连接关闭为止——否则 http.Server.Serve
// 会在第一次 Accept 后立即返回，调用方过早关闭连接导致客户端 reset。
func newSingleConnListener(c net.Conn) net.Listener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) closeDone() {
	l.closed.Do(func() { close(l.done) })
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return &closeNotifyConn{Conn: c, closeDone: l.closeDone}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closeDone()
	return nil
}

// closeNotifyConn 在底层连接关闭时通知 listener 关闭 done，统一复用 listener 的 sync.Once，避免重复 close panic。
type closeNotifyConn struct {
	net.Conn
	closeDone func()
}

func (c *closeNotifyConn) Close() error {
	if c.closeDone != nil {
		c.closeDone()
	}
	return c.Conn.Close()
}
func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}