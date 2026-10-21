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
	"golang.org/x/net/http2"
)

const (
	DefaultPerPeerMaxTunnels = 128
	DefaultGlobalMaxTunnels  = 1024
	DefaultTunnelIdleTimeout = 10 * time.Minute
	authFailureWindow        = 5 * time.Minute
	maxAuthFailures          = 10

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
			peerCounter.Add(-1)
		})
	}, true
}

func (l *TunnelLimiter) ActiveCount() int {
	if l == nil {
		return 0
	}
	return int(l.globalCur.Load())
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
	upstreams, blocked := opts.Config.Snapshot()
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
	if uc, exists := config.Resolve(upstreams, host); exists && uc.IPMode != "" {
		ipMode = uc.IPMode
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
		srv := &http.Server{Handler: plainHandler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second}
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

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			req.Host = targetHost
		}
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		opts.HTTPHandler.ServeHTTP(w, req)
	})

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: handler})
		return
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second}
	_ = srv.Serve(newSingleConnListener(tlsConn))
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
		_, err := io.Copy(dst, src)
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
// done 通道用于让第二次 Accept 阻塞，直到该连接被关闭——
// 否则 http.Server.Serve 会在第一次 Accept 后立即返回，导致调用方过早关闭连接。
func newSingleConnListener(c net.Conn) net.Listener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return &closeNotifyConn{Conn: c, done: l.done}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

// closeNotifyConn 在底层连接关闭时关闭 done 通道，使 singleConnListener 阻塞的
// 第二次 Accept 得以返回。
type closeNotifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}