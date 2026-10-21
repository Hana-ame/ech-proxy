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
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"golang.org/x/net/http2"
)

const (
	DefaultPerPeerMaxTunnels = 128
	DefaultGlobalMaxTunnels  = 1024
	DefaultTunnelIdleTimeout = 10 * time.Minute
	authFailureWindow        = 5 * time.Minute
	maxAuthFailures          = 10
)

// ConnectMode 定义 HTTP CONNECT 请求的处理策略：
//   - "auto" / "mitm": 对 443 端口且拥有本地 CA 时自动执行 TLS 终结并通过 ECH/SNI 管道转发（无需改 hosts、无需 443 权限即可代理 Pixiv/pximg 等全量站点）；非 443 端口自动回退为 TCP 隧道；
//   - "tunnel": 始终作为纯 TCP 字节流隧道透传（不终结 TLS）。
const (
	ConnectModeAuto   = "auto"
	ConnectModeMITM   = "mitm"
	ConnectModeTunnel = "tunnel"
)

// AuthConfig 定义代理访问认证配置（同时保护 CONNECT 隧道与反代请求，豁免 /healthz、/ca.pem、/proxy.pac 与门户首页）。
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

// AuthConfigFromEnv 从环境变量加载认证配置（对齐桌面端与 Android 端 #12）。
func AuthConfigFromEnv() *AuthConfig {
	return &AuthConfig{
		Token:    strings.TrimSpace(os.Getenv("ECH_PROXY_TOKEN")),
		Username: strings.TrimSpace(os.Getenv("ECH_PROXY_USER")),
		Password: strings.TrimSpace(os.Getenv("ECH_PROXY_PASS")),
	}
}

// Enabled 判断是否启用了访问认证。
func (a *AuthConfig) Enabled() bool {
	return a != nil && (a.Token != "" || a.Username != "" || a.Password != "")
}

var ErrAuthRateLimited = errors.New("too many failed authentication attempts")

// Check 校验请求的 Proxy-Authorization 或 Authorization 头，并执行防爆破限流。
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
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(headerVal[6:]))
			if err == nil {
				parts := strings.SplitN(string(raw), ":", 2)
				if len(parts) == 2 {
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

// TunnelLimiter 实现 DESIGN-tunnel-limits-and-android.md 中的双层并发隧道限流器（per-peer + global）。
type TunnelLimiter struct {
	PerPeerMax int
	GlobalMax  int
	globalCur  atomic.Int32
	peers      sync.Map // map[string]*atomic.Int32
}

// NewTunnelLimiter 创建并发隧道限流器。
func NewTunnelLimiter(perPeerMax, globalMax int) *TunnelLimiter {
	if perPeerMax <= 0 {
		perPeerMax = DefaultPerPeerMaxTunnels
	}
	if globalMax <= 0 {
		globalMax = DefaultGlobalMaxTunnels
	}
	return &TunnelLimiter{
		PerPeerMax: perPeerMax,
		GlobalMax:  globalMax,
	}
}

// Acquire 尝试为指定 peerIP 分配一条隧道配额；成功时返回 release 函数与 true，超限时返回 nil 与 false。
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

// ActiveCount 返回当前全局活跃隧道总数。
func (l *TunnelLimiter) ActiveCount() int {
	if l == nil {
		return 0
	}
	return int(l.globalCur.Load())
}

// dialConnectFn 供单元测试注入自定义拨号函数。
var dialConnectFn = func(ctx context.Context, host, port, ipMode string) (net.Conn, error) {
	return netdial.DialContextIPMode(ctx, host, port, ipMode, netdial.DialTimeout)
}

// parseConnectTarget 解析并严格校验 CONNECT 请求的 host:port（CONNECT-boundaries.md B5）。
// RequestURI 中的 authority 优先于 Host 头。
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

// checkConnectTarget 校验 CONNECT 目标是否触发 SSRF 防护（拦截环回、内网与 169.254.169.254 云元数据地址）。
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

// ConnectOptions 配置 HTTP CONNECT 处理器。
type ConnectOptions struct {
	Enabled             bool
	Mode                string // "auto" / "mitm" / "tunnel"
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

// handleHTTPConnect 按照「认证 → 目标校验 → 限流 → MITM / Dial」顺序处理 HTTP CONNECT 请求。
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

	// 1. 认证检查（带防爆破速率限制）
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

	// 2. 目标语法与 SSRF 黑名单校验（在限流配额前执行，防止扫描 169.254.169.254 耗尽配额）
	host, port, err := parseConnectTarget(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var blocked []string
	if opts.Config != nil {
		blocked = opts.Config.BlockedHosts
	}
	if err := checkConnectTarget(host, blocked, opts.AllowPrivateTargets); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 3. 并发隧道限流检查（per-peer 128 / global 1024）
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

	// 判断是否走 Smart MITM ECH/SNI 终结模式
	useMITM := false
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if (mode == "" || mode == ConnectModeAuto || mode == ConnectModeMITM) &&
		port == "443" && opts.CertStore != nil && opts.HTTPHandler != nil && net.ParseIP(host) == nil {
		useMITM = true
	}

	if useMITM {
		clientConn, clientBuf, err := hj.Hijack()
		if err != nil {
			release()
			return
		}
		go func() {
			defer release()
			serveMITMConnect(clientConn, clientBuf, host, opts)
		}()
		return
	}

	// 4. Raw TCP 隧道模式：先拨号上游，再 hijack 发送 200（或 hijack 后手写 502）
	ipMode := opts.IPMode
	if opts.Config != nil {
		if uc, exists := config.Resolve(opts.Config.Upstreams, host); exists && uc.IPMode != "" {
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

	// B2: 转发客户端与 CONNECT 同包发出的 pipelined ClientHello 字节
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		pipelined := make([]byte, clientBuf.Reader.Buffered())
		n, _ := io.ReadFull(clientBuf.Reader, pipelined)
		if n > 0 {
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
	go func() {
		defer release()
		relay(
			newDeadlineConn(clientConn, idleTimeout),
			newDeadlineConn(upConn, idleTimeout),
		)
	}()
}

// serveMITMConnect 在 CONNECT 隧道内用本地自签 CA 终结 TLS，并将解密后的 HTTP/1.1 或 HTTP/2 请求交由 ECH/SNI 反代引擎处理。
func serveMITMConnect(clientConn net.Conn, clientBuf *bufio.ReadWriter, targetHost string, opts ConnectOptions) {
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	wrapped := newPrefixConn(clientConn, clientBuf)
	baseTLS := opts.CertStore.TLSConfig(opts.PortalCert)
	tlsCfg := baseTLS.Clone()
	// 若客户端未发送 SNI，使用 CONNECT 请求行中的 targetHost 签发证书
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			hello.ServerName = targetHost
		}
		return baseTLS.GetCertificate(hello)
	}

	tlsConn := tls.Server(wrapped, tlsCfg)
	ctx, cancel := context.WithTimeout(context.Background(), netdial.DialTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		if !isExpectedConnError(err) && opts.CertStore != nil {
			log.Printf("[CONNECT MITM] TLS handshake for %s failed: %v (ensure %s is trusted)", targetHost, err, opts.CertStore.CAPath())
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
		h2Srv := &http2.Server{}
		h2Srv.ServeConn(tlsConn, &http2.ServeConnOpts{
			Handler: handler,
		})
		return
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
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

// relay 双向拷贝字节，任一方向结束或出错时立即关闭双端连接并退出（修复 B1 哑客户端连接泄漏）。
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

// isExpectedConnError 过滤隧道关闭时的常态网络断开错误，但绝不吞掉 TLS 证书等真实错误（B4）。
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
	for _, pat := range []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"unexpected eof",
		"forcibly closed by the remote host",
	} {
		if strings.Contains(s, pat) {
			return true
		}
	}
	return false
}

// prefixConn 将 Hijack 时已在 bufio.ReadWriter 中缓冲的字节无缝拼接到 net.Conn 前端。
type prefixConn struct {
	net.Conn
	r io.Reader
}

func newPrefixConn(c net.Conn, rw *bufio.ReadWriter) net.Conn {
	if rw != nil && rw.Reader.Buffered() > 0 {
		buf := make([]byte, rw.Reader.Buffered())
		n, _ := io.ReadFull(rw.Reader, buf)
		if n > 0 {
			return &prefixConn{
				Conn: c,
				r:    io.MultiReader(strings.NewReader(string(buf[:n])), c),
			}
		}
	}
	return c
}

func (p *prefixConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

// deadlineConn 在每次成功 Read/Write 后自动顺延空闲超时时间（DESIGN-tunnel-limits-and-android.md 第三层）。
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

// singleConnListener 向 http.Server.Serve 提供恰好一条连接。
// 第二次 Accept 会阻塞到该连接被关闭为止，避免 Serve 在请求仍在处理时
// 提前返回（并触发调用方关闭底层连接）导致 MITM 请求被截断为连接重置。
type singleConnListener struct {
	conn   net.Conn
	done   chan struct{}
	once   sync.Once
	closed sync.Once
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return &closeNotifyConn{Conn: c, done: l.done}, nil
	}
	<-l.done
	return nil, errors.New("singleConnListener: closed")
}

func (l *singleConnListener) Close() error {
	l.closed.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
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