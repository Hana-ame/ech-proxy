package echproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CONNECT tunnel support.
//
// A CONNECT tunnel is opaque at this layer: the client speaks TLS to the real
// origin inside the tunnel and this proxy never terminates it. That is
// deliberate — terminating TLS would present a certificate the browser does
// not trust, so the only correct implementation is byte-for-byte relay.
//
// Consequence, and it is a real functional limitation rather than a bug: with
// a tunnel open there is no place to rewrite response bodies, strip blocked
// hosts, inject a service worker, or manage cookies. Those features only work
// on the host-based reverse-proxy path.

// connectDialTimeout bounds the TCP connect to the upstream for a tunnel.
const connectDialTimeout = 15 * time.Second

// connectDialFn establishes the upstream side of a tunnel. It is a variable so
// tests can substitute a local listener; production code never reassigns it.
var connectDialFn = dialConnectTarget

// dialConnectTarget opens a plain TCP connection to host:port.
//
// It deliberately does NOT go through the ECH or SNI dialers. Those speak TLS
// themselves and expect to own the connection; a CONNECT tunnel needs an
// opaque byte pipe that the client terminates. Using them here would double-
// encrypt: the client would complete its TLS handshake with the proxy's inner
// TLS session instead of with the origin.
//
// ipMode is therefore not consulted here, exactly like the direct mode in
// proxyRoundTrip. Pinning the address family for tunnelled destinations is
// tracked as a known gap rather than silently ignored.
func dialConnectTarget(ctx context.Context, host string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: connectDialTimeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// handleConnect serves the CONNECT method: it hijacks the client connection,
// opens a TCP pipe to the requested origin, replies 200, then relays bytes in
// both directions until either side closes.
//
// The handler is only reachable when the request method is CONNECT, which the
// router routes here explicitly. It never triggers as a fallback, so an
// accidental CONNECT cannot silently degrade into a reverse-proxy request.
func handleConnect(c *gin.Context) {
	if c.Request.Method != http.MethodConnect {
		// Reached in the wrong place. Fail loudly rather than proxying.
		ApplyCORSHeaders(c.Writer.Header(), c.Request)
		c.String(http.StatusBadRequest, "CONNECT handler invoked with method %s", c.Request.Method)
		return
	}

	target, err := parseConnectTarget(c.Request.Host, c.Request.URL)
	if err != nil {
		ApplyCORSHeaders(c.Writer.Header(), c.Request)
		c.String(http.StatusBadRequest, "CONNECT %s: %v", c.Request.Host, err)
		return
	}

	hj, ok := c.Writer.(http.Hijacker)
	if !ok {
		// HTTP/2 has no hijack. RFC 8441 extended CONNECT would be the way to
		// support it; see the boundary notes.
		ApplyCORSHeaders(c.Writer.Header(), c.Request)
		c.String(http.StatusHTTPVersionNotSupported, "CONNECT requires HTTP/1.1, this connection is not hijackable")
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		// Headers are already written by Hijack on success, so we cannot send
		// a status here; closing is the only correct response.
		log.Printf("[connect] hijack failed for %s: %v", target, err)
		clientConn.Close()
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), connectDialTimeout)
	upstreamConn, err := connectDialFn(ctx, target.host, target.port)
	cancel()
	if err != nil {
		log.Printf("[connect] dial %s failed: %v", target, err)
		writeConnectError(clientConn, http.StatusBadGateway, "cannot reach "+target.String())
		return
	}

	// Anything the client pipelined after the CONNECT line is already sitting
	// in the hijacked read buffer. Dropping it would silently eat the first
	// bytes of the client's TLS ClientHello, which presents as a confusing
	// handshake failure on the client side.
	if clientBuf != nil && clientBuf.Reader.Buffered() > 0 {
		n, _ := io.CopyN(upstreamConn, clientBuf, int64(clientBuf.Reader.Buffered()))
		debugLogf("[connect] forwarded %d buffered bytes to %s", n, target)
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[connect] writing 200 to client for %s failed: %v", target, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	debugLogf("[connect] tunnel established %s", target)
	relay(clientConn, upstreamConn)
	log.Printf("[connect] tunnel closed %s", target)
}

// writeConnectError sends a minimal HTTP/1.1 error response on a hijacked
// connection, where the normal gin writer is no longer usable.
func writeConnectError(conn net.Conn, status int, msg string) {
	defer conn.Close()
	body := msg + "\n"
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

// relay copies bytes in both directions. It returns as soon as either
// direction finishes, then tears down both sides so the other direction
// cannot keep the tunnel alive.
//
// Returning on the first completion (rather than waiting for both) is the
// behaviour that matters for long-lived tunnels: when the origin closes the
// connection after a response, the client->upstream copy would otherwise sit
// blocked in Read forever and leak the connection.
func relay(client, upstream net.Conn) {
	done := make(chan struct{}, 2)

	copyFn := func(dst net.Conn, src net.Conn, dir string) {
		n, err := io.Copy(dst, src)
		if err != nil && !isExpectedConnError(err) {
			debugLogf("[connect] %s copy ended after %d bytes: %v", dir, n, err)
		}
		done <- struct{}{}
	}

	go copyFn(upstream, client, "client->upstream")
	go copyFn(client, upstream, "upstream->client")

	<-done
	// Unblock and terminate the opposite copy.
	client.Close()
	upstream.Close()
}

// isExpectedConnError filters out the errors that are a normal part of a
// tunnel closing, so the logs stay useful.
func isExpectedConnError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// A peer that vanishes mid-stream is routine, not a fault.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, expected := range []string{
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
		"unexpected eof",
		"eof",
	} {
		if strings.Contains(msg, expected) {
			return true
		}
	}
	return false
}

// connectTarget is a validated CONNECT destination.
type connectTarget struct {
	host string
	port int
}

func (t connectTarget) String() string {
	return net.JoinHostPort(t.host, strconv.Itoa(t.port))
}

// parseConnectTarget extracts host and port from a CONNECT request.
//
// RFC 9110 section 9.3.6 requires authority-form for CONNECT: "host:port".
// Some clients send it in RequestURI instead, so both are accepted, with
// RequestURI taking precedence when present.
func parseConnectTarget(hostHeader string, url *url.URL) (connectTarget, error) {
	authority := hostHeader
	if url != nil && url.Host != "" {
		authority = url.Host
	}
	if authority == "" {
		return connectTarget{}, errors.New("missing authority (expected host:port)")
	}

	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return connectTarget{}, fmt.Errorf("expected host:port, got %q", authority)
	}
	if host == "" {
		return connectTarget{}, errors.New("missing host")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return connectTarget{}, fmt.Errorf("invalid port %q", portStr)
	}
	if port < 1 || port > 65535 {
		return connectTarget{}, fmt.Errorf("port %d out of range", port)
	}
	// An IP literal in brackets is already unwrapped by SplitHostPort.
	return connectTarget{host: host, port: port}, nil
}

// tlsHandshakeThroughTunnel is used by tests and by any future caller that
// needs to prove a tunnel carries a real TLS session end to end. It exists so
// the "tunnel works" criterion is an actual handshake rather than a byte count.
func tlsHandshakeThroughTunnel(conn net.Conn, serverName string) (tls.ConnectionState, error) {
	tc := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	return tc.ConnectionState(), nil
}
