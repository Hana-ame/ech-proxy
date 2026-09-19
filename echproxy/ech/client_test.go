package cloudflare_ech

import (
	"crypto/tls"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestWrapUTLSConn(t *testing.T) {
	// Create an in-memory net.Pipe to simulate underlying connection
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uConn := utls.UClient(c1, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_120)
	wrapped := WrapUTLSConn(uConn)

	// Verify wrapped connection implements net.Conn
	if _, ok := wrapped.(net.Conn); !ok {
		t.Fatalf("expected wrapped to implement net.Conn")
	}

	// Verify wrapped connection has ConnectionState() tls.ConnectionState
	type tlsStateProvider interface {
		ConnectionState() tls.ConnectionState
	}

	provider, ok := wrapped.(tlsStateProvider)
	if !ok {
		t.Fatalf("expected wrapped to implement ConnectionState() tls.ConnectionState")
	}

	cs := provider.ConnectionState()
	if cs.ServerName != "" && cs.ServerName != "example.com" {
		t.Errorf("unexpected ServerName: %s", cs.ServerName)
	}
}
