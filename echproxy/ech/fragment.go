// Package cloudflare_ech 方式三（Mode 3）：通过 DoH 解析真实 IP + TLS ClientHello 分片（Record Fragmentation & TCP Segmentation）绕过 GFW DPI，
// 底层复用 sni.go 中的 roundTripUTLS（DoH 解析 + uTLS Chrome 指纹 + H2/H1.1 自适应连接池 + 证书核对）。
package cloudflare_ech

import (
	"net"
	"net/http"
	"sync"
)

type tlsFragmentConn struct {
	net.Conn
	mu          sync.Mutex
	firstWrite  bool
	maxFragSize int
}

func newTLSFragmentConn(c net.Conn, maxFragSize int) net.Conn {
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

func FragmentTLSClientHelloRecord(pkt []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = 32
	}
	if len(pkt) <= 5 || pkt[0] != 0x16 || pkt[1] != 0x03 {
		return [][]byte{pkt}
	}
	recLen := int(pkt[3])<<8 | int(pkt[4])
	if 5+recLen != len(pkt) || recLen <= 4 {
		return [][]byte{pkt}
	}
	verMajor, verMinor := pkt[1], pkt[2]
	payload := pkt[5:]

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
		rec[0], rec[1], rec[2] = 0x16, verMajor, verMinor
		rec[3], rec[4] = byte(len(chunk)>>8), byte(len(chunk))
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

	// TCP 记录分节（TCP Segmentation）：保持完整的单个合法 TLS ClientHello 格式不变，
	// 在 TCP 传输层拆为两段发出（配合 TCP_NODELAY），打散 GFW DPI 明文 SNI 嗅探，
	// 同时彻底兼容 DDoS-Guard、Cloudflare、Nginx 等对多 TLS Record 解析不健全的 WAF/反代源站。
	splitAt := fc.maxFragSize
	if splitAt <= 0 || splitAt >= len(b) {
		splitAt = 64
	}
	if splitAt >= len(b) {
		splitAt = len(b) / 2
	}
	if splitAt > 0 && splitAt < len(b) {
		if _, err := fc.Conn.Write(b[:splitAt]); err != nil {
			return 0, err
		}
		return fc.Conn.Write(b[splitAt:])
	}
	return fc.Conn.Write(b)
}

func FragmentDo(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	return roundTripUTLS(req, mode, "frag", "", func(c net.Conn) net.Conn {
		return newTLSFragmentConn(c, 64)
	})
}
