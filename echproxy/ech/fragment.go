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

type tcpFragmentConn struct {
	net.Conn
	mu         sync.Mutex
	firstWrite bool
	maxSegSize int
}

// newTCPFragmentConn 仅在 TCP 传输层对首包 ClientHello 进行分段发送（保持单条完整 TLS 记录头不变），
// 既能打碎 TCP 载荷中的 SNI 明文以绕过 GFW DPI，又对 DDoS-Guard（如 nyaa.si）等拒绝多条细碎 TLS 记录的源站 100% 兼容。
func newTCPFragmentConn(c net.Conn, maxSegSize int) net.Conn {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if maxSegSize <= 0 {
		maxSegSize = 32
	}
	return &tcpFragmentConn{
		Conn:       c,
		firstWrite: true,
		maxSegSize: maxSegSize,
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

// findSNISplitOffset 在 TLS ClientHello 的 payload（不含 5 字节 TLS 记录头）中定位 SNI 域名正中间的偏移量。
// 若未找到标准 SNI 扩展，则回退到 payload 的中间位置。
func findSNISplitOffset(payload []byte) int {
	// Handshake Header (4) + Version (2) + Random (32) = 38
	if len(payload) < 44 || payload[0] != 0x01 {
		return len(payload) / 2
	}
	pos := 38
	// Session ID
	if pos >= len(payload) {
		return len(payload) / 2
	}
	sidLen := int(payload[pos])
	pos += 1 + sidLen
	// Cipher Suites
	if pos+2 > len(payload) {
		return len(payload) / 2
	}
	csLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2 + csLen
	// Compression Methods
	if pos >= len(payload) {
		return len(payload) / 2
	}
	compLen := int(payload[pos])
	pos += 1 + compLen
	// Extensions Length
	if pos+2 > len(payload) {
		return len(payload) / 2
	}
	extTotalLen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2
	end := pos + extTotalLen
	if end > len(payload) {
		end = len(payload)
	}
	for pos+4 <= end {
		extType := int(payload[pos])<<8 | int(payload[pos+1])
		extLen := int(payload[pos+2])<<8 | int(payload[pos+3])
		pos += 4
		if pos+extLen > end {
			break
		}
		// Extension 0x0000 = server_name
		if extType == 0 && extLen >= 5 {
			// ServerNameList length (2) + NameType (1) + HostName length (2)
			nameLen := int(payload[pos+3])<<8 | int(payload[pos+4])
			nameStart := pos + 5
			if nameLen >= 2 && nameStart+nameLen <= pos+extLen {
				return nameStart + nameLen/2
			}
			return pos + extLen/2
		}
		pos += extLen
	}
	return len(payload) / 2
}

// splitClientHelloAtSNI 将单条 TLS ClientHello 记录精准在 SNI 域名正中间切分为 2 条合法的 TLS Handshake 记录。
// 避免切成数十条微小记录（如首包仅 4 字节）触发 DDoS-Guard (nyaa.si) / Nginx 的防畸形分片握手拒绝。
func splitClientHelloAtSNI(pkt []byte) [][]byte {
	if len(pkt) <= 5 || pkt[0] != 0x16 || pkt[1] != 0x03 {
		return [][]byte{pkt}
	}
	recLen := int(pkt[3])<<8 | int(pkt[4])
	if 5+recLen != len(pkt) || recLen <= 16 {
		return [][]byte{pkt}
	}
	verMajor, verMinor := pkt[1], pkt[2]
	payload := pkt[5:]
	splitOff := findSNISplitOffset(payload)
	if splitOff <= 8 || splitOff >= len(payload)-4 {
		splitOff = len(payload) / 2
	}

	makeRec := func(chunk []byte) []byte {
		rec := make([]byte, 5+len(chunk))
		rec[0], rec[1], rec[2] = 0x16, verMajor, verMinor
		rec[3], rec[4] = byte(len(chunk)>>8), byte(len(chunk))
		copy(rec[5:], chunk)
		return rec
	}
	return [][]byte{
		makeRec(payload[:splitOff]),
		makeRec(payload[splitOff:]),
	}
}

func writeInSegments(c net.Conn, data []byte, segSize int) error {
	if segSize <= 0 {
		segSize = 32
	}
	for len(data) > 0 {
		n := segSize
		if n > len(data) {
			n = len(data)
		}
		if _, err := c.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (fc *tlsFragmentConn) Write(b []byte) (int, error) {
	fc.mu.Lock()
	isFirst := fc.firstWrite
	fc.firstWrite = false
	fc.mu.Unlock()

	if !isFirst || len(b) <= 5 || b[0] != 0x16 {
		return fc.Conn.Write(b)
	}
	for _, rec := range splitClientHelloAtSNI(b) {
		if err := writeInSegments(fc.Conn, rec, fc.maxFragSize); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func (tc *tcpFragmentConn) Write(b []byte) (int, error) {
	tc.mu.Lock()
	isFirst := tc.firstWrite
	tc.firstWrite = false
	tc.mu.Unlock()

	if !isFirst || len(b) <= 5 || b[0] != 0x16 {
		return tc.Conn.Write(b)
	}
	payload := b[5:]
	splitOff := 5 + findSNISplitOffset(payload)
	if splitOff <= 5 || splitOff >= len(b) {
		splitOff = len(b) / 2
	}
	if err := writeInSegments(tc.Conn, b[:splitOff], tc.maxSegSize); err != nil {
		return 0, err
	}
	if err := writeInSegments(tc.Conn, b[splitOff:], tc.maxSegSize); err != nil {
		return 0, err
	}
	return len(b), nil
}

func FragmentDo(req *http.Request, ipMode ...string) (*http.Response, error) {
	mode := ""
	if len(ipMode) > 0 {
		mode = ipMode[0]
	}
	return roundTripUTLS(req, mode, "frag", "", func(c net.Conn) net.Conn {
		return newTLSFragmentConn(c, 32)
	})
}
