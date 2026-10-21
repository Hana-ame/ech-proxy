// Package certstore 提供双轨 TLS 证书管理（修复 #21 完整信任链、多级子域/双后缀顶级域通配与 #5 握手告警去重）：
//  1. l.moonchan.xyz 及 *.l.moonchan.xyz 相关域名：使用公网受信证书。
//  2. 其余所有通过修改 hosts=127.0.0.1 或 HTTP CONNECT MITM 接入的域名（如 pixiv.net、api.sec.pixiv.net、i.pximg.net 等）：
//     使用本机自生成的根证书（ca/ca.pem, ca/ca.key）按需动态签发带完整信任链的通配符叶子证书。
package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

const (
	caCertName        = "ca.pem"
	caKeyName         = "ca.key"
	certsDir          = "certs"
	leafCertFile      = "fullchain.pem"
	leafKeyFile       = "privkey.pem"
	caValidDuration   = 10 * 365 * 24 * time.Hour
	leafValidDuration = 730 * 24 * time.Hour
	leafSerialMax     = 1 << 62
)

// 常见双标签公共后缀（eTLD），防止 www.dlsite.co.jp 被错误归并到 *.co.jp。
var multiPartPublicSuffixes = map[string]bool{
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.kr": true, "or.kr": true, "ne.kr": true,
	"com.tw": true, "org.tw": true, "edu.tw": true,
	"com.hk": true, "org.hk": true, "edu.hk": true,
	"com.au": true, "net.au": true, "org.au": true,
	"com.sg": true, "com.my": true, "co.nz": true, "com.br": true,
}

// LoadRemoteCert 从配置的 cert_path 和 key_path 加载公网 TLS 证书（用于 l.moonchan.xyz 及其子域名）。
func LoadRemoteCert(certPath, keyPath string) (*tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("missing cert_path or key_path in config")
	}
	certPEM, err := netdial.FetchBytes(certPath)
	if err != nil {
		return nil, fmt.Errorf("fetch certificate: %w", err)
	}
	keyPEM, err := netdial.FetchBytes(keyPath)
	if err != nil {
		return nil, fmt.Errorf("fetch key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse certificate key pair: %w", err)
	}
	return &cert, nil
}

// CA 表示本机自生成的根证书机构。
type CA struct {
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
	CertPath string
	KeyPath  string
}

// Store 管理本地自签名 CA 及按证书分组域名缓存的叶子证书。
type Store struct {
	mu      sync.Mutex
	DataDir string
	ca      *CA
	leaf    map[string]*tls.Certificate
}

// DefaultDataDir 返回默认的本地证书存储目录（优先可执行文件同级目录，不可写时回退至系统用户配置目录）。
func DefaultDataDir() (string, error) {
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine user config dir: %w", err)
	}
	if exeDir != "" && canWrite(exeDir) {
		return exeDir, nil
	}
	return filepath.Join(base, "ech-proxy"), nil
}

func canWrite(dir string) bool {
	if dir == "" {
		return false
	}
	probe, err := os.CreateTemp(dir, ".ech-proxy-write-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name) == nil
}

// NewStore 初始化本地证书仓库：若已存在 CA 则直接加载，否则自动生成并落盘（权限 0700/0600）。
func NewStore(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("certstore: empty data dir")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("certstore: create data dir %s: %w", dataDir, err)
	}

	st := &Store{
		DataDir: dataDir,
		leaf:    make(map[string]*tls.Certificate),
	}
	caPath := filepath.Join(dataDir, "ca", caCertName)
	keyPath := filepath.Join(dataDir, "ca", caKeyName)

	if ca, err := loadCA(caPath, keyPath); err == nil {
		st.ca = ca
		log.Printf("CA loaded: %s (valid until %s)", ca.Cert.Subject.CommonName, ca.Cert.NotAfter.Format("2006-01-02"))
		return st, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("certstore: cannot load CA from %s and will not overwrite it: %w", caPath, err)
	}

	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	if err := persistCA(ca, caPath, keyPath); err != nil {
		return nil, err
	}
	st.ca = ca
	log.Printf("CA generated: %s (valid until %s) -> %s", ca.Cert.Subject.CommonName, ca.Cert.NotAfter.Format("2006-01-02"), caPath)
	return st, nil
}

// CAPath 返回本地 CA 根证书文件的绝对路径。
func (st *Store) CAPath() string {
	return filepath.Join(st.DataDir, "ca", caCertName)
}

// CAPEM 返回本地 CA 根证书的 PEM 编码字节内容（供 /ca.pem 下载端点与 CLI 导出使用）。
func (st *Store) CAPEM() ([]byte, error) {
	if st == nil || st.ca == nil || st.ca.Cert == nil {
		return nil, errors.New("certstore: CA not initialized")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: st.ca.Cert.Raw}), nil
}

func (st *Store) CAValidUntil() time.Time {
	if st == nil || st.ca == nil {
		return time.Time{}
	}
	return st.ca.Cert.NotAfter
}

// TLSConfig 构建双轨分流的 tls.Config：
//   - 当客户端 SNI 为 l.moonchan.xyz 或 *.l.moonchan.xyz（且公网证书已加载）时，返回公网证书；
//   - 其余所有通过 hosts=127.0.0.1 或 CONNECT MITM 访问的域名（如 pixiv.net、api.sec.pixiv.net、i.pximg.net 等），
//     均由本地自签名 CA 动态签发证书。
func (st *Store) TLSConfig(portalCert *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := strings.ToLower(strings.TrimSpace(hello.ServerName))
			if (sni == "" || config.IsPortalDomain(sni)) && portalCert != nil {
				return portalCert, nil
			}
			if st != nil && sni != "" {
				return st.CertificateFor(sni)
			}
			if portalCert != nil {
				return portalCert, nil
			}
			return nil, errors.New("no TLS certificate available")
		},
	}
}

// CertificateFor 为指定域名返回或按需签发包含基域与 *.baseDomain 通配符及完整 CA 链的 TLS 证书（#21）。
func (st *Store) CertificateFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, errors.New("certstore: empty host")
	}
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("certstore: refusing to issue certificate for IP (%s)", host)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	key := certGroupingDomain(host)
	if c, ok := st.leaf[key]; ok {
		return c, nil
	}
	if leaf, err := st.loadLeaf(key); err == nil {
		st.leaf[key] = leaf
		return leaf, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("certstore: cannot load leaf for %s: %w", key, err)
	}

	cert, err := st.issueLeaf(key)
	if err != nil {
		return nil, err
	}
	st.leaf[key] = cert
	return cert, nil
}

// certGroupingDomain 计算用于签发通配符证书的分组基域：
//   - "pixiv.net"          -> "pixiv.net"      (SAN: pixiv.net, *.pixiv.net)
//   - "www.pixiv.net"      -> "pixiv.net"      (由 *.pixiv.net 覆盖)
//   - "api.sec.pixiv.net"  -> "sec.pixiv.net"  (SAN: sec.pixiv.net, *.sec.pixiv.net，修复 RFC 6125 单级通配限制)
//   - "dlsite.co.jp"       -> "dlsite.co.jp"   (识别双标签公共后缀 co.jp，避免签发非法的 *.co.jp)
//   - "www.dlsite.co.jp"   -> "dlsite.co.jp"   (由 *.dlsite.co.jp 覆盖)
func certGroupingDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	if len(labels) == 3 {
		lastTwo := labels[1] + "." + labels[2]
		if multiPartPublicSuffixes[lastTwo] {
			return host
		}
	}
	return strings.Join(labels[1:], ".")
}

func (st *Store) loadLeaf(domain string) (*tls.Certificate, error) {
	dir := filepath.Join(st.DataDir, certsDir, sanitizeDomain(domain))
	certPEM, err := os.ReadFile(filepath.Join(dir, leafCertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, leafKeyFile))
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (st *Store) issueLeaf(domain string) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(leafSerialMax))
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	sans := []string{domain}
	if strings.Contains(domain, ".") {
		sans = append(sans, "*."+domain)
	}
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	skid := sha1.Sum(pubBytes)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain, Organization: []string{"ech-proxy local CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(leafValidDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        st.ca.Cert.SubjectKeyId,
		DNSNames:              sans,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, st.ca.Cert, &key.PublicKey, st.ca.Key)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(st.DataDir, certsDir, sanitizeDomain(domain))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var fullchainPEM strings.Builder
	fullchainPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	fullchainPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: st.ca.Cert.Raw}))

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writeFileAtomic(filepath.Join(dir, leafCertFile), []byte(fullchainPEM.String()), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, leafKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair([]byte(fullchainPEM.String()), keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cBlock, rest := pem.Decode(certPEM)
	if cBlock == nil || len(rest) > 0 {
		return nil, fmt.Errorf("malformed CA cert %s", certPath)
	}
	caCert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, err
	}
	kBlock, rest := pem.Decode(keyPEM)
	if kBlock == nil || len(rest) > 0 {
		return nil, fmt.Errorf("malformed CA key %s", keyPath)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(kBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&caKey.PublicKey) {
		return nil, errors.New("CA key does not match CA certificate")
	}
	return &CA{Cert: caCert, Key: caKey, CertPath: certPath, KeyPath: keyPath}, nil
}

func generateCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(leafSerialMax))
	if err != nil {
		return nil, err
	}
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	skid := sha1.Sum(pubBytes)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ech-proxy local CA", Organization: []string{"ech-proxy"}, Country: []string{"US"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          skid[:],
		AuthorityKeyId:        skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: parsed, Key: key}, nil
}

func persistCA(ca *CA, certPath, keyPath string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	if err := writeFileAtomic(certPath, certPEM, 0o600); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.Key)})
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	ca.CertPath, ca.KeyPath = certPath, keyPath
	return nil
}

func sanitizeDomain(s string) string {
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			out.WriteRune(r)
		} else {
			out.WriteRune('_')
		}
	}
	if out.Len() == 0 {
		return "host"
	}
	return out.String()
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type tlsAlertFilterWriter struct {
	mu       sync.Mutex
	caPath   string
	lastHint time.Time
}

func (w *tlsAlertFilterWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "tls handshake error") &&
		(strings.Contains(lower, "unknown certificate") || strings.Contains(lower, "bad certificate") || strings.Contains(lower, "certificate unknown")) {
		w.mu.Lock()
		now := time.Now()
		shouldPrint := now.Sub(w.lastHint) >= 30*time.Second
		if shouldPrint {
			w.lastHint = now
		}
		w.mu.Unlock()
		if shouldPrint {
			log.Printf("[TLS CA Hint] Client rejected local CA certificate (%s). Please trust %q in your OS/Browser (Firefox: set security.enterprise_roots.enabled=true in about:config, or download /ca.pem from the portal).", msg, w.caPath)
		}
		return len(p), nil
	}
	// 过滤浏览器预连接空闲关闭产生的 EOF 噪点
	if strings.Contains(lower, "tls handshake error") && strings.HasSuffix(lower, ": eof") {
		return len(p), nil
	}
	log.Print(msg)
	return len(p), nil
}

// NewTLSAlertFilterLogger 创建带 TLS 未知证书告警聚合与排障引导的 http.Server ErrorLog（修复 #5）。
func NewTLSAlertFilterLogger(caPath string) *log.Logger {
	return log.New(&tlsAlertFilterWriter{caPath: caPath}, "", 0)
}