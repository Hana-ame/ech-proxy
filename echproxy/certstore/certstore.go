// Package certstore 提供高内聚的 TLS 证书管理组件（供 PAC 方案、443 方案与 8443 方案按需复用）：
//   - 本地自签 CA + 动态通配符叶子证书签发（Store，供 PAC 方案与 443 方案共享复用，存储于 <dataDir>/ca/ 下，与 certs/ 完全解耦）；
//   - 公网真实证书加载（LoadRemoteCert，仅供 8443 门户方案使用，certs/ 路径完全与 8443 方案相关）。
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
	leavesSubDir      = "leaves"
	leafCertFile      = "fullchain.pem"
	leafKeyFile       = "privkey.pem"
	caValidDuration   = 10 * 365 * 24 * time.Hour
	leafValidDuration = 730 * 24 * time.Hour
	leafSerialMax     = 1 << 62
)

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

// LoadRemoteCert 加载 8443 方案专属的公网真实证书（远端拉取失败时可静默回退至本地 certs/l.moonchan.xyz/）。
func LoadRemoteCert(certPath, keyPath string) (*tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("missing cert_path or key_path in config")
	}
	certPEM, err := netdial.FetchBytes(certPath)
	if err != nil {
		certPEM = readFallback8443File("fullchain.cer")
		if len(certPEM) == 0 {
			return nil, fmt.Errorf("fetch certificate: %w", err)
		}
	}
	keyPEM, err := netdial.FetchBytes(keyPath)
	if err != nil {
		keyPEM = readFallback8443File("privkey.pem")
		if len(keyPEM) == 0 {
			return nil, fmt.Errorf("fetch key: %w", err)
		}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse certificate key pair: %w", err)
	}
	return &cert, nil
}

func readFallback8443File(name string) []byte {
	for _, cand := range []string{
		filepath.Join("certs", "l.moonchan.xyz", name),
		filepath.Join("..", "certs", "l.moonchan.xyz", name),
	} {
		if b, err := os.ReadFile(cand); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}

type CA struct {
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
	CertPath string
	KeyPath  string
}

type Store struct {
	mu         sync.Mutex
	DataDir    string
	ca         *CA
	portalCert *tls.Certificate
	leaf       map[string]*tls.Certificate
}

func (st *Store) SetPortalCert(cert *tls.Certificate) {
	if st == nil {
		return
	}
	st.mu.Lock()
	st.portalCert = cert
	st.mu.Unlock()
}

func (st *Store) PortalCert() *tls.Certificate {
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.portalCert
}

// Stats 返回证书存储模块的概况指标（是否已载入根 CA、根 CA 路径及内存缓存的叶子证书数量）。
func (st *Store) Stats() (hasCA bool, caPath string, leafCount int) {
	if st == nil {
		return false, "", 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	hasCA = st.ca != nil && st.ca.Cert != nil
	if st.ca != nil {
		caPath = st.ca.CertPath
	}
	leafCount = len(st.leaf)
	return
}

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

func (st *Store) CAPath() string {
	return filepath.Join(st.DataDir, "ca", caCertName)
}

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

func (st *Store) TLSConfig(portalCert *tls.Certificate) *tls.Config {
	if st != nil && portalCert != nil {
		st.SetPortalCert(portalCert)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := netdial.CleanHost(hello.ServerName)
			pc := portalCert
			if st != nil && pc == nil {
				st.mu.Lock()
				pc = st.portalCert
				st.mu.Unlock()
			}
			if (sni == "" || config.IsPortalDomain(sni)) && pc != nil {
				return pc, nil
			}
			if st != nil && sni != "" {
				return st.CertificateFor(sni)
			}
			if pc != nil {
				return pc, nil
			}
			return nil, errors.New("no TLS certificate available")
		},
	}
}

func (st *Store) CertificateFor(host string) (*tls.Certificate, error) {
	host = netdial.CleanHost(host)
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

func certGroupingDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	if len(labels) == 3 && multiPartPublicSuffixes[labels[1]+"."+labels[2]] {
		return host
	}
	return strings.Join(labels[1:], ".")
}

func (st *Store) leafDir(domain string) string {
	return filepath.Join(st.DataDir, "ca", leavesSubDir, sanitizeDomain(domain))
}

func (st *Store) loadLeaf(domain string) (*tls.Certificate, error) {
	dir := st.leafDir(domain)
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
	skid := sha1.Sum(x509.MarshalPKCS1PublicKey(&key.PublicKey))

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
	dir := st.leafDir(domain)
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
	skid := sha1.Sum(x509.MarshalPKCS1PublicKey(&key.PublicKey))

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
			log.Printf("[TLS CA Hint] Client rejected local CA certificate (%s). Please trust %q in your OS/Browser.", msg, w.caPath)
		}
		return len(p), nil
	}
	if strings.Contains(lower, "tls handshake error") && strings.HasSuffix(lower, ": eof") {
		return len(p), nil
	}
	log.Print(msg)
	return len(p), nil
}

func NewTLSAlertFilterLogger(caPath string) *log.Logger {
	return log.New(&tlsAlertFilterWriter{caPath: caPath}, "", 0)
}