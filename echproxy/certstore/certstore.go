// Package certstore 提供双模式 TLS 证书管理：
//  1. 8443 门户模式：加载远程或本地配置的公网证书（如 l.moonchan.xyz）。
//  2. 443 本地透明反代模式：在本机生成并持久化自签名根证书（ca/ca.pem, ca/ca.key），
//     并在 TLS 握手时通过 GetCertificate 回调为任意目标域名按需签发带通配符的叶子证书。
//
// 本模块仅依赖标准库与 netdial.FetchBytes。
package certstore

import (
	"crypto/rand"
	"crypto/rsa"
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

// LoadRemoteCert 从配置的 cert_path 和 key_path 加载公网 TLS 证书（用于 8443 模式及门户域名）。
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

// Store 管理 443 本地模式下的自签名 CA 及按域名缓存的叶子证书。
type Store struct {
	mu      sync.Mutex
	DataDir string
	ca      *CA
	leaf    map[string]*tls.Certificate
}

// DefaultDataDir 返回默认的本地证书存储目录：
// 优先使用可执行文件所在同级目录（方便用户直接找到 ca/ca.pem 安装），若不可写则退回系统用户配置目录。
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

func (st *Store) CAPath() string {
	return filepath.Join(st.DataDir, "ca", caCertName)
}

func (st *Store) CAValidUntil() time.Time {
	if st.ca == nil {
		return time.Time{}
	}
	return st.ca.Cert.NotAfter
}

// TLSConfig 构建 443 本地反向代理模式的 tls.Config：
// 门户域名（如 l.moonchan.xyz）保持使用公网证书，其余所有域名由本地 CA 动态签发证书。
func (st *Store) TLSConfig(portalHost string, portalCert *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == portalHost && portalCert != nil {
				return portalCert, nil
			}
			return st.CertificateFor(hello.ServerName)
		},
	}
}

// CertificateFor 为指定域名返回或按需签发包含主域名与 *.domain 通配符的 TLS 证书。
func (st *Store) CertificateFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, errors.New("certstore: empty host")
	}
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("certstore: refusing to issue certificate for IP (%s)", host)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	key := registrableDomain(host)
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
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain, Organization: []string{"ech-proxy local CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(leafValidDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writeFileAtomic(filepath.Join(dir, leafCertFile), certPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(dir, leafKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
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
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ech-proxy local CA", Organization: []string{"ech-proxy"}, Country: []string{"US"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
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

func registrableDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
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
