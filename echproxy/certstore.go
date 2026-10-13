// certstore.go generates and persists a local, self-signed certificate authority
// and per-host leaf certificates for the local reverse proxy mode.
//
// SECURITY RATIONALE — why ech-proxy generates its own certificates instead of
// downloading them:
//
// A TLS terminator that presents a certificate for a third-party domain is a
// supply-chain attack surface. If the leaf came from a remote source (a config
// URL, a CDN, a public git repo) then a compromised upstream could hand back a
// certificate for ANY hostname, and the browser would trust it: every byte of
// the "encrypted" traffic would become attacker-crafted content, with the user
// never seeing a warning. That is a worse failure mode than not having the
// feature at all.
//
// Self-generation eliminates the vector: the CA private key is created on this
// machine and never leaves it, so the only party able to forge a certificate is
// a process that already has read access to the data directory. The data
// directory is created 0700 and every certificate/key file is written 0600.
//
// The generated CA is not trusted by browsers by default. The user installs it
// into the system trust store once (see README, "Local reverse proxy mode");
// from that point the browser validates the proxy's leaf certificates against
// it, exactly like it validates a corporate MITM proxy.
package echproxy

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
)

const (
	caCertName = "ca.pem"
	caKeyName  = "ca.key"
	certsDir   = "certs"

	caValidDuration   = 10 * 365 * 24 * time.Hour
	leafValidDuration = 730 * 24 * time.Hour // 2 years, under common client ceilings
	leafSerialMax     = 1 << 62
	leafCertFile      = "fullchain.pem"
	leafKeyFile       = "privkey.pem"
)

// CA is a locally generated, self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey

	// CertPath / KeyPath are the on-disk locations, so the startup banner can
	// tell the user where to find the CA for system-trust installation.
	CertPath string
	KeyPath  string
}

// CertStore issues and caches TLS leaf certificates signed by a locally
// generated CA. The CA and every leaf are persisted to disk under DataDir and
// reused across restarts, so a browser that already trusts the CA keeps working
// after an upgrade instead of being prompted to re-trust.
type CertStore struct {
	mu sync.Mutex

	// DataDir is the root directory; layout is DataDir/{ca/, certs/<host>/}.
	DataDir string
	ca      *CA

	// leaf is keyed by the normalized (registrable) domain.
	leaf map[string]*tls.Certificate
}

// DefaultDataDir returns the directory that holds the local CA and the issued
// leaf certificates.
//
// The directory containing the executable comes first: the CA is the one file
// the user has to install into the system trust store (see README, "Local
// reverse proxy mode"), so it belongs next to the binary they downloaded and
// renamed to ".443.exe" — not buried under %AppData%. This also keeps the proxy
// self-contained when the user runs it from a single folder or a USB stick.
//
// If the executable directory cannot be written (the binary may sit in a
// read-only location such as C:\Windows\System32, or a read-only extraction
// folder) the fallback is the platform user config dir, which is always
// writable for the current user.
//
// Both paths are overridable with -data-dir or ECH_PROXY_DATA_DIR; this is only
// the fallback when neither is given.
func DefaultDataDir() (string, error) {
	exeDir := ""
	if exe, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exe)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine user config dir: %w", err)
	}
	return resolveDataDir(exeDir, filepath.Join(base, "ech-proxy")), nil
}

// resolveDataDir picks the executable's directory when it is writable and the
// fallback otherwise. It is split out from DefaultDataDir so the priority rule
// is testable without reaching into os.Executable.
func resolveDataDir(exeDir, fallback string) string {
	if exeDir != "" && canWrite(exeDir) {
		return exeDir
	}
	return fallback
}

// canWrite reports whether a probe file can be created and removed inside dir.
//
// Permission bits are meaningless on Windows (NTFS access is decided by ACLs,
// not by the 0700 field), so the only reliable cross-platform check is to
// actually try. The probe file is created 0600 and removed immediately; the
// call fails closed and returns false on any error — an unwritable directory
// must fall back to the user config dir rather than crash the proxy at startup.
func canWrite(dir string) bool {
	if dir == "" {
		return false
	}
	probe, err := os.CreateTemp(dir, ".ech-proxy-write-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		os.Remove(name)
		return false
	}
	return os.Remove(name) == nil
}

// NewCertStore loads an existing CA from dataDir, or generates and persists a
// fresh one on first run. Issued leaves are loaded from disk as they are
// requested (see CertificateFor).
func NewCertStore(dataDir string) (*CertStore, error) {
	if dataDir == "" {
		return nil, errors.New("certstore: empty data dir")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("certstore: create data dir %s: %w", dataDir, err)
	}

	st := &CertStore{
		DataDir: dataDir,
		leaf:    make(map[string]*tls.Certificate),
	}

	caPath := filepath.Join(dataDir, "ca", caCertName)
	keyPath := filepath.Join(dataDir, "ca", caKeyName)

	if ca, err := loadCA(caPath, keyPath); err == nil {
		st.ca = ca
		log.Printf("CA loaded: %s (%s)", ca.Cert.Subject.CommonName, ca.Cert.NotAfter.Format("2006-01-02"))
		return st, nil
	} else if !os.IsNotExist(err) {
		// A CA directory exists but is unreadable/malformed. Refuse to overwrite
		// it: replacing the CA here would silently invalidate every leaf the
		// browser already trusts. The user must inspect the directory by hand.
		return nil, fmt.Errorf("certstore: cannot load CA from %s/%s and will not overwrite it: %w",
			dataDir, caCertName, err)
	}

	log.Printf("No existing CA in %s — generating a new self-signed CA", filepath.Join(dataDir, "ca"))
	ca, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("certstore: generate CA: %w", err)
	}
	if err := st.persistCA(ca, caPath, keyPath); err != nil {
		return nil, err
	}
	st.ca = ca
	log.Printf("CA generated: %s (valid until %s)\n  CA cert for system trust: %s",
		ca.Cert.Subject.CommonName, ca.Cert.NotAfter.Format("2006-01-02"), caPath)
	return st, nil
}

// CAPath returns the on-disk path of the CA certificate, for the startup banner
// and README instructions.
func (st *CertStore) CAPath() string {
	return filepath.Join(st.DataDir, "ca", caCertName)
}

// CAValidUntil reports when the CA certificate stops being trusted, so an
// operator can plan a re-trust rotation.
func (st *CertStore) CAValidUntil() time.Time {
	if st.ca == nil {
		return time.Time{}
	}
	return st.ca.Cert.NotAfter
}

// CertificateFor returns a TLS certificate valid for host, issuing one on first
// use and persisting it so later runs reuse the same key pair.
//
// The issued certificate carries SANs for the registrable domain and its
// wildcard, so a single issuance covers the whole domain tree
// (pixiv.net + www.pixiv.net + account.pixiv.net + ...).
func (st *CertStore) CertificateFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil, errors.New("certstore: empty host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, fmt.Errorf("certstore: refusing to issue a certificate for an IP address (%s); "+
			"pass a hostname instead", host)
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	key := registrableDomain(host)
	if c, ok := st.leaf[key]; ok {
		return c, nil
	}

	leaf, _, err := st.loadLeaf(key)
	if err == nil {
		st.leaf[key] = leaf
		return leaf, nil
	}
	if !os.IsNotExist(err) {
		// Present but unreadable. Same reason as the CA: do not silently
		// regenerate, or the browser's trust would break mid-session.
		return nil, fmt.Errorf("certstore: cannot load leaf for %s: %w", key, err)
	}

	cert, path, err := st.issueLeaf(key, host)
	if err != nil {
		return nil, err
	}
	st.leaf[key] = cert
	log.Printf("Issued certificate for %s (SANs: %s) -> %s", host, strings.Join(sansFor(key), ", "), path)
	return cert, nil
}

// loadLeaf reads and parses a previously persisted leaf certificate. The
// returned path is the certificate file, reported so a read failure names the
// exact file.
func (st *CertStore) loadLeaf(domain string) (*tls.Certificate, string, error) {
	dir := filepath.Join(st.DataDir, certsDir, sanitizeDomain(domain))
	certPath := filepath.Join(dir, leafCertFile)
	keyPath := filepath.Join(dir, leafKeyFile)

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, certPath, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, keyPath, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, certPath, fmt.Errorf("parse %s/%s: %w", certPath, keyPath, err)
	}
	return &cert, certPath, nil
}

// issueLeaf signs a fresh leaf for domain (covering sansFor(domain)) with the
// local CA and persists it atomically.
func (st *CertStore) issueLeaf(domain, host string) (*tls.Certificate, string, error) {
	if st.ca == nil {
		return nil, "", errors.New("certstore: no CA loaded")
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(leafSerialMax))
	if err != nil {
		return nil, "", fmt.Errorf("certstore: random serial: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("certstore: generate key: %w", err)
	}

	sans := sansFor(domain)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"ech-proxy local CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(leafValidDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	if ip := net.ParseIP(domain); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, st.ca.Cert, &key.PublicKey, st.ca.Key)
	if err != nil {
		return nil, "", fmt.Errorf("certstore: sign leaf for %s: %w", domain, err)
	}

	dir := filepath.Join(st.DataDir, certsDir, sanitizeDomain(domain))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", fmt.Errorf("certstore: create leaf dir %s: %w", dir, err)
	}
	certPath := filepath.Join(dir, leafCertFile)
	keyPath := filepath.Join(dir, leafKeyFile)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := writeFileAtomic(certPath, certPEM, 0o600); err != nil {
		return nil, "", err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, "", err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("certstore: parse fresh leaf: %w", err)
	}
	return &tlsCert, certPath, nil
}

// loadCA reads a CA certificate and key from disk.
func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	blocks, rest := pem.Decode(certPEM)
	if blocks == nil || len(rest) > 0 {
		_ = rest
		return nil, fmt.Errorf("malformed CA certificate %s", certPath)
	}
	caCert, err := x509.ParseCertificate(blocks.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	kblock, rest := pem.Decode(keyPEM)
	if kblock == nil || len(rest) > 0 {
		_ = rest
		return nil, fmt.Errorf("malformed CA key %s", keyPath)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	pub, ok := caCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("CA certificate has an unexpected public key type %T (expected RSA)", caCert.PublicKey)
	}
	if !pub.Equal(&caKey.PublicKey) {
		return nil, fmt.Errorf("CA key does not match CA certificate")
	}

	return &CA{
		Cert:     caCert,
		Key:      caKey,
		CertPath: certPath,
		KeyPath:  keyPath,
	}, nil
}

// generateCA creates a fresh self-signed CA with a 10-year validity.
func generateCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, fmt.Errorf("CA serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ech-proxy local CA",
			Organization: []string{"ech-proxy"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign CA certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	return &CA{Cert: parsed, Key: key}, nil
}

// persistCA writes the CA certificate and key atomically with 0600 permissions.
func (st *CertStore) persistCA(ca *CA, certPath, keyPath string) error {
	caDir := filepath.Dir(certPath)
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return fmt.Errorf("certstore: create CA dir %s: %w", caDir, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	if err := writeFileAtomic(certPath, certPEM, 0o600); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.Key)})
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return err
	}
	ca.CertPath = certPath
	ca.KeyPath = keyPath
	return nil
}

// registrableDomain reduces a hostname to the last two labels (pixiv.net for
// www.pixiv.net). Single-label names return themselves. This is a heuristic,
// not a public-suffix lookup: for a local tool the tradeoff is right, because
// co.uk / com.au style domains are rare upstreams and the failure mode is only
// "one extra certificate issued per host" rather than a broken connection.
func registrableDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// sansFor returns the DNS SANs for a registrable domain: the domain itself plus
// its single-label wildcard, so every subdomain in the tree validates.
func sansFor(domain string) []string {
	sans := []string{domain}
	if strings.Contains(domain, ".") {
		sans = append(sans, "*."+domain)
	}
	return sans
}

// sanitizeDomain makes a filesystem-safe directory name for a hostname.
func sanitizeDomain(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	if out.Len() == 0 {
		return "host"
	}
	return out.String()
}

// writeFileAtomic writes data to path via a temp file + rename, so a crash or
// kill mid-write cannot leave a truncated certificate that the next run would
// try to parse. mode is applied to the temp file before the rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("certstore: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("certstore: write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("certstore: chmod %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("certstore: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("certstore: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("certstore: rename to %s: %w", path, err)
	}
	return nil
}
