package certstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertGroupingDomainAndMultiLevelWildcardVerify(t *testing.T) {
	cases := []struct {
		host      string
		wantGroup string
	}{
		{"pixiv.net", "pixiv.net"},
		{"www.pixiv.net", "pixiv.net"},
		{"accounts.pixiv.net", "pixiv.net"},
		{"api.sec.pixiv.net", "sec.pixiv.net"},
		{"a.b.c.pixiv.net", "b.c.pixiv.net"},
		{"dlsite.co.jp", "dlsite.co.jp"},
		{"www.dlsite.co.jp", "dlsite.co.jp"},
		{"img.dlsite.co.jp", "dlsite.co.jp"},
		{"sub.img.dlsite.co.jp", "img.dlsite.co.jp"},
	}
	for _, tc := range cases {
		if got := certGroupingDomain(tc.host); got != tc.wantGroup {
			t.Errorf("certGroupingDomain(%q) = %q, want %q", tc.host, got, tc.wantGroup)
		}
	}

	dataDir := t.TempDir()
	st, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	caPEM, err := st.CAPEM()
	if err != nil || len(caPEM) == 0 {
		t.Fatalf("CAPEM failed: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse CAPEM")
	}

	// 验证所有层级的域名签发出的证书都能通过标准库 x509.VerifyHostname + 信任链校验，
	// 且本地 CA 叶子证书完全存储于 <dataDir>/ca/leaves/ 下，绝不触碰 certs/ 路径（certs/ 路径完全只与 8443 方案相关）。
	for _, tc := range cases {
		tlsCert, err := st.CertificateFor(tc.host)
		if err != nil {
			t.Fatalf("CertificateFor(%q) failed: %v", tc.host, err)
		}
		if len(tlsCert.Certificate) < 2 {
			t.Fatalf("CertificateFor(%q) chain length = %d, want >= 2", tc.host, len(tlsCert.Certificate))
		}
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			t.Fatalf("ParseCertificate(%q): %v", tc.host, err)
		}
		if err := leaf.VerifyHostname(tc.host); err != nil {
			t.Errorf("leaf certificate for %q failed VerifyHostname: %v (DNSNames=%v)", tc.host, err, leaf.DNSNames)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName: tc.host,
			Roots:   roots,
		}); err != nil {
			t.Errorf("leaf certificate for %q failed full chain Verify: %v", tc.host, err)
		}
	}

	if _, err := os.Stat(filepath.Join(dataDir, "certs")); !os.IsNotExist(err) {
		t.Errorf("local CA Store must not create or touch <dataDir>/certs (certs/ is strictly for 8443 scheme)")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "ca", "leaves")); err != nil {
		t.Errorf("expected local CA leaves under <dataDir>/ca/leaves, got err=%v", err)
	}
}

func TestCAHardeningAndExpiredLeafAutoRotation(t *testing.T) {
	dataDir := t.TempDir()
	st, err := NewStore(dataDir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if !st.ca.Cert.MaxPathLenZero || st.ca.Cert.MaxPathLen != 0 {
		t.Fatalf("expected root CA MaxPathLen=0 & MaxPathLenZero=true, got MaxPathLen=%d MaxPathLenZero=%v",
			st.ca.Cert.MaxPathLen, st.ca.Cert.MaxPathLenZero)
	}
	if leafValidDuration > 398*24*time.Hour {
		t.Fatalf("leafValidDuration %v exceeds 398-day browser ceiling", leafValidDuration)
	}

	// 写入一张已过期叶子证书到磁盘缓存，验证 CertificateFor 自动重新签发有效证书
	domain := "rotate-test.example"
	dir := st.leafDir(domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	expTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		DNSNames:     []string{domain, "*." + domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, expTmpl, st.ca.Cert, &key.PublicKey, st.ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: st.ca.Cert.Raw})...,
	)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, leafCertFile), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, leafKeyFile), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	fresh, err := st.CertificateFor(domain)
	if err != nil {
		t.Fatalf("CertificateFor expired cached leaf failed: %v", err)
	}
	parsed, err := x509.ParseCertificate(fresh.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.NotAfter.After(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("expected rotated fresh leaf cert, got NotAfter=%s", parsed.NotAfter)
	}
}
