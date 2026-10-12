package echproxy

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCertStoreGeneratesAndPersistsCA verifies that a fresh data directory gets
// a CA, and that a second CertStore over the same directory reuses it instead of
// generating a new one. Persisting the CA is what makes a browser's one-time
// trust survive an upgrade.
func TestCertStoreGeneratesAndPersistsCA(t *testing.T) {
	dir := t.TempDir()

	st, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}
	caPEM, err := os.ReadFile(st.CAPath())
	if err != nil {
		t.Fatalf("CA cert not persisted at %s: %v", st.CAPath(), err)
	}
	if len(caPEM) == 0 {
		t.Fatalf("CA cert file is empty")
	}

	st2, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("second NewCertStore: %v", err)
	}
	if st2.ca.Cert.SerialNumber.Cmp(st.ca.Cert.SerialNumber) != 0 {
		t.Fatalf("CA was regenerated on reload: serial %v != %v",
			st2.ca.Cert.SerialNumber, st.ca.Cert.SerialNumber)
	}
}

// TestCertStoreRefusesToOverwriteMalformedCA ensures a corrupt CA directory is
// not silently replaced. Replacing it here would invalidate every leaf the
// browser already trusts, which is a worse failure than refusing to start.
func TestCertStoreRefusesToOverwriteMalformedCA(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.pem"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertStore(dir); err == nil {
		t.Fatal("expected an error for a malformed CA directory, got nil")
	}
}

// TestCertStoreIssuesLeafForHost checks that the first request for a hostname
// produces a usable TLS certificate whose SANs cover the host and its
// subdomains, signed by the local CA.
func TestCertStoreIssuesLeafForHost(t *testing.T) {
	dir := t.TempDir()
	st, err := NewCertStore(dir)
	if err != nil {
		t.Fatalf("NewCertStore: %v", err)
	}

	cert, err := st.CertificateFor("www.pixiv.net")
	if err != nil {
		t.Fatalf("CertificateFor: %v", err)
	}

	// Verify the leaf chain validates against the CA pool.
	pool := x509.NewCertPool()
	pool.AddCert(st.ca.Cert)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := parsed.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "www.pixiv.net",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify for www.pixiv.net: %v", err)
	}

	// The same certificate must validate for a sibling subdomain, because the
	// SANs include the wildcard. This is what lets one issuance cover the whole
	// pixiv.net tree the user pointed at 127.0.0.1.
	if _, err := parsed.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "account.pixiv.net",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify for account.pixiv.net: %v", err)
	}

	// And it must NOT validate for an unrelated domain.
	if _, err := parsed.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "evil.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("leaf unexpectedly validates for an unrelated domain")
	}
}

// TestCertStorePersistsLeafAcrossReloads verifies the leaf is reused from disk,
// so the private key does not change between runs.
func TestCertStorePersistsLeafAcrossReloads(t *testing.T) {
	dir := t.TempDir()

	st1, err := NewCertStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := st1.CertificateFor("pixiv.net")
	if err != nil {
		t.Fatal(err)
	}
	p1 := c1.Leaf

	st2, err := NewCertStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := st2.CertificateFor("pixiv.net")
	if err != nil {
		t.Fatal(err)
	}
	p2 := c2.Leaf

	if p1.SerialNumber.Cmp(p2.SerialNumber) != 0 {
		t.Fatalf("leaf regenerated on reload: serial %v != %v", p1.SerialNumber, p2.SerialNumber)
	}
}

// TestCertStoreRefusesIPHostnames guards against accidentally issuing a
// certificate for an IP literal, which would let the proxy present a trusted
// certificate for 127.0.0.1 itself and defeat the redirect setup.
func TestCertStoreRefusesIPHostnames(t *testing.T) {
	st, err := NewCertStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "::1", "10.0.0.1"} {
		if _, err := st.CertificateFor(host); err == nil {
			t.Errorf("CertificateFor(%q) succeeded; want error", host)
		}
	}
}

// TestRegistrableDomain checks the last-two-labels heuristic the certificate
// lookup keys on.
func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"pixiv.net":         "pixiv.net",
		"www.pixiv.net":     "pixiv.net",
		"account.pixiv.net": "pixiv.net",
		"a.b.c.pixiv.net":   "pixiv.net",
		"localhost":         "localhost",
		"co.uk":             "co.uk",
	}
	for in, want := range cases {
		if got := registrableDomain(in); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSansFor confirms a wildcard is added only when the domain is not
// single-label, since "*.localhost" style SANs are rejected by some clients.
func TestSansFor(t *testing.T) {
	if got := sansFor("pixiv.net"); len(got) != 2 || got[0] != "pixiv.net" || got[1] != "*.pixiv.net" {
		t.Errorf("sansFor(pixiv.net) = %v", got)
	}
	if got := sansFor("localhost"); len(got) != 1 || got[0] != "localhost" {
		t.Errorf("sansFor(localhost) = %v", got)
	}
}

// TestCertificateForUsesExistingLeaf ensures a warm load does not re-issue (and
// therefore does not churn keys) for a host that was already issued in the same
// process.
func TestCertificateForUsesExistingLeaf(t *testing.T) {
	st, err := NewCertStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c1, err := st.CertificateFor("pixiv.net")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := st.CertificateFor("www.pixiv.net")
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Fatal("expected the same cached certificate for both pixiv.net and www.pixiv.net")
	}
}

// TestWriteFileAtomicFallsBackToRename verifies permissions are applied and the
// file is readable after the atomic write.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.pem")
	if err := writeFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".tmp-*")); err == nil && len(leftovers) > 0 {
		t.Errorf("leftover temp files: %v", leftovers)
	}
}

// TestCertStoreIssueNotBeforeIsBackdated makes sure a leaf issued at startup is
// already valid right now: a TLS handshake happening within seconds of
// generation must not fail with "certificate not yet valid".
func TestCertStoreIssueNotBeforeIsBackdated(t *testing.T) {
	st, err := NewCertStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := st.CertificateFor("pixiv.net")
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if time.Now().Before(leaf.NotBefore) {
		t.Errorf("leaf NotBefore %v is in the future", leaf.NotBefore)
	}
}
