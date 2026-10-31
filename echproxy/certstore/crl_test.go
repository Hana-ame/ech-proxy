package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestCRLAndCRLDP(t *testing.T) {
	dir, _ := os.MkdirTemp("", "cs")
	defer os.RemoveAll(dir)
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetCRLBaseURL("http://127.0.0.1:8443")

	cert, err := st.CertificateFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != "http://127.0.0.1:8443/crl" {
		t.Fatalf("bad CRL DP: %v", leaf.CRLDistributionPoints)
	}

	crlPEM, err := st.CRL()
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(crlPEM)
	if blk == nil || blk.Type != "X509 CRL" {
		t.Fatalf("bad CRL pem type=%v", blk)
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(st.ca.Cert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	if n := len(crl.RevokedCertificateEntries); n != 0 {
		t.Fatalf("expected empty CRL, got %d entries", n)
	}
}
