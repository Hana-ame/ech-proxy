package certstore

import (
	"crypto/x509"
	"testing"
)

func TestCertGroupingDomainAndMultiLevelWildcardVerify(t *testing.T) {
	cases := []struct {
		host     string
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

	st, err := NewStore(t.TempDir())
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

	// 验证所有层级的域名签发出的证书都能通过标准库 x509.VerifyHostname + 信任链校验
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
}
