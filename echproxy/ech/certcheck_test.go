package cloudflare_ech

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// makeSelfSigned 生成一张自签叶证书（可控 DNS SAN 与有效期），用于「不可信链 / 过期 / 不一致」分支。
func makeSelfSigned(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ech-proxy-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c
}

// makeTestCA 生成一张自签 CA 证书 + 私钥，用于签发可信叶证书。
func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ech-proxy-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("ca CreateCertificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca Parse: %v", err)
	}
	return c, priv
}

// makeSignedLeaf 用 ca 签发一张可控 DNS SAN 与有效期的叶证书（用于「可信链」分支）。
func makeSignedLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf keygen: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf CreateCertificate: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("leaf Parse: %v", err)
	}
	return c
}

// TestValidateUpstreamCert 覆盖 SNI/ECH/Direct 通用上游证书校验各类分支：
// 过期 / 尚未生效 / 不一致 / 不可信链 / 可信链 / 通配符 / 强行访问 / 无证书 / 时间优先 / classify 非证书错误。
// 校验顺序：时间 -> 主机名 -> 信任链。
func TestValidateUpstreamCert(t *testing.T) {
	now := time.Now()
	realDomain := "truedomain.com"

	ca, caKey := makeTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	SetRootPoolOverride(pool)
	defer SetRootPoolOverride(nil)

	// 1. 过期 -> ErrCertExpired（时间优先于主机名/链）
	expired := makeSelfSigned(t, []string{realDomain}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{expired})
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("expired cert: want ErrCertExpired, got %v", err)
	}
	if kind, host, _, ok := ClassifyCertError(err); !ok || kind != "expired" || host != realDomain {
		t.Fatalf("classify expired: kind=%q host=%q ok=%v", kind, host, ok)
	}

	// 2. 尚未生效 -> ErrCertExpired
	notYet := makeSelfSigned(t, []string{realDomain}, now.Add(24*time.Hour), now.Add(48*time.Hour))
	if err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{notYet}); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("not-yet-valid cert: want ErrCertExpired, got %v", err)
	}

	// 3. 域名不一致（cert 给 fakedomain.com）-> ErrCertMismatch（主机名优先于链）
	other := makeSelfSigned(t, []string{"fakedomain.com"}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	err = validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{other})
	if !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("mismatched cert: want ErrCertMismatch, got %v", err)
	}
	if kind, host, _, ok := ClassifyCertError(err); !ok || kind != "mismatch" || host != realDomain {
		t.Fatalf("classify mismatch: kind=%q host=%q ok=%v", kind, host, ok)
	}

	// 4. 不可信链（自签叶，根池不含其签发者）-> ErrCertUntrusted
	untrusted := makeSelfSigned(t, []string{realDomain}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	err = validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{untrusted})
	if !errors.Is(err, ErrCertUntrusted) {
		t.Fatalf("untrusted cert: want ErrCertUntrusted, got %v", err)
	}
	if kind, host, _, ok := ClassifyCertError(err); !ok || kind != "chain" || host != realDomain {
		t.Fatalf("classify chain: kind=%q host=%q ok=%v", kind, host, ok)
	}

	// 5. 可信链（CA 签发，根池含该 CA）-> 放行
	trusted := makeSignedLeaf(t, ca, caKey, []string{realDomain}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	if err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{trusted}); err != nil {
		t.Fatalf("trusted chain should pass, got %v", err)
	}

	// 6. 通配符 + 可信链 -> 放行
	wild := makeSignedLeaf(t, ca, caKey, []string{"*.truedomain.com"}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	if err := validateUpstreamCert(context.Background(), "www.truedomain.com", []*x509.Certificate{wild}); err != nil {
		t.Fatalf("wildcard trusted cert should cover subdomain, got %v", err)
	}

	// 7. 强行访问覆盖 -> 即便过期/不可信也跳过
	ctx := WithAllowBadCert(context.Background())
	if err := validateUpstreamCert(ctx, realDomain, []*x509.Certificate{untrusted}); err != nil {
		t.Fatalf("WithAllowBadCert should bypass untrusted cert, got %v", err)
	}
	if err := validateUpstreamCert(ctx, realDomain, []*x509.Certificate{expired}); err != nil {
		t.Fatalf("WithAllowBadCert should bypass expired cert, got %v", err)
	}

	// 8. 无证书可校验 -> 放行
	if err := validateUpstreamCert(context.Background(), realDomain, nil); err != nil {
		t.Fatalf("no peer certs should pass, got %v", err)
	}

	// 9. 过期优先于不一致（时间客观无效时先判 expired）
	expiredAndOther := makeSelfSigned(t, []string{"fakedomain.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{expiredAndOther}); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("expired+wrong-domain: want ErrCertExpired (time first), got %v", err)
	}

	// 10. ClassifyCertError 对非证书错误返回 ok=false
	if _, _, _, ok := ClassifyCertError(errors.New("some network error")); ok {
		t.Fatalf("ClassifyCertError should return ok=false for non-cert errors")
	}
}
