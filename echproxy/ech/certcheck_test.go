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

// makeTestCert 生成一张自签证书（可控 DNS SAN 与有效期），仅用于单元测试。
func makeTestCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) *x509.Certificate {
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

// TestValidateUpstreamCert 覆盖 SNI 伪装路径返回证书校验的各类分支：
// 过期 / 尚未生效 / 域名不一致 / 域名一致 / 通配符 / 强行访问覆盖 / 无证书 / 时间优先于不一致。
func TestValidateUpstreamCert(t *testing.T) {
	now := time.Now()
	realDomain := "truedomain.com"

	// 1. 过期 -> ErrCertExpired
	expired := makeTestCert(t, []string{realDomain}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{expired})
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("expired cert: want ErrCertExpired, got %v", err)
	}
	if kind, host, _, ok := ClassifyCertError(err); !ok || kind != "expired" || host != realDomain {
		t.Fatalf("classify expired: kind=%q host=%q ok=%v", kind, host, ok)
	}

	// 2. 尚未生效 -> ErrCertExpired
	notYet := makeTestCert(t, []string{realDomain}, now.Add(24*time.Hour), now.Add(48*time.Hour))
	if err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{notYet}); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("not-yet-valid cert: want ErrCertExpired, got %v", err)
	}

	// 3. 域名不一致（cert 给 fakedomain.com）-> ErrCertMismatch
	other := makeTestCert(t, []string{"fakedomain.com"}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	err = validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{other})
	if !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("mismatched cert: want ErrCertMismatch, got %v", err)
	}
	if kind, host, _, ok := ClassifyCertError(err); !ok || kind != "mismatch" || host != realDomain {
		t.Fatalf("classify mismatch: kind=%q host=%q ok=%v", kind, host, ok)
	}

	// 4. 域名一致 + 时间有效 -> 放行
	good := makeTestCert(t, []string{realDomain}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	if err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{good}); err != nil {
		t.Fatalf("valid cert should pass, got %v", err)
	}

	// 5. 通配符覆盖子域 -> 放行
	wild := makeTestCert(t, []string{"*.truedomain.com"}, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	if err := validateUpstreamCert(context.Background(), "www.truedomain.com", []*x509.Certificate{wild}); err != nil {
		t.Fatalf("wildcard cert should cover subdomain, got %v", err)
	}

	// 6. 「强行访问」覆盖 -> 即便过期或不一致也跳过
	ctx := WithAllowBadCert(context.Background())
	if err := validateUpstreamCert(ctx, realDomain, []*x509.Certificate{other}); err != nil {
		t.Fatalf("WithAllowBadCert should bypass mismatched cert, got %v", err)
	}
	if err := validateUpstreamCert(ctx, realDomain, []*x509.Certificate{expired}); err != nil {
		t.Fatalf("WithAllowBadCert should bypass expired cert, got %v", err)
	}

	// 7. 无证书可校验 -> 放行（不阻塞伪装路径）
	if err := validateUpstreamCert(context.Background(), realDomain, nil); err != nil {
		t.Fatalf("no peer certs should pass, got %v", err)
	}

	// 8. 过期优先于不一致：时间客观无效时先判 expired
	expiredAndOther := makeTestCert(t, []string{"fakedomain.com"}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err := validateUpstreamCert(context.Background(), realDomain, []*x509.Certificate{expiredAndOther}); !errors.Is(err, ErrCertExpired) {
		t.Fatalf("expired+wrong-domain: want ErrCertExpired (time first), got %v", err)
	}

	// 9. ClassifyCertError 对非证书错误返回 ok=false
	if _, _, _, ok := ClassifyCertError(errors.New("some network error")); ok {
		t.Fatalf("ClassifyCertError should return ok=false for non-cert errors")
	}
}
