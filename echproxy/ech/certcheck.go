// Package cloudflare_ech 上游证书校验模块（统一服务于 SNI 伪装、ECH、TLS 分片绕过与 Direct 直连路径）。
//
// 为什么需要：
// 在 PAC + CONNECT MITM 本地 HTTPS 服务模式下，代理用本地自生成的 CA 证书与浏览器完成 TLS 握手，
// 浏览器无法直接看到上游源站回传的真实证书，因此必须由本代理在上游 TLS 握手完成后立即核对源站回传的证书：
//  1. 比较真实目标域名（truedomain.com，即伪装前的原始访问域名）与服务端回传证书是否一致（leaf.VerifyHostname）；
//  2. 检查服务端回传证书是否过期或尚未生效（NotBefore / NotAfter）；
//  3. 检查服务端回传证书链是否可信（leaf.Verify）。
//
// 当证书不一致或已过期时，返回结构化的 *CertError（区分 "expired" 与 "mismatch"），
// 由上层渲染对应的中文警告页并提供「强行访问」按钮。
package cloudflare_ech

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

var (
	// ErrCertExpired 上游证书已过期或尚未生效（时间有效性失败）。
	ErrCertExpired = errors.New("upstream certificate expired or not yet valid")
	// ErrCertMismatch 上游证书未覆盖真实请求域名（主机名不一致，可能遭遇中间人或连接到了错误的服务器）。
	ErrCertMismatch = errors.New("upstream certificate does not match the requested domain")
	// ErrCertUntrusted 上游证书链未通过系统根证书信任校验（自签 / 未知 CA / 中间证书缺失）。
	ErrCertUntrusted = errors.New("upstream certificate chain is not trusted by system roots")
)

// CertError 携带上游证书校验失败的完整上下文，Unwrap 到 ErrCertExpired / ErrCertMismatch / ErrCertUntrusted。
type CertError struct {
	Host      string    // 伪装前访问的真实目标域名（如 truedomain.com）
	Kind      string    // "expired" | "mismatch" | "chain"
	Subject   string    // 服务端回传证书的 Subject
	DNSNames  []string  // 服务端回传证书包含的 SAN 域名列表
	Issuer    string    // 服务端回传证书的签发机构
	NotBefore time.Time // 证书生效时间
	NotAfter  time.Time // 证书过期时间
	Detail    string    // 人类可读详细诊断信息
	err       error
}

func (e *CertError) Error() string {
	return fmt.Sprintf("upstream %s: %s: %s", e.Host, e.err, e.Detail)
}

func (e *CertError) Unwrap() error { return e.err }

// IsCertError 判断 err 是否为上游证书校验失败（过期 / 不一致 / 不可信）。
func IsCertError(err error) bool {
	return errors.Is(err, ErrCertExpired) || errors.Is(err, ErrCertMismatch) || errors.Is(err, ErrCertUntrusted)
}

// ClassifyCertError 从（可能被 http2/url 包装的）错误中判定证书校验失败类型。
// 返回 kind ∈ {"expired","mismatch","chain"}、host、detail 与是否命中。
func ClassifyCertError(err error) (kind, host, detail string, ok bool) {
	if err == nil {
		return "", "", "", false
	}
	var ce *CertError
	if errors.As(err, &ce) {
		return ce.Kind, ce.Host, ce.Detail, true
	}
	if errors.Is(err, ErrCertExpired) {
		return "expired", "", err.Error(), true
	}
	if errors.Is(err, ErrCertMismatch) {
		return "mismatch", "", err.Error(), true
	}
	if errors.Is(err, ErrCertUntrusted) {
		return "chain", "", err.Error(), true
	}
	s := err.Error()
	if strings.Contains(s, ErrCertExpired.Error()) {
		return "expired", "", s, true
	}
	if strings.Contains(s, ErrCertMismatch.Error()) {
		return "mismatch", "", s, true
	}
	if strings.Contains(s, ErrCertUntrusted.Error()) {
		return "chain", "", s, true
	}
	return "", "", "", false
}

// allowBadCertKey 是请求 Context 中的「强行访问」覆盖标记：命中时跳过上游证书校验。
type allowBadCertKey struct{}

// WithAllowBadCert 在请求 Context 中注入「强行访问」标记，使该请求跳过上游证书校验。
// 用于警告页的「强行访问」按钮：用户在看到过期/不一致警告后明确选择继续访问。
func WithAllowBadCert(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, allowBadCertKey{}, true)
}

func allowBadCert(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(allowBadCertKey{}).(bool)
	return v
}

// AllowBadCert 报告 ctx 是否携带「强行访问」标记（命中时跳过上游证书校验）。
func AllowBadCert(ctx context.Context) bool { return allowBadCert(ctx) }

// rootPoolOverride 仅用于测试：注入自定义根证书池以验证证书链通过/失败；nil 时使用系统根证书校验。
var rootPoolOverride atomic.Pointer[x509.CertPool]

// SetRootPoolOverride 设置（仅测试用）自定义根证书池；传 nil 恢复使用系统根证书校验。
func SetRootPoolOverride(pool *x509.CertPool) { rootPoolOverride.Store(pool) }

func normalizeCertDomain(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

// ValidateUpstreamCert 核对服务端回传的证书与伪装前访问的真实目标域名（realDomain，如 truedomain.com）：
//  1. 检查证书时间有效性（NotBefore / NotAfter）-> 若过期或尚未生效，返回 ErrCertExpired（kind="expired"）；
//  2. 比较 realDomain 与回传证书的域名（leaf.VerifyHostname(realDomain)）-> 若不一致，返回 ErrCertMismatch（kind="mismatch"）；
//  3. 校验服务端证书链是否受系统根证书信任 -> 若不可信，返回 ErrCertUntrusted（kind="chain"）。
func ValidateUpstreamCert(ctx context.Context, realDomain string, peerCerts []*x509.Certificate) error {
	return validateUpstreamCert(ctx, realDomain, peerCerts)
}

func validateUpstreamCert(ctx context.Context, realDomain string, peerCerts []*x509.Certificate) error {
	if allowBadCert(ctx) {
		return nil
	}
	if len(peerCerts) == 0 {
		return nil
	}
	realDomain = normalizeCertDomain(realDomain)
	if realDomain == "" {
		return nil
	}

	leaf := peerCerts[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return &CertError{
			Host:      realDomain,
			Kind:      "expired",
			Subject:   leaf.Subject.String(),
			DNSNames:  append([]string(nil), leaf.DNSNames...),
			Issuer:    leaf.Issuer.String(),
			NotBefore: leaf.NotBefore,
			NotAfter:  leaf.NotAfter,
			Detail: fmt.Sprintf("certificate for %s is not yet valid (NotBefore=%s, NotAfter=%s, now=%s)",
				realDomain, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339), now.Format(time.RFC3339)),
			err: ErrCertExpired,
		}
	}
	if now.After(leaf.NotAfter) {
		return &CertError{
			Host:      realDomain,
			Kind:      "expired",
			Subject:   leaf.Subject.String(),
			DNSNames:  append([]string(nil), leaf.DNSNames...),
			Issuer:    leaf.Issuer.String(),
			NotBefore: leaf.NotBefore,
			NotAfter:  leaf.NotAfter,
			Detail: fmt.Sprintf("certificate for %s expired on %s (NotBefore=%s, now=%s)",
				realDomain, leaf.NotAfter.Format(time.RFC3339), leaf.NotBefore.Format(time.RFC3339), now.Format(time.RFC3339)),
			err: ErrCertExpired,
		}
	}
	if err := leaf.VerifyHostname(realDomain); err != nil {
		return &CertError{
			Host:      realDomain,
			Kind:      "mismatch",
			Subject:   leaf.Subject.String(),
			DNSNames:  append([]string(nil), leaf.DNSNames...),
			Issuer:    leaf.Issuer.String(),
			NotBefore: leaf.NotBefore,
			NotAfter:  leaf.NotAfter,
			Detail: fmt.Sprintf("certificate does not match true domain %s: %v (cert Subject=%s, DNSNames=%v)",
				realDomain, err, leaf.Subject, leaf.DNSNames),
			err: ErrCertMismatch,
		}
	}

	// 证书链 / 信任根校验：
	// - 若单元测试通过 SetRootPoolOverride 注入了测试根池，则严格使用该池校验；
	// - 生产环境下（rootPoolOverride == nil），优先使用 Roots: nil 调用操作系统原生验证器
	//   （在 Windows 7~11 上调用 CryptoAPI CertGetCertificateChain，自动支持系统根证书库与 AIA 中间证书补全），
	//   若失败（如 Android/Termux 无标准系统证书目录）再回退使用 netdial.RootPool()。
	intermediates := x509.NewCertPool()
	for _, c := range peerCerts[1:] {
		intermediates.AddCert(c)
	}
	if overridePool := rootPoolOverride.Load(); overridePool != nil {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         overridePool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return &CertError{
				Host:      realDomain,
				Kind:      "chain",
				Subject:   leaf.Subject.String(),
				DNSNames:  append([]string(nil), leaf.DNSNames...),
				Issuer:    leaf.Issuer.String(),
				NotBefore: leaf.NotBefore,
				NotAfter:  leaf.NotAfter,
				Detail:    fmt.Sprintf("certificate chain not trusted by system roots: %v (issuer=%s)", err, leaf.Issuer),
				err:       ErrCertUntrusted,
			}
		}
		return nil
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         nil, // 使用 OS 原生根证书库（Windows CryptoAPI / macOS Security / Linux system roots）
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		if _, err2 := leaf.Verify(x509.VerifyOptions{
			Roots:         netdial.RootPool(),
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err2 != nil {
			return &CertError{
				Host:      realDomain,
				Kind:      "chain",
				Subject:   leaf.Subject.String(),
				DNSNames:  append([]string(nil), leaf.DNSNames...),
				Issuer:    leaf.Issuer.String(),
				NotBefore: leaf.NotBefore,
				NotAfter:  leaf.NotAfter,
				Detail:    fmt.Sprintf("certificate chain not trusted by system roots: %v (issuer=%s)", err, leaf.Issuer),
				err:       ErrCertUntrusted,
			}
		}
	}
	return nil
}
