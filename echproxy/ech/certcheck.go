// Package cloudflare_ech 上游证书校验（SNI 伪装路径专用）。
//
// 为什么需要：MITM 模式下代理用本地 CA 覆盖了客户端证书，客户端无法再自行判断上游真实证书，
// 故由代理代为校验上游返回的证书。
//
// 为什么不比对 SNI/伪装域名：SNI 伪装下发的域名（fakedomain.com）与上游返回的证书域名
// 必然不同——证书域名是真实域名（truedomain.com）。因此校验对象是「返回的证书是否覆盖
// 真实请求域名」，而非是否匹配发送的假 SNI。伪装（假 SNI + InsecureSkipVerify）保持不变，
// 绝不牺牲。
//
// 校验项（两类，提示不同）：
//  1. 时间有效性（NotBefore/NotAfter）不过 -> ErrCertExpired（过期）
//  2. 主机名是否覆盖真实请求域名（leaf.VerifyHostname）不过 -> ErrCertMismatch（不一致）
//
// 不做证书链/信任根校验（用户未要求；自签等第三类情形按需另行扩展）。
package cloudflare_ech

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"crypto/x509"
)

var (
	// ErrCertExpired 上游证书已过期或尚未生效（时间有效性失败）。
	ErrCertExpired = errors.New("upstream certificate expired or not yet valid")
	// ErrCertMismatch 上游证书未覆盖真实请求域名（主机名不一致，可能遭遇中间人/走错服务器）。
	ErrCertMismatch = errors.New("upstream certificate does not match the requested domain")
)

// CertError 携带证书校验失败的具体上下文，Unwrap 到 ErrCertExpired 或 ErrCertMismatch。
type CertError struct {
	Host   string // 真实请求域名
	Kind   string // "expired" | "mismatch"
	Detail string // 人类可读细节
	err    error  // ErrCertExpired 或 ErrCertMismatch
}

func (e *CertError) Error() string {
	return fmt.Sprintf("upstream %s: %s: %s", e.Host, e.err, e.Detail)
}

func (e *CertError) Unwrap() error { return e.err }

// IsCertError 判断 err 是否为上游证书校验失败（过期或不匹配）。
func IsCertError(err error) bool {
	return errors.Is(err, ErrCertExpired) || errors.Is(err, ErrCertMismatch)
}

// ClassifyCertError 从（可能被 http2/url 包装的）错误中判定证书校验失败类型。
// 返回 kind ∈ {"expired","mismatch"}、host、detail 与是否命中。
// 优先 errors.As（走 CertError）；其次 errors.Is（%w 包装链）；最后字符串兜底
// （http2/url 可能未保留 Unwrap 链）。
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
	s := err.Error()
	if strings.Contains(s, ErrCertExpired.Error()) {
		return "expired", "", s, true
	}
	if strings.Contains(s, ErrCertMismatch.Error()) {
		return "mismatch", "", s, true
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
// 供测试与诊断使用。
func AllowBadCert(ctx context.Context) bool { return allowBadCert(ctx) }

// validateUpstreamCert 校验 SNI 伪装路径返回的上游叶证书：
//   - 时间有效性（NotBefore/NotAfter）不过 -> ErrCertExpired（过期）
//   - 主机名是否覆盖真实请求域名 realDomain（leaf.VerifyHostname）不过 -> ErrCertMismatch（不一致）
//
// 不比对假 SNI（伪装域名与证书域名必然不同）。ctx 携带 WithAllowBadCert 时直接放行（强行访问覆盖）。
// 无证书可校验时放行（不阻塞伪装路径）。
func validateUpstreamCert(ctx context.Context, realDomain string, peerCerts []*x509.Certificate) error {
	if allowBadCert(ctx) {
		return nil
	}
	if len(peerCerts) == 0 {
		return nil
	}
	leaf := peerCerts[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return &CertError{
			Host:   realDomain,
			Kind:   "expired",
			Detail: fmt.Sprintf("certificate not yet valid (NotBefore=%s)", leaf.NotBefore.Format(time.RFC3339)),
			err:    ErrCertExpired,
		}
	}
	if now.After(leaf.NotAfter) {
		return &CertError{
			Host:   realDomain,
			Kind:   "expired",
			Detail: fmt.Sprintf("certificate expired on %s", leaf.NotAfter.Format(time.RFC3339)),
			err:    ErrCertExpired,
		}
	}
	if err := leaf.VerifyHostname(realDomain); err != nil {
		return &CertError{
			Host:   realDomain,
			Kind:   "mismatch",
			Detail: fmt.Sprintf("certificate not valid for %s: %v (subject=%s, DNSNames=%v)", realDomain, err, leaf.Subject, leaf.DNSNames),
			err:    ErrCertMismatch,
		}
	}
	return nil
}
