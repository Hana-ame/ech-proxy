package echproxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// 本文件实现「强行访问」的会话级记忆与限速，用于约束 ?__ech_proxy_force_cert__=<token> 覆盖：
//
// 风险：若放行仅凭 ?__ech_proxy_force_cert__=1 即生效，任意页面可内嵌该参数链接，诱导用户点击后
// 静默跳过上游证书校验（中间人可借此绕过警告）。
//
// 缓解（本文件）：
//   - 警告页签发一次性 token（host -> token），仅在 ech-proxy 自己渲染的警告页 HTML 中出现；
//     跨源脚本无法读取，恶意页面无法伪造。
//   - 放行须持有效 token（常数时间比较），且一次性消费；消费后该主机在本会话内进入 approved 集合，
//     后续子资源请求不再校验其上游证书（避免反复警告、保证可用性）。
//   - 限速：每主机每分钟最多签发 forceTokenRatePerMin 个 token，防止刷量与资源耗尽。
//   - 容量：approved 集合上限 maxApprovedHosts，超限整体清空（会话级兜底，极少触发）。
//
// thus 内嵌 ?__ech_proxy_force_cert__=1（无 token 或 token 不匹配）不会触发放行——
// 该请求照常走证书校验，证书不过则渲染警告页（不静默放行）。

const (
	// forceTokenTTL 待消费 token 的最长有效期。token 应在用户看到警告页后即时点击使用。
	forceTokenTTL = 5 * time.Minute
	// forceTokenRatePerMin 每主机每分钟最多签发的 token 数（限速防刷）。
	forceTokenRatePerMin = 6
	// maxApprovedHosts 会话内已批准主机上限，超限整体清空。
	maxApprovedHosts = 256
)

// forceCertState 是「强行访问」的会话级状态（进程内、非持久化）。
type forceCertState struct {
	mu       sync.Mutex
	approved map[string]bool   // 用户已强行访问批准的主机（本会话内不再校验其上游证书）
	tokens   map[string]string // 警告页签发的一次性 token（host -> token）
	issued   map[string][]time.Time
}

var forceCerts = newForceCertState()

func newForceCertState() *forceCertState {
	return &forceCertState{
		approved: make(map[string]bool),
		tokens:   make(map[string]string),
		issued:   make(map[string][]time.Time),
	}
}

// issueForceToken 为 host 签发一个一次性「强行访问」token（嵌入警告页按钮 URL）。
// 带限速：每主机每分钟最多 forceTokenRatePerMin 个；超限复用最近 token 或返回空（不渲染按钮）。
// 返回空串表示当前因限速不发新 token（调用方应渲染「稍后重试」而非按钮）。
func (s *forceCertState) issueForceToken(host string) string {
	host = lowerForceHost(host)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	recent := s.issued[host]
	cutoff := now.Add(-time.Minute)
	pruned := recent[:0]
	for _, t := range recent {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	s.issued[host] = pruned
	if len(pruned) >= forceTokenRatePerMin {
		if t, ok := s.tokens[host]; ok && t != "" {
			return t // 复用已签发 token
		}
		return ""
	}
	s.issued[host] = append(s.issued[host], now)

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)
	s.tokens[host] = tok
	return tok
}

// consumeForceToken 校验并一次性消费 token：匹配则把 host 加入 approved（会话内不再校验其上游证书）
// 并返回 true。常数时间比较。token 不存在/不匹配则返回 false（调用方不应放行）。
func (s *forceCertState) consumeForceToken(host, token string) bool {
	host = lowerForceHost(host)
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want, ok := s.tokens[host]
	if !ok || want == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(want), []byte(token)) != 1 {
		return false
	}
	delete(s.tokens, host)
	if len(s.approved) >= maxApprovedHosts {
		s.approved = make(map[string]bool)
	}
	s.approved[host] = true
	return true
}

// isForceApproved 报告 host 是否在本会话内已被用户强行访问批准。
func (s *forceCertState) isForceApproved(host string) bool {
	host = lowerForceHost(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.approved[host]
}

func lowerForceHost(h string) string {
	return strings.ToLower(strings.TrimSpace(h))
}

// reset 清空全部会话级状态（仅用于测试隔离）。
func (s *forceCertState) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approved = make(map[string]bool)
	s.tokens = make(map[string]string)
	s.issued = make(map[string][]time.Time)
}
