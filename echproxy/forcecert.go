package echproxy

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"
)

// 本文件实现「强行访问」的会话级记忆、多 Token 并发容错与限速，用于约束 ?__ech_proxy_force_cert__=<token> 覆盖：
//
// 核心安全与可用性设计：
//   - 警告页签发一次性 token（仅在 ech-proxy 自己渲染的警告页 HTML 中出现，跨源脚本无法读取，恶意页面无法伪造）。
//   - 修复浏览器并发拉取 /favicon.ico 覆盖主页面 token 的边界问题：
//     每个 host 维护一组未过期的有效 token 集合（带 forceTokenTTL 有效期），因此即使浏览器在渲染主页面警告页后立即自动请求 /favicon.ico
//     触发了第二次警告页渲染，主页面按钮上的 token 依然有效，用户首次点击「强行访问」即可 100% 成功放行！
//   - 放行后该主机及其基础父域名在本会话内进入 approved 集合，后续页面内的图片、脚本、样式等子资源请求不再重复拦截。
//   - 内嵌伪造参数（如 ?__ech_proxy_force_cert__=1）因无匹配 token 绝不会触发放行。

const (
	// forceTokenTTL 待消费 token 的最长有效期。
	forceTokenTTL = 10 * time.Minute
	// forceTokenRatePerMin 每主机每分钟最多签发的 token 数（限速防刷）。
	forceTokenRatePerMin = 12
	// maxApprovedHosts 会话内已批准主机上限，超限整体清空。
	maxApprovedHosts = 256
)

// forceCertState 是「强行访问」的会话级状态（进程内、非持久化）。
type forceCertState struct {
	mu       sync.Mutex
	approved map[string]bool                 // 用户已强行访问批准的主机（本会话内不再校验其上游证书）
	tokens   map[string]map[string]time.Time // 警告页签发的一次性有效 token 集合（host -> token -> expiry）
	lastTok  map[string]string               // 最近一次签发的 token（供触发速率上限时同主机复用）
	issued   map[string][]time.Time
}

var forceCerts = newForceCertState()

func newForceCertState() *forceCertState {
	return &forceCertState{
		approved: make(map[string]bool),
		tokens:   make(map[string]map[string]time.Time),
		lastTok:  make(map[string]string),
		issued:   make(map[string][]time.Time),
	}
}

// issueForceToken 为 host 签发一个一次性「强行访问」token（嵌入警告页按钮 URL）。
func (s *forceCertState) issueForceToken(host string) string {
	host = lowerForceHost(host)
	if host == "" {
		return ""
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	// 清理已过期 token
	if tokMap, ok := s.tokens[host]; ok {
		for k, exp := range tokMap {
			if now.After(exp) {
				delete(tokMap, k)
			}
		}
	}

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
		if last := s.lastTok[host]; last != "" {
			if tokMap := s.tokens[host]; tokMap != nil {
				if exp, ok := tokMap[last]; ok && now.Before(exp) {
					return last
				}
			}
		}
		return ""
	}
	s.issued[host] = append(s.issued[host], now)

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b)
	if s.tokens[host] == nil {
		s.tokens[host] = make(map[string]time.Time)
	}
	s.tokens[host][tok] = now.Add(forceTokenTTL)
	s.lastTok[host] = tok
	return tok
}

// consumeForceToken 校验并一次性消费 token：匹配则把 host（及其父级基础域名）加入 approved 并返回 true。
func (s *forceCertState) consumeForceToken(host, token string) bool {
	host = lowerForceHost(host)
	token = strings.TrimSpace(token)
	if host == "" || token == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	tokMap := s.tokens[host]
	if len(tokMap) == 0 {
		return false
	}
	matchedKey := ""
	for candidate, exp := range tokMap {
		if now.After(exp) {
			delete(tokMap, candidate)
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			matchedKey = candidate
			break
		}
	}
	if matchedKey == "" {
		return false
	}

	delete(s.tokens, host)
	delete(s.lastTok, host)
	if len(s.approved) >= maxApprovedHosts {
		s.approved = make(map[string]bool)
	}
	s.approved[host] = true
	if base := baseRegistrableDomain(host); base != "" {
		s.approved["."+base] = true
	}
	return true
}

// isForceApproved 报告 host（或其同源父域名）是否在本会话内已被用户强行访问批准。
func (s *forceCertState) isForceApproved(host string) bool {
	host = lowerForceHost(host)
	if host == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.approved[host] {
		return true
	}
	if base := baseRegistrableDomain(host); base != "" && s.approved["."+base] {
		return true
	}
	return false
}

func lowerForceHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func baseRegistrableDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	if len(labels) >= 3 {
		lastTwo := labels[len(labels)-2] + "." + labels[len(labels)-1]
		switch lastTwo {
		case "co.jp", "ne.jp", "or.jp", "com.cn", "net.cn", "org.cn", "co.uk", "org.uk", "com.tw", "com.hk":
			return strings.Join(labels[len(labels)-3:], ".")
		}
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// reset 清空全部会话级状态（仅用于测试隔离）。
func (s *forceCertState) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.approved = make(map[string]bool)
	s.tokens = make(map[string]map[string]time.Time)
	s.lastTok = make(map[string]string)
	s.issued = make(map[string][]time.Time)
}
