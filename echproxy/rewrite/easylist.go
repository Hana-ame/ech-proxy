package rewrite

import (
	"regexp"
	"strings"
)

// 本文件实现 EasyList 网络请求拦截规则（仅在 domain 与 domain + path 上生效）。
// 严格不做任何 HTML 元素删除、Cosmetic 隐藏样式（##）、CSP 注入或参数篡改。

const maxEasyListBytes = 32 << 20

var easyHostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// EasyListMatcher 是 EasyList 规则集合（只做 domain 与 domain+path 网络过滤）。
type EasyListMatcher struct {
	hostOnly  map[string]bool
	hostPaths map[string][]string
	pathOnly  []string

	allowHostOnly  map[string]bool
	allowHostPaths map[string][]string

	ruleCount int
}

func newEasyListMatcher() *EasyListMatcher {
	return &EasyListMatcher{
		hostOnly:       make(map[string]bool),
		hostPaths:      make(map[string][]string),
		allowHostOnly:  make(map[string]bool),
		allowHostPaths: make(map[string][]string),
	}
}

// RuleCount 返回归一后的规则条数。
func (m *EasyListMatcher) RuleCount() int {
	if m == nil {
		return 0
	}
	return m.ruleCount
}

// NormalizeEasyHost 归一化域名；非法（含通配/端口/非域名）返回空。
func NormalizeEasyHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.Trim(h, "|^")
	if strings.ContainsAny(h, "*/: ") || !easyHostRE.MatchString(h) {
		return ""
	}
	return h
}

// ParseEasyListNetworkRules 解析 EasyList 文本，仅保留域名 (||domain^) 与域名+路径 (||domain/path, /path/*) 规则。
func ParseEasyListNetworkRules(raw []byte) *EasyListMatcher {
	m := newEasyListMatcher()
	if len(raw) == 0 || len(raw) > maxEasyListBytes {
		return m
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		// 忽略一切非网络规则（元素隐藏 ##、cosmetic 例外 #@#、以及各类特殊选择器语法）
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") ||
			strings.Contains(line, "#?#") || strings.Contains(line, "#@?#") ||
			strings.Contains(line, "#$#") || strings.Contains(line, "#@$#") ||
			strings.Contains(line, "#%#") || strings.Contains(line, "#@%#") {
			continue
		}

		isException := strings.HasPrefix(line, "@@")
		if isException {
			line = strings.TrimPrefix(line, "@@")
		}
		opts := ""
		if i := strings.IndexByte(line, '$'); i >= 0 {
			line, opts = line[:i], line[i+1:]
		}
		keep, denyAllow := parseEasyOptions(opts)
		if !keep {
			continue
		}

		rest := line
		rest = strings.TrimPrefix(rest, "||")
		rest = strings.TrimPrefix(rest, "|")
		rest = strings.TrimPrefix(rest, "http://")
		rest = strings.TrimPrefix(rest, "https://")
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		host, path := splitEasyHostPath(rest)
		host, path = NormalizeEasyHost(host), normalizeEasyPath(path)
		if host == "" && path == "" {
			continue
		}

		for _, d := range denyAllow {
			m.allowHostOnly[d] = true
		}

		switch {
		case isException:
			if host != "" && path == "" {
				m.allowHostOnly[host] = true
			} else if host != "" {
				m.allowHostPaths[host] = appendEasyUnique(m.allowHostPaths[host], path)
			}
			m.ruleCount++
		case host != "" && path == "":
			m.hostOnly[host] = true
			m.ruleCount++
		case host != "":
			m.hostPaths[host] = appendEasyUnique(m.hostPaths[host], path)
			m.ruleCount++
		case path != "" && len(m.pathOnly) < 20000:
			m.pathOnly = append(m.pathOnly, path)
			m.ruleCount++
		}
	}
	return m
}

func parseEasyOptions(opts string) (keep bool, denyAllow []string) {
	if strings.TrimSpace(opts) == "" {
		return true, nil
	}
	for _, o := range strings.Split(opts, ",") {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		key, val, hasVal := strings.Cut(o, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "important":
		case "badfilter":
			return false, nil
		case "denyallow":
			if hasVal {
				for _, h := range strings.Split(val, "|") {
					if n := NormalizeEasyHost(h); n != "" {
						denyAllow = append(denyAllow, n)
					}
				}
			}
		default:
			return false, nil
		}
	}
	return true, denyAllow
}

func splitEasyHostPath(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i:]
	}
	if i := strings.IndexByte(s, '^'); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func normalizeEasyPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "^" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "^")
	if i := strings.IndexByte(p, '*'); i >= 0 {
		p = p[:i]
	}
	return strings.ReplaceAll(p, "^", "")
}

func easyHostSuffixes(host string) []string {
	labels := strings.Split(host, ".")
	out := make([]string, 0, len(labels))
	for i := 0; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

func easyPathHit(path string, rule string) bool {
	return rule == "" || path == rule || strings.HasPrefix(path, rule)
}

// ShouldBlock 判断 host+path 是否命中 EasyList 规则（已考虑 @@ / $denyallow 例外）。
func (m *EasyListMatcher) ShouldBlock(host, path string) bool {
	if m == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(path)
	for _, suf := range easyHostSuffixes(host) {
		if m.allowHostOnly[suf] {
			return false
		}
		for _, p := range m.allowHostPaths[suf] {
			if easyPathHit(path, p) {
				return false
			}
		}
	}
	for _, suf := range easyHostSuffixes(host) {
		if m.hostOnly[suf] {
			return true
		}
		for _, p := range m.hostPaths[suf] {
			if easyPathHit(path, p) {
				return true
			}
		}
	}
	for _, p := range m.pathOnly {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func appendEasyUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
