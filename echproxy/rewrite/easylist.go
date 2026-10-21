package rewrite

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
)

// 本文件实现「EasyList 确定性可做子集」，作用域仅限 adult.txt 命中的站点
// （不做全站请求拦截；只用于这些站点的广告剥离、隐藏与参数/CSP 处理）。
//
// 做：
//   - 网络：||domain^、||domain/path、|https://domain/path、/path/*
//   - 例外：@@、$denyallow
//   - 选项：$important（等同普通）、$badfilter（丢弃该规则）、$removeparam、$csp
//   - cosmetic：##selector（通用/域限定/支持 ~domain 域排除）、#@#（cosmetic 例外）
//
// 不做（代理缺浏览器上下文，做了只能近似）：
//   - $third-party / $domain / $script / $image / $xhr / $frame 等请求上下文选项
//   - scriptlets(##+js)、procedural(#?#)、##^、$redirect、$header=

const maxEasyListBytes = 32 << 20

var (
	easyHostRE    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)
	htmlURLScanRE = regexp.MustCompile(`(?i)(?:https?:)?//([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?`)
)

// EasyListMatcher 是 EasyList 确定性规则集合。
type EasyListMatcher struct {
	hostOnly  map[string]bool
	hostPaths map[string][]string
	pathOnly  []string

	allowHostOnly  map[string]bool
	allowHostPaths map[string][]string

	removeParamsAll    []string
	removeParamsByHost map[string][]string

	cspAll    []string
	cspByHost map[string][]string

	cosmeticGeneric       []string
	cosmeticByDomain      map[string][]string
	cosmeticExceptGeneric map[string]bool
	cosmeticExceptDomain  map[string]map[string]bool

	ruleCount int
}

// RuleCount 返回归一后的规则条数。
func (m *EasyListMatcher) RuleCount() int {
	if m == nil {
		return 0
	}
	return m.ruleCount
}

func newEasyListMatcher() *EasyListMatcher {
	return &EasyListMatcher{
		hostOnly:              make(map[string]bool),
		hostPaths:             make(map[string][]string),
		allowHostOnly:         make(map[string]bool),
		allowHostPaths:        make(map[string][]string),
		removeParamsByHost:    make(map[string][]string),
		cspByHost:             make(map[string][]string),
		cosmeticByDomain:      make(map[string][]string),
		cosmeticExceptGeneric: make(map[string]bool),
		cosmeticExceptDomain:  make(map[string]map[string]bool),
	}
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

// ParseEasyListNetworkRules 解析 EasyList 文本，返回确定性规则集合。
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
		if strings.Contains(line, "#?#") || strings.Contains(line, "#@?#") ||
			strings.Contains(line, "#$#") || strings.Contains(line, "#@$#") ||
			strings.Contains(line, "#%#") || strings.Contains(line, "#@%#") {
			continue
		}
		if i := strings.Index(line, "#@#"); i >= 0 {
			domains, sel := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+3:])
			if sel == "" {
				continue
			}
			if domains == "" {
				m.cosmeticExceptGeneric[sel] = true
			} else {
				pos, neg := splitEasyDomainsWithNeg(domains)
				for _, d := range append(pos, neg...) {
					if m.cosmeticExceptDomain[d] == nil {
						m.cosmeticExceptDomain[d] = make(map[string]bool)
					}
					m.cosmeticExceptDomain[d][sel] = true
				}
			}
			m.ruleCount++
			continue
		}
		if i := strings.Index(line, "##"); i >= 0 {
			domains, sel := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+2:])
			if sel == "" {
				continue
			}
			if domains == "" {
				m.cosmeticGeneric = append(m.cosmeticGeneric, sel)
			} else {
				pos, neg := splitEasyDomainsWithNeg(domains)
				for _, d := range neg {
					if m.cosmeticExceptDomain[d] == nil {
						m.cosmeticExceptDomain[d] = make(map[string]bool)
					}
					m.cosmeticExceptDomain[d][sel] = true
				}
				if len(pos) == 0 && len(neg) > 0 {
					m.cosmeticGeneric = append(m.cosmeticGeneric, sel)
				} else {
					for _, d := range pos {
						m.cosmeticByDomain[d] = append(m.cosmeticByDomain[d], sel)
					}
				}
			}
			m.ruleCount++
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
		keep, removeParams, cspDirective, denyAllow := parseEasyOptions(opts)
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
		for _, p := range removeParams {
			if host != "" {
				m.removeParamsByHost[host] = appendEasyUnique(m.removeParamsByHost[host], p)
			} else {
				m.removeParamsAll = appendEasyUnique(m.removeParamsAll, p)
			}
		}
		if cspDirective != "" {
			if host != "" {
				m.cspByHost[host] = append(m.cspByHost[host], cspDirective)
			} else {
				m.cspAll = append(m.cspAll, cspDirective)
			}
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

// parseEasyOptions 只接受确定性选项；出现任何近似选项则整条丢弃。
func parseEasyOptions(opts string) (keep bool, removeParams []string, csp string, denyAllow []string) {
	if strings.TrimSpace(opts) == "" {
		return true, nil, "", nil
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
			return false, nil, "", nil
		case "removeparam":
			if hasVal && strings.TrimSpace(val) != "" {
				removeParams = append(removeParams, strings.TrimSpace(val))
			}
		case "csp":
			if hasVal && strings.TrimSpace(val) != "" {
				csp = strings.TrimSpace(val)
			}
		case "denyallow":
			if hasVal {
				for _, h := range strings.Split(val, "|") {
					if n := NormalizeEasyHost(h); n != "" {
						denyAllow = append(denyAllow, n)
					}
				}
			}
		default:
			return false, nil, "", nil
		}
	}
	return true, removeParams, csp, denyAllow
}

func splitEasyDomainsWithNeg(s string) (pos []string, neg []string) {
	for _, d := range strings.Split(s, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "~") {
			if norm := NormalizeEasyHost(strings.TrimPrefix(d, "~")); norm != "" {
				neg = append(neg, norm)
			}
			continue
		}
		if norm := NormalizeEasyHost(d); norm != "" {
			pos = append(pos, norm)
		}
	}
	return pos, neg
}

func appendEasyUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func splitEasyHostPath(s string) (host, path string) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func normalizeEasyPath(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
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

// ShouldBlock 判断 host+path 是否命中（已含 @@ / $denyallow 例外）。
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

// RemoveParamsFor 返回该 host 需移除的 query 参数（含通用规则）。
func (m *EasyListMatcher) RemoveParamsFor(host string) []string {
	if m == nil {
		return nil
	}
	host = strings.ToLower(strings.TrimSpace(host))
	out := append([]string(nil), m.removeParamsAll...)
	for _, suf := range easyHostSuffixes(host) {
		out = append(out, m.removeParamsByHost[suf]...)
	}
	return out
}

// CSPFor 返回该 host 需附加的 CSP 指令。
func (m *EasyListMatcher) CSPFor(host string) []string {
	if m == nil {
		return nil
	}
	host = strings.ToLower(strings.TrimSpace(host))
	out := append([]string(nil), m.cspAll...)
	for _, suf := range easyHostSuffixes(host) {
		out = append(out, m.cspByHost[suf]...)
	}
	return out
}

// CosmeticFor 返回该 host 生效的 cosmetic 选择器（通用 + 域限定 − #@# / ~domain 例外）。
func (m *EasyListMatcher) CosmeticFor(host string) []string {
	if m == nil {
		return nil
	}
	host = strings.ToLower(strings.TrimSpace(host))
	suffixes := easyHostSuffixes(host)
	var out []string
	seen := make(map[string]bool)
	isExcepted := func(sel string) bool {
		if m.cosmeticExceptGeneric[sel] {
			return true
		}
		for _, suf := range suffixes {
			if ex := m.cosmeticExceptDomain[suf]; ex != nil && ex[sel] {
				return true
			}
		}
		return false
	}
	add := func(sel string) {
		if sel == "" || seen[sel] || isExcepted(sel) {
			return
		}
		seen[sel] = true
		out = append(out, sel)
	}
	for _, sel := range m.cosmeticGeneric {
		add(sel)
	}
	for _, suf := range suffixes {
		for _, sel := range m.cosmeticByDomain[suf] {
			add(sel)
		}
	}
	return out
}

// CosmeticStyle 生成隐藏样式（仅在命中 cosmetic 规则时返回非空）。
func (m *EasyListMatcher) CosmeticStyle(host string) string {
	sels := m.CosmeticFor(host)
	if len(sels) == 0 {
		return ""
	}
	sort.Strings(sels)
	return `<style id="ech-proxy-easylist-style">` + strings.Join(sels, ",") +
		`{display:none!important;visibility:hidden!important;height:0!important;max-height:0!important;overflow:hidden!important;pointer-events:none!important;}</style>`
}

// StripMatchedURLs 扫描 HTML 中的 URL，命中 EasyList（域名/域名+path）即从文档移除。
func (m *EasyListMatcher) StripMatchedURLs(body []byte) ([]byte, int) {
	if m == nil || len(body) == 0 {
		return body, 0
	}
	found := make(map[string]bool)
	var hits []string
	for _, mt := range htmlURLScanRE.FindAllSubmatch(body, -1) {
		host := strings.ToLower(string(mt[1]))
		path := ""
		if len(mt) > 2 {
			path = string(mt[2])
		}
		if host == "" || m.allowHostOnly[host] || !m.ShouldBlock(host, path) {
			continue
		}
		lit := string(mt[0])
		if lit != "" && !found[lit] {
			found[lit] = true
			hits = append(hits, lit)
		}
		if len(hits) >= 512 {
			break
		}
	}
	if len(hits) == 0 {
		return body, 0
	}
	out := body
	for _, h := range hits {
		out = stripOneBlockedURL(out, []byte(h))
		if i := strings.Index(h, "://"); i >= 0 {
			out = stripOneBlockedURL(out, []byte("//"+h[i+3:]))
		}
	}
	return out, len(hits)
}

// StripEscapedURLs 处理 JS 字符串里被转义的 URL（\/\/host\/path），仅剥离命中的转义广告 URL，保留其余 `<\/script>` 与正则转义。
func (m *EasyListMatcher) StripEscapedURLs(body []byte) ([]byte, int) {
	if m == nil || len(body) == 0 || !bytes.Contains(body, []byte(`\/\/`)) {
		return body, 0
	}
	unescaped := bytes.ReplaceAll(body, []byte(`\/`), []byte("/"))
	found := make(map[string]bool)
	var hits []string
	for _, mt := range htmlURLScanRE.FindAllSubmatch(unescaped, -1) {
		host := strings.ToLower(string(mt[1]))
		path := ""
		if len(mt) > 2 {
			path = string(mt[2])
		}
		if host == "" || m.allowHostOnly[host] || !m.ShouldBlock(host, path) {
			continue
		}
		lit := string(mt[0])
		if lit != "" && !found[lit] {
			found[lit] = true
			hits = append(hits, lit)
		}
		if len(hits) >= 512 {
			break
		}
	}
	if len(hits) == 0 {
		return body, 0
	}
	out := body
	for _, h := range hits {
		escH := strings.ReplaceAll(h, "/", `\/`)
		out = stripOneBlockedURL(out, []byte(escH))
		if i := strings.Index(h, "://"); i >= 0 {
			escProtoRel := `\/\/` + strings.ReplaceAll(h[i+3:], "/", `\/`)
			out = stripOneBlockedURL(out, []byte(escProtoRel))
		}
	}
	return out, len(hits)
}
