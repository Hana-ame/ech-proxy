package rewrite

import (
	"regexp"
	"strings"
)

// 本文件实现「EasyList 网络过滤子集」：
//
//   - 只取域名（||domain^）与 域名+path（||domain/path、|https://domain/path、/path/*）两类；
//   - 不实现 $options（third-party/script/image/...）、不实现 cosmetic（##）、不实现正则；
//   - @@ 例外规则与含 $ 选项的规则直接跳过（白名单完全由手动维护的 ads.txt 决定）。
//
// 匹配语义：host 命中（含父域后缀）且 path 片段包含即拦截；path 为空的规则表示整域拦截。
// 这与 uBO 的「网络过滤」方向一致（在请求发出前取消），但只保留最小可用子集。

// maxEasyListBytes 是 EasyList 文本的下载上限（easyList 约 2~3MB）。
const maxEasyListBytes = 32 << 20

// BlockRule 是化简后的拦截规则。
type BlockRule struct {
	Host string // 小写域名；空表示纯 path 规则
	Path string // 小写 path 片段；空表示整域拦截
}

// EasyListMatcher 是 EasyList 网络规则的索引化匹配器。
type EasyListMatcher struct {
	hostOnly  map[string]bool
	hostPaths map[string][]string
	pathOnly  []string
	ruleCount int
}

// RuleCount 返回成功归一的规则条数。
func (m *EasyListMatcher) RuleCount() int {
	if m == nil {
		return 0
	}
	return m.ruleCount
}

var easyHostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

// NormalizeEasyHost 归一化 EasyList 中的域名；非法（含通配/端口/非域名）返回空。
func NormalizeEasyHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.Trim(h, "|^")
	if strings.ContainsAny(h, "*/: ") || !easyHostRE.MatchString(h) {
		return ""
	}
	return h
}

// ParseEasyListNetworkRules 解析 EasyList 文本（仅网络过滤部分），返回索引化匹配器。
func ParseEasyListNetworkRules(raw []byte) *EasyListMatcher {
	m := &EasyListMatcher{
		hostOnly:  make(map[string]bool),
		hostPaths: make(map[string][]string),
	}
	if len(raw) == 0 || len(raw) > maxEasyListBytes {
		return m
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		// cosmetic / scriptlet / HTML 过滤器全部跳过
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") ||
			strings.Contains(line, "#?#") || strings.Contains(line, "#$#") || strings.Contains(line, "#%#") {
			continue
		}
		// 例外规则与选项规则跳过（白名单由 ads.js 决定）
		if strings.HasPrefix(line, "@@") || strings.Contains(line, "$") {
			continue
		}
		// 正则规则跳过
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
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

		hostPart, pathPart := splitEasyHostPath(rest)
		host := NormalizeEasyHost(hostPart)
		path := normalizeEasyPath(pathPart)

		switch {
		case host != "" && path == "":
			m.hostOnly[host] = true
			m.ruleCount++
		case host != "":
			m.hostPaths[host] = append(m.hostPaths[host], path)
			m.ruleCount++
		case path != "" && len(m.pathOnly) < 20000:
			m.pathOnly = append(m.pathOnly, path)
			m.ruleCount++
		}
	}
	return m
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
	// 通配符只取第一段字面前缀（如 /banner/*/img -> /banner/），避免把 * 删成 "//" 反而匹配不到。
	if i := strings.IndexByte(p, '*'); i >= 0 {
		p = p[:i]
	}
	p = strings.ReplaceAll(p, "^", "")
	return p
}

// Match 判断 host+path 是否命中 EasyList 网络规则。
func (m *EasyListMatcher) Match(host, path string) bool {
	if m == nil || len(m.hostOnly)+len(m.hostPaths)+len(m.pathOnly) == 0 {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(path)
	if host != "" {
		labels := strings.Split(host, ".")
		for i := 0; i < len(labels); i++ {
			suffix := strings.Join(labels[i:], ".")
			if m.hostOnly[suffix] {
				return true
			}
			if paths, ok := m.hostPaths[suffix]; ok {
				for _, p := range paths {
					if p == "" || strings.Contains(path, p) {
						return true
					}
				}
			}
		}
	}
	for _, p := range m.pathOnly {
		if p != "" && strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// AllowRule 是 ads.txt 中的放行项（域名 + 必填 path，精确到路径）。
type AllowRule struct {
	Host string
	Path string
}

// Allows 判断请求 host+path 是否被 ads.txt 白名单放行。
// 必须是 host 命中且 path 前缀命中 —— **不允许按域名整域放行**，避免把同域的其他广告一起放出来。
func Allows(rules []AllowRule, host, path string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(path)
	for _, r := range rules {
		if r.Host == "" || r.Path == "" || host == "" {
			continue
		}
		if !(host == r.Host || strings.HasSuffix(host, "."+r.Host)) {
			continue
		}
		rulePath := strings.ToLower(r.Path)
		if path == rulePath || strings.HasPrefix(path, rulePath) {
			return true
		}
	}
	return false
}

// ParseAdsAllowlistText 解析 ads.txt 形式的放行清单（**支持多行/续行**）：
//   - 一行一条：host/path 或 https://host/path 或 //host/path；
//   - 反斜杠续行（行尾 \）、以及「域名一行 + /path 下一行」的折行都会自动拼接；
//   - # 注释、空行忽略；
//   - 只写域名（没有 path）的行一律忽略 —— 禁止整域放行。
func ParseAdsAllowlistText(raw []byte) []AllowRule {
	var out []AllowRule
	seen := make(map[string]bool)

	text := string(raw)
	// 反斜杠续行
	text = strings.ReplaceAll(text, "\\\r\n", "")
	text = strings.ReplaceAll(text, "\\\n", "")

	pendingHost := ""
	add := func(host, path string) {
		host = NormalizeEasyHost(host)
		path = normalizeEasyPath(path)
		if host == "" || path == "" {
			return
		}
		key := host + "|" + path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, AllowRule{Host: host, Path: path})
	}

	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "#") {
			continue
		}
		// 折行：域名一行 + 下一行以 / 开头
		if strings.HasPrefix(s, "/") && pendingHost != "" {
			add(pendingHost, s)
			pendingHost = ""
			continue
		}
		pendingHost = ""
		if strings.HasPrefix(s, "//") {
			// 协议相对 URL；若 // 后不像域名则视为注释
			rest := strings.TrimPrefix(s, "//")
			if !strings.Contains(rest, ".") {
				continue
			}
			s = rest
		}
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
		host, path := splitEasyHostPath(s)
		if path == "" {
			// 先记住域名，若下一行以 / 开头则拼成一条；否则最终丢弃（禁止整域放行）
			if NormalizeEasyHost(host) != "" {
				pendingHost = host
			}
			continue
		}
		add(host, path)
	}
	return out
}
