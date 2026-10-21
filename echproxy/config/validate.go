package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Severity 表示配置校验问题的严重级别。
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// ValidationIssue 描述单条配置校验发现的问题及其修复提示。
type ValidationIssue struct {
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Message  string   `json:"message"`
	Hint     string   `json:"hint,omitempty"`
}

func (v ValidationIssue) String() string {
	s := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(string(v.Severity)), v.Path, v.Message)
	if v.Hint != "" {
		s += fmt.Sprintf(" (%s)", v.Hint)
	}
	return s
}

var (
	knownTopLevelKeys = []string{
		"cert_path", "key_path", "ip_mode", "whitelist_url", "ad_script_url", "ad_script_disabled", "upstreams", "blocked_hosts",
	}
	knownEntryKeys = []string{
		"host", "describe", "display", "mode", "ip_mode", "sni_server_name",
		"referer", "origin", "x_site", "headers", "response_headers",
		"cookie", "cookie_file", "cookie_domain", "cookie_priority",
		"sw_inject", "rewrites", "body_replace", "wildcard",
	}
	knownWildcardKeys = []string{
		"prefix", "entry_suffix", "upstream_suffix", "entry", "upstream",
		"referer", "origin", "x_site", "headers", "response_headers",
		"cookie", "cookie_file", "cookie_domain", "cookie_priority",
		"mode", "ip_mode", "sni_server_name", "sw_inject", "rewrites", "body_replace",
	}

	validModes          = map[string]bool{"": true, "auto": true, "ech": true, "sni": true, "fragment": true, "bypass": true, "gfw": true, "direct": true}
	validIPModes        = map[string]bool{"": true, "auto": true, "dual": true, "v4": true, "ipv4": true, "4": true, "v6": true, "ipv6": true, "6": true}
	validCookiePriority = map[string]bool{"": true, "browser": true, "seed": true}
)

// Validate 对 upstream.json 原始字节执行严格静态校验，主动捕获 S1–S6 静默失败面。
// 该函数只读，绝不修改任何运行时状态。
func Validate(buf []byte) ([]ValidationIssue, error) {
	var rawRoot map[string]json.RawMessage
	if err := json.Unmarshal(buf, &rawRoot); err != nil {
		return nil, fmt.Errorf("invalid JSON syntax: %w", err)
	}

	var issues []ValidationIssue

	// 1. 校验顶层键名（捕获 S1/S5 未知键与拼写错误）
	for k := range rawRoot {
		if !containsExact(knownTopLevelKeys, k) {
			hint := ""
			if sug := suggestField(k, knownTopLevelKeys); sug != "" {
				hint = fmt.Sprintf("did you mean %q?", sug)
			}
			issues = append(issues, ValidationIssue{
				Severity: SeverityWarning,
				Path:     k,
				Message:  fmt.Sprintf("unknown top-level field %q", k),
				Hint:     hint,
			})
		}
	}

	// 校验顶层 ip_mode
	if rawIPMode, ok := rawRoot["ip_mode"]; ok {
		var ipMode string
		if err := json.Unmarshal(rawIPMode, &ipMode); err != nil {
			issues = append(issues, ValidationIssue{
				Severity: SeverityError,
				Path:     "ip_mode",
				Message:  "ip_mode must be a string",
			})
		} else {
			issues = append(issues, checkIPMode("ip_mode", ipMode)...)
		}
	}

	// 2. 校验 upstreams
	rawUpstreamsMsg, hasUpstreams := rawRoot["upstreams"]
	if !hasUpstreams {
		issues = append(issues, ValidationIssue{
			Severity: SeverityError,
			Path:     "upstreams",
			Message:  "missing required top-level field \"upstreams\"",
		})
		return sortIssues(issues), nil
	}

	var rawUpstreams map[string]json.RawMessage
	if err := json.Unmarshal(rawUpstreamsMsg, &rawUpstreams); err != nil || len(rawUpstreams) == 0 {
		issues = append(issues, ValidationIssue{
			Severity: SeverityError,
			Path:     "upstreams",
			Message:  "upstreams must be a non-empty JSON object",
		})
		return sortIssues(issues), nil
	}

	entryNames := make([]string, 0, len(rawUpstreams))
	for k := range rawUpstreams {
		entryNames = append(entryNames, k)
	}
	sort.Strings(entryNames)

	seenPortalHostTargets := make(map[string]string)

	for _, entry := range entryNames {
		entryPath := "upstreams." + entry
		var rawEntry map[string]json.RawMessage
		if err := json.Unmarshal(rawUpstreams[entry], &rawEntry); err != nil {
			issues = append(issues, ValidationIssue{
				Severity: SeverityError,
				Path:     entryPath,
				Message:  "entry must be a JSON object",
			})
			continue
		}

		for k := range rawEntry {
			if !containsExact(knownEntryKeys, k) {
				hint := ""
				if sug := suggestField(k, knownEntryKeys); sug != "" {
					hint = fmt.Sprintf("did you mean %q?", sug)
				}
				issues = append(issues, ValidationIssue{
					Severity: SeverityWarning,
					Path:     entryPath + "." + k,
					Message:  fmt.Sprintf("unknown field %q in upstream entry", k),
					Hint:     hint,
				})
			}
		}

		var uc UpstreamConfig
		if err := json.Unmarshal(rawUpstreams[entry], &uc); err != nil {
			issues = append(issues, ValidationIssue{
				Severity: SeverityError,
				Path:     entryPath,
				Message:  fmt.Sprintf("cannot decode upstream entry: %v", err),
			})
			continue
		}

		if strings.TrimSpace(uc.Host) == "" {
			issues = append(issues, ValidationIssue{
				Severity: SeverityError,
				Path:     entryPath + ".host",
				Message:  "upstream host must not be empty",
			})
		} else if IsPortalDomain(entry) {
			target := strings.ToLower(strings.TrimSpace(uc.Host))
			if prev, exists := seenPortalHostTargets[target]; exists {
				issues = append(issues, ValidationIssue{
					Severity: SeverityWarning,
					Path:     entryPath + ".host",
					Message:  fmt.Sprintf("duplicate upstream host %q (already used by %q)", uc.Host, prev),
				})
			} else {
				seenPortalHostTargets[target] = entry
			}
		}

		issues = append(issues, checkMode(entryPath+".mode", uc.Mode)...)
		issues = append(issues, checkIPMode(entryPath+".ip_mode", uc.IPMode)...)
		issues = append(issues, checkCookiePriority(entryPath+".cookie_priority", uc.CookiePriority)...)
		issues = append(issues, checkCookieFile(entryPath+".cookie_file", uc.CookieFile)...)
		issues = append(issues, checkHeaderRules(entryPath+".headers", uc.Headers)...)
		issues = append(issues, checkHeaderRules(entryPath+".response_headers", uc.ResponseHeaders)...)
		issues = append(issues, checkBodyReplaceRules(entryPath+".body_replace", uc.BodyReplace)...)

		if rawW, ok := rawEntry["wildcard"]; ok && string(rawW) != "null" {
			wPath := entryPath + ".wildcard"
			var rawWildcardMap map[string]json.RawMessage
			if err := json.Unmarshal(rawW, &rawWildcardMap); err != nil {
				issues = append(issues, ValidationIssue{
					Severity: SeverityError,
					Path:     wPath,
					Message:  "wildcard must be a JSON object",
				})
			} else {
				for wk := range rawWildcardMap {
					if !containsExact(knownWildcardKeys, wk) {
						hint := ""
						if sug := suggestField(wk, knownWildcardKeys); sug != "" {
							hint = fmt.Sprintf("did you mean %q?", sug)
						}
						issues = append(issues, ValidationIssue{
							Severity: SeverityWarning,
							Path:     wPath + "." + wk,
							Message:  fmt.Sprintf("unknown field %q in wildcard rule", wk),
							Hint:     hint,
						})
					}
				}
				if uc.Wildcard != nil {
					issues = append(issues, checkMode(wPath+".mode", uc.Wildcard.Mode)...)
					issues = append(issues, checkIPMode(wPath+".ip_mode", uc.Wildcard.IPMode)...)
					issues = append(issues, checkCookiePriority(wPath+".cookie_priority", uc.Wildcard.CookiePriority)...)
					issues = append(issues, checkCookieFile(wPath+".cookie_file", uc.Wildcard.CookieFile)...)
					issues = append(issues, checkHeaderRules(wPath+".headers", uc.Wildcard.Headers)...)
					issues = append(issues, checkHeaderRules(wPath+".response_headers", uc.Wildcard.ResponseHeaders)...)
					issues = append(issues, checkBodyReplaceRules(wPath+".body_replace", uc.Wildcard.BodyReplace)...)
				}
			}
		}
	}

	return sortIssues(issues), nil
}

func checkMode(path, mode string) []ValidationIssue {
	trimmed := strings.TrimSpace(mode)
	if validModes[trimmed] {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if validModes[lower] {
		return []ValidationIssue{{
			Severity: SeverityWarning,
			Path:     path,
			Message:  fmt.Sprintf("mode %q uses uppercase characters", mode),
			Hint:     fmt.Sprintf("use lowercase %q", lower),
		}}
	}
	return []ValidationIssue{{
		Severity: SeverityError,
		Path:     path,
		Message:  fmt.Sprintf("invalid mode %q", mode),
		Hint:     `valid values are "auto", "ech", "sni", "fragment", or "direct"`,
	}}
}

func checkIPMode(path, ipMode string) []ValidationIssue {
	trimmed := strings.TrimSpace(ipMode)
	if validIPModes[trimmed] {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if validIPModes[lower] {
		return []ValidationIssue{{
			Severity: SeverityError,
			Path:     path,
			Message:  fmt.Sprintf("non-canonical ip_mode %q", ipMode),
			Hint:     fmt.Sprintf("use lowercase %q", lower),
		}}
	}
	return []ValidationIssue{{
		Severity: SeverityError,
		Path:     path,
		Message:  fmt.Sprintf("invalid ip_mode %q", ipMode),
		Hint:     `valid values are "v4" (or "ipv4"/"4", default), "dual", or "v6" (or "ipv6"/"6")`,
	}}
}

func checkCookiePriority(path, cp string) []ValidationIssue {
	trimmed := strings.TrimSpace(cp)
	if validCookiePriority[trimmed] {
		return nil
	}
	return []ValidationIssue{{
		Severity: SeverityError,
		Path:     path,
		Message:  fmt.Sprintf("invalid cookie_priority %q", cp),
		Hint:     `valid values are "browser" or "seed"`,
	}}
}

func checkCookieFile(path, cf string) []ValidationIssue {
	p := strings.TrimSpace(strings.TrimPrefix(cf, "file://"))
	if p == "" {
		return nil
	}
	if filepath.IsAbs(p) || strings.Contains(p, "..") || strings.ContainsAny(p, "\r\n") {
		return []ValidationIssue{{
			Severity: SeverityError,
			Path:     path,
			Message:  fmt.Sprintf("unsafe cookie_file path %q (path traversal or absolute path prohibited)", cf),
			Hint:     "use a bare filename under certs/l.moonchan.xyz/",
		}}
	}
	return nil
}

func checkHeaderRules(path string, rules map[string]HeaderRule) []ValidationIssue {
	var issues []ValidationIssue
	for k, r := range rules {
		if len(r.Replace) >= 2 && r.Replace[0] != "" {
			if _, err := regexp.Compile(r.Replace[0]); err != nil {
				issues = append(issues, ValidationIssue{
					Severity: SeverityError,
					Path:     path + "." + k,
					Message:  fmt.Sprintf("invalid replace regex %q: %v", r.Replace[0], err),
				})
			}
		}
	}
	return issues
}

func checkBodyReplaceRules(path string, rules []BodyReplaceRule) []ValidationIssue {
	var issues []ValidationIssue
	for i, r := range rules {
		if r.Regex && r.Old != "" {
			if _, err := regexp.Compile(r.Old); err != nil {
				issues = append(issues, ValidationIssue{
					Severity: SeverityError,
					Path:     fmt.Sprintf("%s[%d]", path, i),
					Message:  fmt.Sprintf("invalid body_replace regex %q: %v", r.Old, err),
				})
			}
		}
	}
	return issues
}

// HasErrors 判断校验结果列表中是否存在 error 级别的问题。
func HasErrors(issues []ValidationIssue) bool {
	for _, iss := range issues {
		if iss.Severity == SeverityError {
			return true
		}
	}
	return false
}

// FormatIssues 将校验结果格式化为人类可读的多行报告（Error 排在 Warning 之前）。
func FormatIssues(issues []ValidationIssue) string {
	if len(issues) == 0 {
		return "OK: no issues found"
	}
	sorted := sortIssues(append([]ValidationIssue(nil), issues...))
	var errs, warns int
	var sb strings.Builder
	for _, iss := range sorted {
		if iss.Severity == SeverityError {
			errs++
		} else {
			warns++
		}
		sb.WriteString(iss.String())
		sb.WriteByte('\n')
	}
	sb.WriteString(fmt.Sprintf("Summary: %d error(s), %d warning(s)", errs, warns))
	return sb.String()
}

func sortIssues(issues []ValidationIssue) []ValidationIssue {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity == SeverityError
		}
		return issues[i].Path < issues[j].Path
	})
	return issues
}

func containsExact(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func suggestField(unknown string, candidates []string) string {
	u := strings.ToLower(unknown)
	best := ""
	bestDist := 4 // 仅当编辑距离 <= 3 时给出建议，避免无关词乱建议
	for _, c := range candidates {
		d := levenshtein(u, strings.ToLower(c))
		if d < bestDist {
			bestDist = d
			best = c
		}
	}
	return best
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}