package echproxy

import (
	"bytes"
	"sort"
	"strings"
)

// buildEntryRewriter constructs a response domain rewriter from a single UpstreamConfig:
// Exact rewrites are used as-is; wildcard entries are automatically deduced if wildcard is present;
// body_replace executes generic text or regex replacement rules.
// blocked is the global list of excluded domains (Config.BlockedHosts, configurable in upstream.json).
func buildEntryRewriter(uc UpstreamConfig, blocked []string) func([]byte, string) []byte {
	rules := make(map[string]string, len(uc.Rewrites)+2)
	for k, v := range uc.Rewrites {
		rules[k] = v
	}
	if uc.Wildcard != nil {
		w := uc.Wildcard
		rules["*"+w.UpstreamSuffix] = w.Prefix + "*" + w.EntrySuffix
		base := strings.TrimSuffix(w.Prefix, "-")
		bare := strings.TrimPrefix(w.UpstreamSuffix, ".")
		rules[bare] = base + w.EntrySuffix
		rules["."+bare] = base + w.EntrySuffix
	}
	base := buildRewriter(rules)
	// Ensure body replace rules have pre-compiled regexes (defensive: handles ad-hoc configs not from ParseConfig)
	compileBodyReplaceRules(uc.BodyReplace)
	return func(body []byte, port string) []byte {
		body = stripBlockedURLs(body, blocked)
		body = base(body, port)
		if len(uc.BodyReplace) > 0 {
			body = applyBodyReplace(body, uc.BodyReplace)
		}
		return body
	}
}

// applyBodyReplace performs generic replacement rules on response body (supports fast literal replacement and regex replacement).
func applyBodyReplace(body []byte, rules []BodyReplaceRule) []byte {
	for _, r := range rules {
		if r.Old == "" {
			continue
		}
		if r.Regex {
			if r.compiled != nil {
				body = r.compiled.ReplaceAll(body, []byte(r.New))
			}
			continue
		}
		if bytes.Contains(body, []byte(r.Old)) {
			body = bytes.ReplaceAll(body, []byte(r.Old), []byte(r.New))
		} else if r.compiled != nil {
			body = r.compiled.ReplaceAll(body, []byte(r.New))
		}
	}
	return body
}

// stripBlockedURLs removes complete URL values of blocked third-party domains from response text.
func stripBlockedURLs(body []byte, blocked []string) []byte {
	out := body
	for _, b := range blocked {
		out = stripOneBlockedURL(out, []byte(b))
		if strings.HasPrefix(b, "https://") {
			out = stripOneBlockedURL(out, []byte("//"+b[len("https://"):]))
		}
	}
	return out
}

func stripOneBlockedURL(body, blocked []byte) []byte {
	var out []byte
	rest := body
	for {
		i := bytes.Index(rest, blocked)
		if i < 0 {
			out = append(out, rest...)
			break
		}
		start := i
		j := i + len(blocked)
		for j < len(rest) {
			c := rest[j]
			if c == '"' || c == '\'' || c == ')' || c == '`' ||
				c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
				c == '<' || c == '>' {
				break
			}
			j++
		}
		out = append(out, rest[:start]...)
		rest = rest[j:]
	}
	return out
}

func buildRewriter(rt map[string]string) func([]byte, string) []byte {
	var exact, wildcard []string
	for k := range rt {
		if strings.HasPrefix(k, "*.") {
			wildcard = append(wildcard, k)
		} else {
			exact = append(exact, k)
		}
	}
	sort.Slice(exact, func(i, j int) bool { return len(exact[i]) > len(exact[j]) })
	sort.Slice(wildcard, func(i, j int) bool { return len(wildcard[i]) > len(wildcard[j]) })
	keys := append(exact, wildcard...)
	return func(body []byte, port string) []byte {
		for _, k := range keys {
			target := rt[k]
			if port != "" && !strings.HasPrefix(k, ".") && !strings.Contains(target, ":") {
				target += ":" + port
			}
			if strings.HasPrefix(k, "*.") {
				body = replaceWildcardDomain(body, k[2:], target)
				continue
			}
			body = replaceDomainBounded(body, k, target)
		}
		return body
	}
}

func replaceWildcardDomain(body []byte, suffix, target string) []byte {
	var out []byte
	rest := body
	for {
		i := bytes.Index(rest, []byte(suffix))
		if i < 0 {
			out = append(out, rest...)
			break
		}
		start := i
		for start > 0 && isDomainChar(rest[start-1]) {
			if start >= 3 && rest[start-3] == '%' &&
				isHexDigit(rest[start-2]) && isHexDigit(rest[start-1]) {
				break
			}
			start--
		}
		sub := string(rest[start:i])
		if sub == "" {
			out = append(out, rest[:i+len(suffix)]...)
			rest = rest[i+len(suffix):]
			continue
		}
		sub = strings.TrimSuffix(sub, ".")
		if sub == "" {
			out = append(out, rest[:i+len(suffix)]...)
			rest = rest[i+len(suffix):]
			continue
		}
		var left, right byte
		if start > 0 {
			left = rest[start-1]
		}
		j := i + len(suffix)
		if j < len(rest) {
			right = rest[j]
		}
		leftOK := !isDomainChar(left)
		if start >= 3 && rest[start-3] == '%' && isHexDigit(rest[start-2]) && isHexDigit(left) {
			leftOK = true
		}
		if leftOK && !isDomainChar(right) {
			out = append(out, rest[:start]...)
			out = append(out, strings.ReplaceAll(target, "*", sub)...)
			rest = rest[j:]
		} else {
			out = append(out, rest[:j]...)
			rest = rest[j:]
		}
	}
	return out
}

func replaceDomainBounded(body []byte, from, to string) []byte {
	fromB := []byte(from)
	toB := []byte(to)
	var out []byte
	rest := body
	for {
		i := bytes.Index(rest, fromB)
		if i < 0 {
			out = append(out, rest...)
			break
		}
		var left, right byte
		if i > 0 {
			left = rest[i-1]
		}
		j := i + len(fromB)
		if j < len(rest) {
			right = rest[j]
		}
		leftOK := !isDomainChar(left)
		if i >= 3 && rest[i-3] == '%' && isHexDigit(rest[i-2]) && isHexDigit(left) {
			leftOK = true
		}
		if leftOK && !isDomainChar(right) {
			out = append(out, rest[:i]...)
			out = append(out, toB...)
			rest = rest[j:]
		} else {
			out = append(out, rest[:j]...)
			rest = rest[j:]
		}
	}
	return out
}

func isDomainChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_'
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}
