package echproxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Config validation: turn silently-ignored configuration mistakes into
// reported ones.
//
// Go's encoding/json drops unknown object fields without complaint and this
// project relies on that for backwards compatibility (a config written for an
// older build must keep working). The cost is that a typo'd or misplaced key
// looks exactly like "not configured" — the classic case being a top-level
// "ip_mode": "v4", which is parsed nowhere and silently leaves the egress IP
// family up to the OS resolver.
//
// Everything below is read-only with respect to Config: Validate never mutates
// and never blocks startup. LoadConfig reports what it finds, and callers decide.

// ConfigIssue is a single problem found in a configuration. Issues are
// advisory by default: LoadConfig logs them and keeps going, so a config that
// merely carries a stale key still serves traffic.
type ConfigIssue struct {
	// Severity is "error" (the entry cannot do what the config asks) or
	// "warning" (the key is ignored, or the entry will behave differently
	// from what the value suggests).
	Severity string
	// Entry is the upstream entry name, or "" for whole-config issues.
	Entry string
	// Field is the JSON key involved, e.g. "ip_mode". Empty when the issue
	// is about the entry as a whole.
	Field string
	// Message explains the problem in one sentence.
	Message string
	// Hint is a concrete suggested fix, when there is an unambiguous one.
	Hint string
}

func (c ConfigIssue) String() string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(c.Severity))
	b.WriteString(": ")
	if c.Entry != "" {
		b.WriteString(c.Entry)
		b.WriteString(".")
		b.WriteString(c.Field)
		if c.Field == "" {
			b.WriteString("<entry>")
		}
		b.WriteString(": ")
	} else if c.Field != "" {
		b.WriteString(c.Field)
		b.WriteString(": ")
	}
	b.WriteString(c.Message)
	if c.Hint != "" {
		b.WriteString(" (")
		b.WriteString(c.Hint)
		b.WriteString(")")
	}
	return b.String()
}

// HasErrors reports whether any issue has severity "error".
func HasErrors(issues []ConfigIssue) bool {
	for _, is := range issues {
		if is.Severity == "error" {
			return true
		}
	}
	return false
}

// ipModeValues is the exact accepted set for ip_mode. Matching is
// case-sensitive on purpose: the runtime switch in ech/client.go compares
// literals, so accepting "V4" here would advertise a value that silently
// degrades to auto at runtime.
var ipModeValues = []string{"", "auto", "v4", "v6"}

// modeValues is the exact accepted set for mode. Anything else falls through
// to the ECH default branch in proxyRoundTrip, which is surprising enough to
// be worth reporting.
var modeValues = []string{"", "ech", "direct", "sni"}

// cookiePriorityValues is the exact accepted set for cookie_priority.
var cookiePriorityValues = []string{"", "seed", "browser"}

// entryScopedFields is every JSON key accepted inside an upstream entry.
// Used to flag typos that would otherwise be dropped by encoding/json.
var entryScopedFields = map[string]bool{
	"host": true, "describe": true, "display": true,
	"headers": true, "response_headers": true,
	"cookie": true, "cookie_file": true, "cookie_domain": true, "cookie_priority": true,
	"sw_inject": true, "mode": true, "ip_mode": true,
	"rewrites": true, "body_replace": true, "wildcard": true,
	// Legacy compatibility fields, still honored by normalizeConfig.
	"referer": true, "origin": true, "x_site": true,
}

// topLevelFields is every JSON key accepted at the top level of the config.
var topLevelFields = map[string]bool{
	"cert_path": true, "key_path": true,
	"upstreams": true, "wildcards": true, "blocked_hosts": true,
}

// wildcardFields is every JSON key accepted inside a wildcard rule.
var wildcardFields = map[string]bool{
	"entry": true, "upstream": true, "host": true, "match": true, "target": true,
	"prefix": true, "entry_suffix": true, "upstream_suffix": true,
	"headers": true, "response_headers": true,
	"cookie": true, "cookie_file": true, "cookie_domain": true, "cookie_priority": true,
	"mode": true, "ip_mode": true, "sw_inject": true,
	"rewrites": true, "body_replace": true,
	"referer": true, "origin": true, "x_site": true,
}

func containsFold(list []string, v string) bool {
	for _, c := range list {
		if c == v {
			return true
		}
	}
	return false
}

// suggestField returns the closest known key to name, or "" if nothing is
// close. It is intentionally conservative: only candidates within a small
// edit distance are offered, so we never suggest something unrelated.
func suggestField(name string, known map[string]bool) string {
	if name == "" {
		return ""
	}
	lower := strings.ToLower(name)
	best, bestDist := "", 1<<30
	for k := range known {
		d := editDistance(lower, strings.ToLower(k))
		if d < bestDist {
			best, bestDist = k, d
		}
	}
	// Allow one edit for short keys, two for longer ones.
	limit := 1
	if len(lower) >= 5 {
		limit = 2
	}
	if bestDist <= limit {
		return best
	}
	return ""
}

func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = prev[j-1] + cost
			if cur[j] > prev[j]+1 {
				cur[j] = prev[j] + 1
			}
			if cur[j] > cur[j-1]+1 {
				cur[j] = cur[j-1] + 1
			}
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

// Validate checks a parsed configuration and returns everything worth telling
// the operator about. It is safe to call on a Config produced by ParseConfig
// and never mutates it.
func Validate(cfg *Config) []ConfigIssue {
	var issues []ConfigIssue
	if cfg == nil {
		return []ConfigIssue{{Severity: "error", Message: "config is nil"}}
	}

	// Raw JSON for unknown-key detection. ParseConfig keeps it for us; when
	// Validate is called on a hand-built Config we simply skip that part.
	issues = append(issues, validateUnknownKeys(cfg)...)

	seenHost := map[string]string{}
	// Validate every entry exactly once, in config order where known so the
	// report is stable. Entries absent from UpstreamOrder still route (map
	// lookup is exact-match); they are simply missing from the portal list.
	ordered := make([]string, 0, len(cfg.Upstreams))
	visited := make(map[string]bool, len(cfg.Upstreams))
	for _, entry := range cfg.UpstreamOrder {
		if _, ok := cfg.Upstreams[entry]; ok && !visited[entry] {
			ordered = append(ordered, entry)
			visited[entry] = true
		}
	}
	rest := make([]string, 0)
	for entry := range cfg.Upstreams {
		if !visited[entry] {
			rest = append(rest, entry)
		}
	}
	sort.Strings(rest)
	ordered = append(ordered, rest...)

	for _, entry := range ordered {
		uc := cfg.Upstreams[entry]
		issues = append(issues, validateEntry(entry, uc)...)

		if uc.Host == "" {
			issues = append(issues, ConfigIssue{
				Severity: "error", Entry: entry, Field: "host",
				Message: "host is empty, this entry cannot route anywhere",
			})
			continue
		}
		if prev, dup := seenHost[uc.Host]; dup {
			issues = append(issues, ConfigIssue{
				Severity: "warning", Entry: entry, Field: "host",
				Message: fmt.Sprintf("host %q is also used by entry %q", uc.Host, prev),
				Hint:    "two entries pointing at the same upstream are usually a leftover duplicate",
			})
		} else {
			seenHost[uc.Host] = entry
		}
	}

	return issues
}

func validateEntry(entry string, uc UpstreamConfig) []ConfigIssue {
	var issues []ConfigIssue

	if !containsFold(modeValues, uc.Mode) {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: entry, Field: "mode",
			Message: fmt.Sprintf("mode %q is not a recognized transport mode", uc.Mode),
			Hint:    "valid values are \"\", \"ech\", \"direct\", \"sni\"; anything else silently falls back to ech",
		})
	}
	if !containsFold(ipModeValues, uc.IPMode) {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: entry, Field: "ip_mode",
			Message: fmt.Sprintf("ip_mode %q is not a valid IP family", uc.IPMode),
			Hint:    "valid values are \"\", \"auto\", \"v4\", \"v6\"; values are case-sensitive",
		})
	}
	if !containsFold(cookiePriorityValues, uc.CookiePriority) {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: entry, Field: "cookie_priority",
			Message: fmt.Sprintf("cookie_priority %q is not a recognized value", uc.CookiePriority),
			Hint:    "valid values are \"\", \"seed\", \"browser\"",
		})
	}

	// The one that actually bit during the ip_mode work: ip_mode on a mode
	// that never reads it is a config line that implies control it does not
	// have.
	if uc.IPMode != "" && (uc.Mode == "direct" || uc.Mode == "sni") {
		issues = append(issues, ConfigIssue{
			Severity: "warning", Entry: entry, Field: "ip_mode",
			Message: fmt.Sprintf("ip_mode %q has no effect in mode %q", uc.IPMode, uc.Mode),
			Hint:    "proxyRoundTrip only forwards ip_mode in the ech branch; sni already tries every resolved address",
		})
	}

	if uc.Cookie == "" && uc.CookieFile != "" {
		issues = append(issues, ConfigIssue{
			Severity: "warning", Entry: entry, Field: "cookie_file",
			Message: "cookie_file is set but cookie is empty",
			Hint:    "the file is still read at request time; this is only odd if you expected cookie to be required",
		})
	}
	if uc.CookieFile != "" && strings.ContainsAny(uc.CookieFile, "\n\r") {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: entry, Field: "cookie_file",
			Message: "cookie_file must be a single-line path",
		})
	}

	if uc.Wildcard != nil {
		issues = append(issues, validateWildcard(entry, uc.Wildcard)...)
	}
	return issues
}

func validateWildcard(entry string, w *WildcardRule) []ConfigIssue {
	var issues []ConfigIssue
	where := entry + ".wildcard"

	if !containsFold(modeValues, w.Mode) {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: where, Field: "mode",
			Message: fmt.Sprintf("mode %q is not a recognized transport mode", w.Mode),
			Hint:    "valid values are \"\", \"ech\", \"direct\", \"sni\"",
		})
	}
	if !containsFold(ipModeValues, w.IPMode) {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: where, Field: "ip_mode",
			Message: fmt.Sprintf("ip_mode %q is not a valid IP family", w.IPMode),
			Hint:    "valid values are \"\", \"auto\", \"v4\", \"v6\"; values are case-sensitive",
		})
	}
	if !containsFold(cookiePriorityValues, w.CookiePriority) {
		issues = append(issues, ConfigIssue{
			Severity: "error", Entry: where, Field: "cookie_priority",
			Message: fmt.Sprintf("cookie_priority %q is not a recognized value", w.CookiePriority),
			Hint:    "valid values are \"\", \"seed\", \"browser\"",
		})
	}

	// normalizeWildcardRule can infer the suffix/prefix from the entry name, so
	// a completely empty wildcard is legal. But one that specifies some parts
	// and not others usually means the author expected the rest to be derived.
	if w.Prefix == "" && w.UpstreamSuffix == "" && w.Upstream == "" && w.Host == "" {
		if w.Entry == "" && w.Match == "" {
			issues = append(issues, ConfigIssue{
				Severity: "warning", Entry: where, Field: "wildcard",
				Message: "wildcard rule has no entry, prefix or upstream, it will never match",
			})
		}
	}
	return issues
}

// validateUnknownKeys flags JSON keys that no struct field claims. This is the
// only way to catch a top-level "ip_mode" or an "ipmode" typo, because
// encoding/json discards them before we ever see them.
func validateUnknownKeys(cfg *Config) []ConfigIssue {
	raw := cfg.rawJSON
	if len(raw) == 0 {
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil
	}

	var issues []ConfigIssue
	for _, k := range sortedKeys(top) {
		if topLevelFields[k] {
			continue
		}
		// Upstreams live under their own namespace; a misplaced upstream key
		// such as ip_mode is exactly the trap this guards against.
		issue := ConfigIssue{
			Severity: "error", Field: k,
			Message: fmt.Sprintf("unknown top-level key %q is ignored", k),
		}
		if k == "ip_mode" {
			issue.Hint = "ip_mode is per-entry: set it inside upstreams.<entry>, not at the top level"
		} else if s := suggestField(k, topLevelFields); s != "" {
			issue.Hint = fmt.Sprintf("did you mean %q?", s)
		}
		issues = append(issues, issue)
	}

	var ups map[string]json.RawMessage
	if rawUps, ok := top["upstreams"]; ok {
		if err := json.Unmarshal(rawUps, &ups); err != nil {
			return issues
		}
		for _, entry := range sortedKeys(ups) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(ups[entry], &fields); err != nil {
				continue
			}
			for _, k := range sortedKeys(fields) {
				if entryScopedFields[k] {
					continue
				}
				issue := ConfigIssue{
					Severity: "error", Entry: entry, Field: k,
					Message: fmt.Sprintf("unknown key %q is ignored", k),
				}
				if s := suggestField(k, entryScopedFields); s != "" {
					issue.Hint = fmt.Sprintf("did you mean %q?", s)
				}
				issues = append(issues, issue)
			}
			// A wildcard sub-object gets the same treatment.
			if rawW, ok := fields["wildcard"]; ok {
				var w map[string]json.RawMessage
				if err := json.Unmarshal(rawW, &w); err == nil {
					for _, k := range sortedKeys(w) {
						if wildcardFields[k] {
							continue
						}
						issue := ConfigIssue{
							Severity: "error", Entry: entry + ".wildcard", Field: k,
							Message: fmt.Sprintf("unknown key %q is ignored", k),
						}
						if s := suggestField(k, wildcardFields); s != "" {
							issue.Hint = fmt.Sprintf("did you mean %q?", s)
						}
						issues = append(issues, issue)
					}
				}
			}
		}
	}
	return issues
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FormatIssues renders issues as a stable, human-readable report. Entries with
// errors come first so the report can be triaged top-down.
func FormatIssues(issues []ConfigIssue) string {
	if len(issues) == 0 {
		return "config OK: no issues found"
	}
	ordered := make([]ConfigIssue, len(issues))
	copy(ordered, issues)
	sort.SliceStable(ordered, func(i, j int) bool {
		if (ordered[i].Severity == "error") != (ordered[j].Severity == "error") {
			return ordered[i].Severity == "error"
		}
		return false
	})

	var b strings.Builder
	errs := 0
	for _, is := range ordered {
		if is.Severity == "error" {
			errs++
		}
		b.WriteString("  ")
		b.WriteString(is.String())
		b.WriteString("\n")
	}
	warns := len(ordered) - errs
	switch {
	case errs > 0 && warns > 0:
		fmt.Fprintf(&b, "%d error(s), %d warning(s)\n", errs, warns)
	case errs > 0:
		fmt.Fprintf(&b, "%d error(s)\n", errs)
	default:
		fmt.Fprintf(&b, "%d warning(s), 0 errors\n", warns)
	}
	return b.String()
}
