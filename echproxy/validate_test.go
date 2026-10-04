package echproxy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// shippedConfigPath is the config production actually loads, relative to the
// package directory.
const shippedConfigPath = "../certs/l.moonchan.xyz/upstream.json"

func readShippedConfig() ([]byte, error) {
	return os.ReadFile(shippedConfigPath)
}

// buildTestConfig is a helper that parses a JSON literal through the real
// ParseConfig path, so tests exercise the same code production does.
func buildTestConfig(t *testing.T, body string) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(body))
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	return cfg
}

// hasIssue reports whether issues contain one matching entry+field. An empty
// entry or field matches anything, which keeps the assertions short without
// making them vacuous: the field is always specified in practice.
func hasIssue(issues []ConfigIssue, entry, field string) bool {
	for _, is := range issues {
		if entry != "" && is.Entry != entry {
			continue
		}
		if field != "" && is.Field != field {
			continue
		}
		return true
	}
	return false
}

func issueCount(issues []ConfigIssue, entry, field string) int {
	n := 0
	for _, is := range issues {
		if entry != "" && is.Entry != entry {
			continue
		}
		if field != "" && is.Field != field {
			continue
		}
		n++
	}
	return n
}

// findHint returns the hint of the first matching issue.
func findHint(issues []ConfigIssue, entry, field string) string {
	for _, is := range issues {
		if entry != "" && is.Entry != entry {
			continue
		}
		if field != "" && is.Field != field {
			continue
		}
		return is.Hint
	}
	return ""
}

// --- S1: top-level ip_mode is silently dropped by encoding/json -----------

func TestValidateFlagsTopLevelIPMode(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "ip_mode": "v4",
        "upstreams": { "a.l.moonchan.xyz": { "host": "example.com" } }
    }`)

	// Precondition for the whole test: the value really is dropped, which is
	// why a validator is needed at all.
	if _, ok := cfg.Upstreams["a.l.moonchan.xyz"]; !ok {
		t.Fatal("test config did not parse as expected")
	}

	issues := Validate(cfg)
	if !hasIssue(issues, "", "ip_mode") {
		t.Fatalf("expected an issue for top-level ip_mode, got: %v", issues)
	}
	if hint := findHint(issues, "", "ip_mode"); !strings.Contains(hint, "upstreams") {
		t.Errorf("expected hint to point at upstreams.<entry>, got %q", hint)
	}
}

func TestValidateAcceptsCleanTopLevelKeys(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "cert_path": "https://example.com/cert",
        "key_path": "https://example.com/key",
        "upstreams": { "a.l.moonchan.xyz": { "host": "example.com" } },
        "blocked_hosts": ["https://fonts.googleapis.com"]
    }`)

	if issues := Validate(cfg); len(issues) != 0 {
		t.Errorf("expected no issues for a clean config, got: %v", issues)
	}
}

// --- S5: misspelled keys inside an entry are silently dropped -------------

func TestValidateFlagsUnknownEntryKey(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": { "a.l.moonchan.xyz": { "host": "example.com", "ipmode": "v4" } }
    }`)

	issues := Validate(cfg)
	if !hasIssue(issues, "a.l.moonchan.xyz", "ipmode") {
		t.Fatalf("expected an issue for unknown key ipmode, got: %v", issues)
	}
	// The suggestion is the actionable half of this report, so assert it
	// directly rather than only that some issue exists.
	if hint := findHint(issues, "a.l.moonchan.xyz", "ipmode"); !strings.Contains(hint, "ip_mode") {
		t.Errorf("expected suggestion ip_mode, got %q", hint)
	}
}

func TestSuggestFieldPicksClosestMatch(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{"ipmode", "ip_mode"},
		{"ip_modes", "ip_mode"},
		{"hosst", "host"},
		{"describee", "describe"},
		{"wildcrad", "wildcard"},
		{"sw_injct", "sw_inject"},
	}
	for _, c := range cases {
		if got := suggestField(c.got, entryScopedFields); got != c.want {
			t.Errorf("suggestField(%q) = %q, want %q", c.got, got, c.want)
		}
	}
	// upstream_suffix only exists inside a wildcard rule, so it is matched
	// against the wildcard key set rather than the entry key set.
	if got := suggestField("upstream_sufix", wildcardFields); got != "upstream_suffix" {
		t.Errorf("suggestField(upstream_sufix, wildcard) = %q, want upstream_suffix", got)
	}
}

// TestSuggestFieldDeclinesUnrelatedNames guards against a validator that
// confidently suggests nonsense, which is worse than staying quiet.
func TestSuggestFieldDeclinesUnrelatedNames(t *testing.T) {
	for _, name := range []string{"totally_different", "zzzzzzzz", "qqqqqqqq"} {
		if got := suggestField(name, entryScopedFields); got != "" {
			t.Errorf("suggestField(%q) = %q, want no suggestion", name, got)
		}
	}
}

func TestValidateFlagsUnknownWildcardKey(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": {
            "a.l.moonchan.xyz": {
                "host": "example.com",
                "wildcard": { "prefix": "a-", "entry_suffix": ".l.moonchan.xyz", "upstream_sufix": ".example.com" }
            }
        }
    }`)

	issues := Validate(cfg)
	if !hasIssue(issues, "a.l.moonchan.xyz.wildcard", "upstream_sufix") {
		t.Fatalf("expected an issue for misspelled wildcard key, got: %v", issues)
	}
}

// --- S2: ip_mode values are case-sensitive at runtime ---------------------

func TestValidateFlagsInvalidIPMode(t *testing.T) {
	for _, bad := range []string{"V4", "V6", "AUTO", "ipv4", "4"} {
		cfg := buildTestConfig(t, `{
            "upstreams": { "a.l.moonchan.xyz": { "host": "example.com", "ip_mode": "`+bad+`" } }
        }`)

		issues := Validate(cfg)
		if !hasIssue(issues, "a.l.moonchan.xyz", "ip_mode") {
			t.Errorf("expected ip_mode=%q to be rejected, got: %v", bad, issues)
		}
		if !HasErrors(issues) {
			t.Errorf("expected ip_mode=%q to be an error, not a warning: %v", bad, issues)
		}
	}
}

func TestValidateAcceptsAllValidIPModes(t *testing.T) {
	for _, ok := range []string{"", "auto", "v4", "v6"} {
		body := `{"upstreams": {"a.l.moonchan.xyz": {"host": "example.com"`
		if ok != "" {
			body += `, "ip_mode": "` + ok + `"`
		}
		body += `}}}`
		cfg := buildTestConfig(t, body)

		if issues := Validate(cfg); len(issues) != 0 {
			t.Errorf("expected ip_mode=%q to be accepted, got: %v", ok, issues)
		}
	}
}

// --- S3: ip_mode is ignored on direct / sni entries -----------------------

func TestValidateFlagsIneffectiveIPMode(t *testing.T) {
	for _, mode := range []string{"direct", "sni"} {
		cfg := buildTestConfig(t, `{
            "upstreams": { "a.l.moonchan.xyz": { "host": "example.com", "mode": "`+mode+`", "ip_mode": "v4" } }
        }`)

		issues := Validate(cfg)
		if !hasIssue(issues, "a.l.moonchan.xyz", "ip_mode") {
			t.Errorf("expected a warning for ip_mode on mode=%s, got: %v", mode, issues)
		}
		// It is a warning, not an error: the config still works, the key just
		// does not do what it looks like it does.
		if HasErrors(issues) {
			t.Errorf("expected ip_mode on mode=%s to be a warning, got errors: %v", mode, issues)
		}
	}
}

func TestValidateAcceptsIPModeOnECHEdEntry(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": { "a.l.moonchan.xyz": { "host": "example.com", "ip_mode": "v4" } }
    }`)

	if issues := Validate(cfg); len(issues) != 0 {
		t.Errorf("expected ip_mode on an ech entry to be accepted, got: %v", issues)
	}
}

// --- mode / cookie_priority values ---------------------------------------

func TestValidateFlagsInvalidMode(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": { "a.l.moonchan.xyz": { "host": "example.com", "mode": "DIRECT" } }
    }`)

	issues := Validate(cfg)
	if !hasIssue(issues, "a.l.moonchan.xyz", "mode") {
		t.Fatalf("expected mode=\"DIRECT\" to be rejected, got: %v", issues)
	}
}

func TestValidateFlagsInvalidCookiePriority(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": { "a.l.moonchan.xyz": { "host": "example.com", "cookie_priority": "Seed" } }
    }`)

	if issues := Validate(cfg); !hasIssue(issues, "a.l.moonchan.xyz", "cookie_priority") {
		t.Fatalf("expected cookie_priority=\"Seed\" to be rejected, got: %v", issues)
	}
}

// --- structural checks ----------------------------------------------------

func TestValidateFlagsEmptyHost(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": { "a.l.moonchan.xyz": { "describe": "no host here" } }
    }`)

	issues := Validate(cfg)
	if !hasIssue(issues, "a.l.moonchan.xyz", "host") {
		t.Fatalf("expected an error for empty host, got: %v", issues)
	}
	// Severity matters: an entry with no host cannot route at all, so this has
	// to stay an error or -check-config would exit 0 on a broken config.
	if !HasErrors(issues) {
		t.Errorf("expected empty host to be an error, not a warning: %v", issues)
	}
}

// TestValidateFlagsEmptyHostAsErrorInCheckConfig exercises the exit-code path:
// -check-config returns 0 only when nothing is an error.
func TestValidateFlagsEmptyHostBlocksCheckConfig(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": { "a.l.moonchan.xyz": { "describe": "no host here" } }
    }`)

	if !HasErrors(Validate(cfg)) {
		t.Error("a config whose only entry has no host must fail -check-config")
	}
}

func TestValidateFlagsDuplicateHost(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": {
            "a.l.moonchan.xyz": { "host": "example.com" },
            "b.l.moonchan.xyz": { "host": "example.com" }
        }
    }`)

	issues := Validate(cfg)
	if !hasIssue(issues, "b.l.moonchan.xyz", "host") {
		t.Fatalf("expected a duplicate-host warning on the second entry, got: %v", issues)
	}
	if HasErrors(issues) {
		t.Errorf("duplicate host should be a warning, not an error: %v", issues)
	}
}

// --- the shipped config must stay clean ----------------------------------

// This is the assertion that gives the validator its value: if it fires, the
// config that production actually loads is wrong somewhere.
func TestShippedConfigValidatesClean(t *testing.T) {
	data, err := readShippedConfig()
	if err != nil {
		t.Fatalf("read upstream.json failed: %v", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if issues := Validate(cfg); len(issues) > 0 {
		t.Errorf("shipped upstream.json has %d issue(s):\n%s", len(issues), FormatIssues(issues))
	}
}

// --- reporting behavior ---------------------------------------------------

func TestValidateReportsEachEntryOnce(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": {
            "a.l.moonchan.xyz": { "host": "example.com", "ip_mode": "V4" },
            "b.l.moonchan.xyz": { "host": "other.com",  "ip_mode": "V6" }
        }
    }`)

	issues := Validate(cfg)
	if n := issueCount(issues, "a.l.moonchan.xyz", "ip_mode"); n != 1 {
		t.Errorf("expected exactly 1 issue for entry a, got %d: %v", n, issues)
	}
	if n := issueCount(issues, "b.l.moonchan.xyz", "ip_mode"); n != 1 {
		t.Errorf("expected exactly 1 issue for entry b, got %d: %v", n, issues)
	}
}

func TestValidateOnHandBuiltConfigSkipsUnknownKeyCheck(t *testing.T) {
	// Validate must not panic on a Config built without rawJSON.
	cfg := &Config{
		Upstreams: UpstreamMap{
			"a.l.moonchan.xyz": UpstreamConfig{Host: "example.com"},
		},
	}
	if issues := Validate(cfg); len(issues) != 0 {
		t.Errorf("expected no issues for a hand-built valid config, got: %v", issues)
	}
}

func TestValidateNilConfig(t *testing.T) {
	issues := Validate(nil)
	if !HasErrors(issues) {
		t.Errorf("expected an error for a nil config, got: %v", issues)
	}
}

func TestFormatIssuesSortsErrorsFirst(t *testing.T) {
	issues := []ConfigIssue{
		{Severity: "warning", Entry: "a", Field: "f", Message: "warn line"},
		{Severity: "error", Entry: "b", Field: "f", Message: "error line"},
	}
	out := FormatIssues(issues)
	if strings.Index(out, "error line") > strings.Index(out, "warn line") {
		t.Errorf("expected errors before warnings, got:\n%s", out)
	}
	if !strings.Contains(out, "1 error(s), 1 warning(s)") {
		t.Errorf("expected a summary line, got:\n%s", out)
	}
}

func TestFormatIssuesEmptyIsOK(t *testing.T) {
	if out := FormatIssues(nil); !strings.Contains(out, "no issues") {
		t.Errorf("expected an OK message, got %q", out)
	}
}

// TestValidateDoesNotMutateConfig guards the promise that Validate is
// read-only: a validator that repairs config silently is worse than none.
//
// It uses a fixture with fields that a mutation would plausibly touch
// (ip_mode, mode, cookie_priority) rather than the shipped config, so the
// assertion cannot pass just because those fields happen to be absent.
func TestValidateDoesNotMutateConfig(t *testing.T) {
	cfg := buildTestConfig(t, `{
        "upstreams": {
            "a.l.moonchan.xyz": { "host": "example.com", "ip_mode": "v4", "describe": "a" },
            "b.l.moonchan.xyz": { "host": "other.example.com", "mode": "direct", "ip_mode": "V4", "cookie_priority": "Seed" },
            "c.l.moonchan.xyz": {
                "host": "third.example.com",
                "ip_mode": "v6",
                "wildcard": { "prefix": "c-", "entry_suffix": ".l.moonchan.xyz", "upstream_suffix": ".example.com" }
            }
        }
    }`)

	// Precondition: the fixture really carries those values, otherwise the
	// comparison below would be vacuous.
	if cfg.Upstreams["a.l.moonchan.xyz"].IPMode != "v4" {
		t.Fatalf("fixture precondition failed, ip_mode was not parsed: %+v", cfg.Upstreams["a.l.moonchan.xyz"])
	}

	before, err := json.Marshal(cfg.Upstreams)
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}
	_ = Validate(cfg)
	after, err := json.Marshal(cfg.Upstreams)
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}

	if string(before) != string(after) {
		t.Errorf("Validate mutated the config:\nbefore: %s\nafter:  %s", before, after)
	}
}
