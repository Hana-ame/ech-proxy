package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateCatchesSilentFailuresS1ToS6(t *testing.T) {
	badJSON := []byte(`{
		"ipmode": "v4",
		"upstreams": {
			"bad1.l.moonchan.xyz": {
				"host": "",
				"ip_mode": "V4",
				"mode": "invalid_mode",
				"cookie_priority": "wrong_prio",
				"cookie_file": "../../etc/passwd",
				"rewirtes": {"a.com": "b.com"}
			},
			"dup1.l.moonchan.xyz": {
				"host": "same.example.com"
			},
			"dup2.l.moonchan.xyz": {
				"host": "same.example.com"
			}
		}
	}`)

	issues, err := Validate(badJSON)
	if err != nil {
		t.Fatalf("Validate returned unexpected parse error: %v", err)
	}
	if !HasErrors(issues) {
		t.Fatalf("expected HasErrors=true, got false; issues=%v", issues)
	}

	report := FormatIssues(issues)
	mustContain := []string{
		`unknown top-level field "ipmode"`,
		`did you mean "ip_mode"?`,
		`upstream host must not be empty`,
		`non-canonical ip_mode "V4"`,
		`invalid mode "invalid_mode"`,
		`invalid cookie_priority "wrong_prio"`,
		`unsafe cookie_file path`,
		`unknown field "rewirtes"`,
		`did you mean "rewrites"?`,
		`duplicate upstream host "same.example.com"`,
	}
	for _, want := range mustContain {
		if !strings.Contains(report, want) {
			t.Errorf("Validate report missing %q:\n%s", want, report)
		}
	}

	// Verify errors are sorted before warnings in FormatIssues
	errIdx := strings.Index(report, "[ERROR]")
	warnIdx := strings.Index(report, "[WARNING]")
	if errIdx < 0 || warnIdx < 0 || errIdx > warnIdx {
		t.Errorf("expected [ERROR] before [WARNING] in report:\n%s", report)
	}
}

func TestValidateProductionUpstreamJSONIsClean(t *testing.T) {
	buf, err := os.ReadFile("../../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json: %v", err)
	}
	issues, err := Validate(buf)
	if err != nil {
		t.Fatalf("Validate production upstream.json failed: %v", err)
	}
	if HasErrors(issues) {
		t.Errorf("production upstream.json has validation errors:\n%s", FormatIssues(issues))
	}
}

func TestTopLevelIPModeInheritanceAndNormalization(t *testing.T) {
	raw := []byte(`{
		"ip_mode": "V6",
		"upstreams": {
			"a.l.moonchan.xyz": {
				"host": "a.example.com"
			},
			"b.l.moonchan.xyz": {
				"host": "b.example.com",
				"ip_mode": "V4",
				"cookie_priority": "SEED"
			}
		}
	}`)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.IPMode != "v6" {
		t.Errorf("cfg.IPMode = %q, want v6", cfg.IPMode)
	}
	if got := cfg.Upstreams["a.l.moonchan.xyz"].IPMode; got != "v6" {
		t.Errorf("entry a inherited IPMode = %q, want v6", got)
	}
	if got := cfg.Upstreams["b.l.moonchan.xyz"].IPMode; got != "v4" {
		t.Errorf("entry b overridden IPMode = %q, want v4", got)
	}
	if got := cfg.Upstreams["b.l.moonchan.xyz"].CookiePriority; got != "seed" {
		t.Errorf("entry b CookiePriority = %q, want seed", got)
	}
}

func TestGenerateAndManageHostsAndPACDecoupledFromUpstreamJSON(t *testing.T) {
	raw := []byte(`{
		"upstreams": {
			"dlsite.l.moonchan.xyz": {
				"host": "www.dlsite.com",
				"wildcard": {
					"prefix": "dlsite-",
					"entry_suffix": ".l.moonchan.xyz",
					"upstream_suffix": ".dlsite.com"
				}
			}
		}
	}`)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	hostsPath := filepath.Join(t.TempDir(), "hosts")
	initial := "127.0.0.1 localhost\n"
	if err := os.WriteFile(hostsPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyHostsBlock(hostsPath, "127.0.0.1", cfg); err != nil {
		t.Fatalf("ApplyHostsBlock: %v", err)
	}
	afterApply, _ := os.ReadFile(hostsPath)
	s := string(afterApply)
	for _, want := range []string{"127.0.0.1 localhost", "127.0.0.1 i.pximg.net", "127.0.0.1 s.pximg.net", "127.0.0.1 www.dlsite.com"} {
		if !strings.Contains(s, want) {
			t.Errorf("hosts missing %q:\n%s", want, s)
		}
	}

	if err := RemoveHostsBlock(hostsPath); err != nil {
		t.Fatalf("RemoveHostsBlock: %v", err)
	}
	afterRemove, _ := os.ReadFile(hostsPath)
	if strings.Contains(string(afterRemove), HostsBlockBegin) || !strings.Contains(string(afterRemove), "127.0.0.1 localhost") {
		t.Errorf("RemoveHostsBlock did not cleanly restore hosts:\n%s", string(afterRemove))
	}

	// 验证 GeneratePAC 与 upstream.json (cfg) 完全解耦：
	// 即使传入非空 cfg，只要未传入 pac.txt 白名单，绝不从 upstream.json 生成任何域名规则！
	pacEmpty := GeneratePAC(cfg, "127.0.0.1:8443", false)
	if strings.Contains(pacEmpty, "dlsite.com") || strings.Contains(pacEmpty, "pximg.net") || strings.Contains(pacEmpty, "moonchan.xyz") {
		t.Errorf("GeneratePAC must be completely decoupled from upstream.json (cfg), got:\n%s", pacEmpty)
	}

	// 传入 pac.txt 白名单时，严格仅生成 pac.txt 中的域名规则
	pacWithWL := GeneratePAC(nil, "127.0.0.1:8443", false, []string{"i.pximg.net", "dlsite.com"})
	for _, want := range []string{`PROXY 127.0.0.1:8443; DIRECT`, `"i.pximg.net":true`, `".dlsite.com"`} {
		if !strings.Contains(pacWithWL, want) {
			t.Errorf("GeneratePAC missing %q:\n%s", want, pacWithWL)
		}
	}
}

// TestResolveOriginalDomainLeavesIPModeEmpty 验证 issue #40：
// 原域名（PAC/443 方案）解析结果必须把 IPMode 留空，交给 resolveEffectiveIPMode
// 回退到全局 ip_mode，否则 -6 / -dual 对原域名请求永不生效。
func TestResolveOriginalDomainLeavesIPModeEmpty(t *testing.T) {
	uc, ok := Resolve(nil, "example.com")
	if !ok {
		t.Fatal("Resolve(example.com) = false, want true")
	}
	if uc.IPMode != "" {
		t.Errorf("original-domain Resolve IPMode = %q, want empty (global ip_mode fallback)", uc.IPMode)
	}
	if uc.Host != "example.com" || uc.Mode != "auto" {
		t.Errorf("unexpected original-domain config: %+v", uc)
	}
}
