package rewrite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBypassSourceLocalPriority(t *testing.T) {
	dir := t.TempDir()
	localPath := filepath.Join(dir, LocalBypassFileName)
	if err := os.WriteFile(localPath, []byte("google.com\nyoutube.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := ResolveBypassSource(WhitelistSourceOptions{
		Candidates: []string{localPath},
	})
	if src.Kind != WhitelistKindLocal {
		t.Fatalf("Kind = %q, want %q", src.Kind, WhitelistKindLocal)
	}
	if src.LocalPath != localPath {
		t.Fatalf("LocalPath = %q, want %q", src.LocalPath, localPath)
	}

	// Explicit -bypass-url overrides local file
	exp := ResolveBypassSource(WhitelistSourceOptions{
		ExplicitURL: "https://example.com/bypass.txt",
		Candidates:  []string{localPath},
	})
	if exp.Kind != WhitelistKindExplicit || exp.URL != "https://example.com/bypass.txt" {
		t.Fatalf("Explicit source = %+v, want explicit https://example.com/bypass.txt", exp)
	}

	// -no-local-bypass ignores local file and falls back to DefaultBypassURL
	noLocal := ResolveBypassSource(WhitelistSourceOptions{
		DisableLocal: true,
		Candidates:   []string{localPath},
	})
	if noLocal.Kind != WhitelistKindRemote || noLocal.URL != DefaultBypassURL {
		t.Fatalf("DisableLocal source = %+v, want remote %s", noLocal, DefaultBypassURL)
	}
}

func TestAdScriptManagerBypassListMatching(t *testing.T) {
	dir := t.TempDir()
	localPath := filepath.Join(dir, LocalBypassFileName)
	if err := os.WriteFile(localPath, []byte("# comment\ngoogle.com\n*.openai.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr := NewAdScriptManager(AdScriptOptions{
		BypassFile: localPath,
		NoLocalPAC: true,
	})
	if !mgr.IsBypassed("google.com") || !mgr.IsBypassed("www.google.com") {
		t.Error("expected google.com and www.google.com to match bypass.txt")
	}
	if !mgr.IsBypassed("api.openai.com") {
		t.Error("expected api.openai.com to match *.openai.com in bypass.txt")
	}
	if mgr.IsBypassed("pixiv.net") {
		t.Error("pixiv.net should not match bypass.txt")
	}
}

func TestDefaultSensitiveBypassDomainsAlwaysActive(t *testing.T) {
	mgr := NewAdScriptManager(AdScriptOptions{
		NoLocalPAC:    true,
		NoLocalBypass: true,
	})
	for _, host := range []string{
		"mybank.icbc.com.cn",
		"www.paypal.com",
		"vault.bitwarden.com",
		"download.windowsupdate.com",
		"login.microsoftonline.com",
	} {
		if !mgr.IsBypassed(host) {
			t.Errorf("expected sensitive domain %q to be bypassed by default", host)
		}
	}
	if mgr.IsBypassed("pixiv.net") {
		t.Error("non-sensitive domain pixiv.net should not be in DefaultSensitiveBypassDomains")
	}
}

func TestDefaultSensitiveBypassDomainsImmutableAndPKICoverage(t *testing.T) {
	s1 := DefaultSensitiveBypassDomains()
	if len(s1) == 0 {
		t.Fatal("expected non-empty DefaultSensitiveBypassDomains")
	}
	orig := s1[0]
	s1[0] = "evil.invalid"
	s2 := DefaultSensitiveBypassDomains()
	if s2[0] != orig {
		t.Fatalf("DefaultSensitiveBypassDomains mutated across calls: got %q, want %q", s2[0], orig)
	}

	mgr := NewAdScriptManager(AdScriptOptions{NoLocalPAC: true, NoLocalBypass: true})
	for _, host := range []string{
		"open.weixin.qq.com",
		"login.weixin.qq.com",
		"accounts.google.com",
		"crl.apple.com",
		"ocsp.sectigo.com",
		"ocsp.usertrust.com",
		"ocsp.globalsign.com",
	} {
		if !mgr.IsBypassed(host) {
			t.Errorf("expected %q to be protected by DefaultSensitiveBypassDomains", host)
		}
	}
}
