package rewrite

import (
	"strings"
	"testing"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
)

func TestOriginalDomainModeDoesNotRewriteToPortalDomains(t *testing.T) {
	uc := config.UpstreamConfig{
		Host: "www.dlsite.com",
		Rewrites: map[string]string{
			"www.dlsite.com": "dlsite.l.moonchan.xyz",
			"img.dlsite.jp":  "dlsite-img.l.moonchan.xyz",
		},
		Wildcard: &config.WildcardRule{
			Prefix:         "dlsite-",
			EntrySuffix:    ".l.moonchan.xyz",
			UpstreamSuffix: ".dlsite.com",
		},
	}
	payload := []byte(`<img src="https://img.dlsite.jp/a.jpg"><a href="https://ci.dlsite.com/b">`)

	// 1. 门户模式（dlsite.l.moonchan.xyz:8443）应将域名重写为 *.l.moonchan.xyz:8443
	portalRewriter := BuildEntryRewriterForHost("dlsite.l.moonchan.xyz:8443", uc, nil)
	gotPortal := string(portalRewriter(payload, "8443"))
	if !strings.Contains(gotPortal, "dlsite-img.l.moonchan.xyz:8443") || !strings.Contains(gotPortal, "dlsite-ci.l.moonchan.xyz:8443") {
		t.Errorf("portal mode rewrite failed: got %q", gotPortal)
	}

	// 2. 原域名透明反代/MITM 模式（www.dlsite.com）不应将子域改写到 *.l.moonchan.xyz（修复 Issue #3）
	origRewriter := BuildEntryRewriterForHost("www.dlsite.com", uc, nil)
	gotOrig := string(origRewriter(payload, "443"))
	if strings.Contains(gotOrig, "l.moonchan.xyz") {
		t.Errorf("original domain mode must not rewrite to l.moonchan.xyz, got %q", gotOrig)
	}
	if !strings.Contains(gotOrig, "https://img.dlsite.jp/a.jpg") || !strings.Contains(gotOrig, "https://ci.dlsite.com/b") {
		t.Errorf("original domain mode altered original URLs unexpectedly: %q", gotOrig)
	}
}

func TestStripBlockedURLsAndGzipRoundTrip(t *testing.T) {
	uc := config.UpstreamConfig{Host: "example.com"}
	rw := BuildEntryRewriter(uc, []string{"https://www.googletagmanager.com"})
	in := []byte(`<script src="https://www.googletagmanager.com/gtm.js?id=123"></script><p>ok</p>`)
	out := string(rw(in, ""))
	if strings.Contains(out, "googletagmanager.com") || !strings.Contains(out, `<script src=""></script><p>ok</p>`) {
		t.Errorf("stripBlockedURLs got %q", out)
	}

	compressed, enc := CompressBody([]byte("hello world"), "gzip", "br, gzip;q=0.9")
	if enc != "gzip" {
		t.Fatalf("CompressBody enc = %q, want gzip", enc)
	}
	plain, err := DecompressBody(compressed, "gzip")
	if err != nil || string(plain) != "hello world" {
		t.Errorf("DecompressBody = %q, %v", string(plain), err)
	}
}
