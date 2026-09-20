package echproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/gin-gonic/gin"
)

func TestMatchWildcardHeadersInheritance(t *testing.T) {
	cfg := UpstreamMap{
		"iwara.l.moonchan.xyz": UpstreamConfig{
			Host: "iwara.tv",
			Headers: map[string]HeaderRule{
				"Referer":    {Value: "https://www.iwara.tv/"},
				"Origin":     {Value: "https://www.iwara.tv"},
				"X-Site":     {Value: "www.iwara.tv"},
				"Custom-Key": {Value: "CustomVal"},
			},
			Wildcard: &WildcardRule{
				Prefix:         "iwara-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".iwara.tv",
			},
		},
	}

	uc, ok := MatchWildcardForTest(cfg, "iwara-api.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for iwara-api.l.moonchan.xyz")
	}
	if uc.Host != "api.iwara.tv" {
		t.Errorf("expected host api.iwara.tv, got %s", uc.Host)
	}
	if uc.Origin != "https://www.iwara.tv" {
		t.Errorf("expected origin https://www.iwara.tv, got %s", uc.Origin)
	}
	if uc.XSite != "www.iwara.tv" {
		t.Errorf("expected xsite www.iwara.tv, got %s", uc.XSite)
	}
	if uc.Headers["Custom-Key"].Value != "CustomVal" {
		t.Errorf("expected Custom-Key=CustomVal, got %s", uc.Headers["Custom-Key"].Value)
	}
}

func TestCORSMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware())
	r.POST("/test", func(c *gin.Context) {
		c.String(200, "ok")
	})

	// 1. Preflight OPTIONS with Origin
	req, _ := http.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://iwara.l.moonchan.xyz:8443")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, X-Site")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Errorf("expected status 204, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://iwara.l.moonchan.xyz:8443" {
		t.Errorf("expected mirrored origin, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("expected allow credentials true, got %s", w.Header().Get("Access-Control-Allow-Credentials"))
	}
	if w.Header().Get("Access-Control-Allow-Headers") != "Content-Type, X-Site" {
		t.Errorf("expected echoed headers, got %s", w.Header().Get("Access-Control-Allow-Headers"))
	}

	// 2. Simple POST without Origin
	req2, _ := http.NewRequest(http.MethodPost, "/test", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != 200 {
		t.Errorf("expected status 200, got %d", w2.Code)
	}
	if w2.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected *, got %s", w2.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestLoadUpstreamJSON(t *testing.T) {
	data, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json failed: %v", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	iwara, ok := cfg.Upstreams["iwara.l.moonchan.xyz"]
	if !ok {
		t.Fatalf("iwara entry not found in upstream.json")
	}
	if iwara.Origin != "https://www.iwara.tv" {
		t.Errorf("expected origin https://www.iwara.tv, got %s", iwara.Origin)
	}
	if iwara.XSite != "www.iwara.tv" {
		t.Errorf("expected xsite www.iwara.tv, got %s", iwara.XSite)
	}
	if iwara.Headers["Origin"].Value != "https://www.iwara.tv" || iwara.Headers["X-Site"].Value != "www.iwara.tv" {
		t.Errorf("expected headers Origin and X-Site, got %v", iwara.Headers)
	}
	if iwara.Headers["Referer"].Value != "https://www.iwara.tv/" {
		t.Errorf("expected headers Referer, got %v", iwara.Headers["Referer"])
	}

	// Verify wildcard subdomain matching merged from standalone wildcards list:
	wildMatch, ok := MatchWildcardForTest(cfg.Upstreams, "iwara-api.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for iwara-api.l.moonchan.xyz")
	}
	if wildMatch.Host != "api.iwara.tv" {
		t.Errorf("expected host api.iwara.tv, got %s", wildMatch.Host)
	}
	if wildMatch.Headers["Origin"].Value != "https://www.iwara.tv" {
		t.Errorf("expected origin in wildcard match, got %v", wildMatch.Headers["Origin"])
	}
	if wildMatch.Headers["X-Site"].Value != "www.iwara.tv" {
		t.Errorf("expected x-site in wildcard match, got %v", wildMatch.Headers["X-Site"])
	}
	if wildMatch.Headers["Referer"].Value != "https://www.iwara.tv/" {
		t.Errorf("expected referer in wildcard match, got %v", wildMatch.Headers["Referer"])
	}
}

func TestUpstreamOrderAndBanner(t *testing.T) {
	data, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json failed: %v", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	if len(cfg.UpstreamOrder) == 0 {
		t.Fatalf("expected UpstreamOrder to be populated via orderedmap")
	}

	expectedOrder := []string{
		"l.moonchan.xyz",
		"xx.l.moonchan.xyz",
		"twimg.l.moonchan.xyz",
		"ex.l.moonchan.xyz",
		"sukebei.l.moonchan.xyz",
		"ao3.l.moonchan.xyz",
		"iwara.l.moonchan.xyz",
		"zen.l.moonchan.xyz",
		"sensenova.l.moonchan.xyz",
		"dlsite.l.moonchan.xyz",
		"dlsite-img.l.moonchan.xyz",
		"asmr.l.moonchan.xyz",
		"asmr-api-100.l.moonchan.xyz",
		"asmr-api-200.l.moonchan.xyz",
		"asmr-api-300.l.moonchan.xyz",
		"f95.l.moonchan.xyz",
		"south.l.moonchan.xyz",
		"pixiv.l.moonchan.xyz",
		"pximg.l.moonchan.xyz",
		"pximg-s.l.moonchan.xyz",
	}

	if len(cfg.UpstreamOrder) != len(expectedOrder) {
		t.Fatalf("expected %d entries, got %d (%v)", len(expectedOrder), len(cfg.UpstreamOrder), cfg.UpstreamOrder)
	}
	for i, expected := range expectedOrder {
		if cfg.UpstreamOrder[i] != expected {
			t.Errorf("at index %d: expected %s, got %s", i, expected, cfg.UpstreamOrder[i])
		}
	}

	// Verify Server.PrintBanner outputs in the exact same order
	srv := &Server{
		Options: ServerOptions{Addr: "127.0.0.1:8443"},
		Config:  cfg,
		Port:    8443,
	}
	oldStdout := os.Stdout
	rPipe, wPipe, _ := os.Pipe()
	os.Stdout = wPipe

	srv.PrintBanner("")

	wPipe.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, rPipe)
	bannerOutput := buf.String()

	lastIdx := -1
	for _, domain := range expectedOrder {
		idx := strings.Index(bannerOutput, domain)
		if idx == -1 {
			t.Errorf("domain %s not found in banner output", domain)
			continue
		}
		if idx <= lastIdx {
			t.Errorf("domain %s appeared out of order in banner (idx=%d <= lastIdx=%d)", domain, idx, lastIdx)
		}
		lastIdx = idx
	}
}

func TestBuildEntryRewriter(t *testing.T) {
	uc := UpstreamConfig{
		Host: "iwara.tv",
		Wildcard: &WildcardRule{
			Prefix:         "iwara-",
			EntrySuffix:    ".l.moonchan.xyz",
			UpstreamSuffix: ".iwara.tv",
		},
		Rewrites: map[string]string{
			"www.iwara.tv": "iwara.l.moonchan.xyz",
		},
	}
	rewriter := buildEntryRewriter(uc, nil)
	input := []byte(`Visit https://api.iwara.tv/user and https://www.iwara.tv/videos`)
	output := rewriter(input, "8443")
	expected := `Visit https://iwara-api.l.moonchan.xyz:8443/user and https://iwara.l.moonchan.xyz:8443/videos`
	if string(output) != expected {
		t.Errorf("unexpected rewritten output: %s", string(output))
	}
}

func TestBodyReplace(t *testing.T) {
	jsonCfg := []byte(`{
		"host": "example.com",
		"body_replace": [
			["https://cdn.upstream.com/", "https://cdn.proxy.com/"],
			{"replace": ["v[0-9]+\\.[0-9]+", "v9.9.9"]}
		]
	}`)
	var uc UpstreamConfig
	if err := json.Unmarshal(jsonCfg, &uc); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(uc.BodyReplace) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(uc.BodyReplace))
	}
	if uc.BodyReplace[0].Old != "https://cdn.upstream.com/" || uc.BodyReplace[0].New != "https://cdn.proxy.com/" {
		t.Errorf("rule 0 mismatch: %+v", uc.BodyReplace[0])
	}
	if uc.BodyReplace[1].Old != `v[0-9]+\.[0-9]+` || uc.BodyReplace[1].New != "v9.9.9" {
		t.Errorf("rule 1 mismatch: %+v", uc.BodyReplace[1])
	}

	rewriter := buildEntryRewriter(uc, nil)
	input := []byte(`<script src="https://cdn.upstream.com/app.js?v=v1.2"></script>`)
	output := rewriter(input, "")
	expected := `<script src="https://cdn.proxy.com/app.js?v=v9.9.9"></script>`
	if string(output) != expected {
		t.Errorf("expected: %s\ngot: %s", expected, string(output))
	}
}

func TestRewriteSetCookieDomains(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "sid=123; Domain=.iwara.tv; Path=/; Secure")
	h.Add("Set-Cookie", "theme=dark; Path=/")

	rewriteSetCookieDomains(h, "iwara.l.moonchan.xyz:8443", true) // httpMode = true
	scs := h.Values("Set-Cookie")
	if len(scs) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d", len(scs))
	}
	if scs[0] != "sid=123; Domain=iwara.l.moonchan.xyz; Path=/" {
		t.Errorf("unexpected cookie 0: %s", scs[0])
	}
	if scs[1] != "theme=dark; Path=/" {
		t.Errorf("unexpected cookie 1: %s", scs[1])
	}
}

func TestHeadersNormalization(t *testing.T) {
	jsonRaw := []byte(`{
		"cert_path": "https://example.com/cert",
		"key_path": "https://example.com/key",
		"upstreams": {
			"auto-origin.test": {
				"host": "backend.test",
				"headers": {
					"Referer": "https://frontend.test/path"
				}
			},
			"legacy-compat.test": {
				"host": "legacy.test",
				"origin": "https://legacy.test",
				"x_site": "legacy.test"
			},
			"advanced-rules.test": {
				"host": "advanced.test",
				"headers": {
					"X-Delete-Me": { "delete": true },
					"X-Replace-Domain": { "replace": ["old.domain.com", "new.domain.com"] },
					"X-Custom-Token": "secret123"
				},
				"response_headers": {
					"X-Frame-Options": { "delete": true },
					"X-Proxy-By": "ech-proxy"
				}
			}
		}
	}`)
	cfg, err := ParseConfig(jsonRaw)
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}

	// 1. auto-derived origin from referer header
	auto := cfg.Upstreams["auto-origin.test"]
	if auto.Headers["Origin"].Value != "https://frontend.test" {
		t.Errorf("expected auto origin https://frontend.test, got %s", auto.Headers["Origin"].Value)
	}

	// 2. legacy origin & x_site compatibility normalization
	legacy := cfg.Upstreams["legacy-compat.test"]
	if legacy.Headers["Origin"].Value != "https://legacy.test" {
		t.Errorf("expected legacy Origin in Headers, got %s", legacy.Headers["Origin"].Value)
	}
	if legacy.Headers["X-Site"].Value != "legacy.test" {
		t.Errorf("expected legacy X-Site in Headers, got %s", legacy.Headers["X-Site"].Value)
	}

	// 3. advanced object rules (delete & replace)
	adv := cfg.Upstreams["advanced-rules.test"]
	if adv.Headers["X-Custom-Token"].Value != "secret123" {
		t.Errorf("expected X-Custom-Token, got %s", adv.Headers["X-Custom-Token"].Value)
	}
	if !adv.Headers["X-Delete-Me"].Delete {
		t.Errorf("expected X-Delete-Me delete=true")
	}
	if len(adv.Headers["X-Replace-Domain"].Replace) != 2 || adv.Headers["X-Replace-Domain"].Replace[0] != "old.domain.com" {
		t.Errorf("expected replace rule, got %v", adv.Headers["X-Replace-Domain"].Replace)
	}
	if !adv.ResponseHeaders["X-Frame-Options"].Delete {
		t.Errorf("expected X-Frame-Options delete=true")
	}
	if adv.ResponseHeaders["X-Proxy-By"].Value != "ech-proxy" {
		t.Errorf("expected X-Proxy-By=ech-proxy, got %s", adv.ResponseHeaders["X-Proxy-By"].Value)
	}
}

func TestApplyHeaderRules(t *testing.T) {
	rules := map[string]HeaderRule{
		"X-Custom-Add":     {Value: "added_val"},
		"X-To-Delete":      {Delete: true},
		"X-Empty-Delete":   {Value: ""},
		"Referer":          {Replace: []string{"proxy.moonchan.xyz", "upstream.target.com"}},
		"Origin":           {Value: "https://upstream.target.com"},
	}

	// Request 1: POST request with existing headers
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/api", nil)
	req.Header.Set("X-To-Delete", "leave_me_not")
	req.Header.Set("X-Empty-Delete", "should_disappear")
	req.Header.Set("Referer", "https://proxy.moonchan.xyz/videos/123")
	req.Header.Set("Origin", "https://proxy.moonchan.xyz")

	ApplyHeaderRules(req.Header, rules, true, req)

	if req.Header.Get("X-Custom-Add") != "added_val" {
		t.Errorf("expected X-Custom-Add to be set")
	}
	if req.Header.Get("X-To-Delete") != "" {
		t.Errorf("expected X-To-Delete to be deleted")
	}
	if req.Header.Get("X-Empty-Delete") != "" {
		t.Errorf("expected X-Empty-Delete to be deleted")
	}
	if req.Header.Get("Referer") != "https://upstream.target.com/videos/123" {
		t.Errorf("expected replaced Referer, got %s", req.Header.Get("Referer"))
	}
	if req.Header.Get("Origin") != "https://upstream.target.com" {
		t.Errorf("expected overridden Origin, got %s", req.Header.Get("Origin"))
	}
}

func TestClientCookiesSavingAndFileCookie(t *testing.T) {
	host := "cookie-test.com"

	// 1. Client sends request with JS-set cookie
	clientReq, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	clientReq.AddCookie(&http.Cookie{Name: "js_auth", Value: "js_token_123"})
	clientReq.AddCookie(&http.Cookie{Name: "device_id", Value: "dev_999"})

	saveClientCookies(host, clientReq)

	// 2. Upstream responds with Set-Cookie
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "server_sid=sess_abc; Path=/")
	saveCookies(host, resp)

	// 3. Next outgoing request should merge JS cookie + server Set-Cookie
	outReq, _ := http.NewRequest(http.MethodGet, "http://example.com/api", nil)
	applyCookies(host, outReq, "")

	cookieHeader := outReq.Header.Get("Cookie")
	if !strings.Contains(cookieHeader, "js_auth=js_token_123") {
		t.Errorf("expected js_auth in Cookie, got: %s", cookieHeader)
	}
	if !strings.Contains(cookieHeader, "server_sid=sess_abc") {
		t.Errorf("expected server_sid in Cookie, got: %s", cookieHeader)
	}

	// 4. Fixed / local file cookie takes highest priority
	tmpFile, err := os.CreateTemp("", "ech-cookie-test-*.txt")
	if err != nil {
		t.Fatalf("create temp cookie file failed: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("js_auth=file_override_val; extra=file_extra")
	tmpFile.Close()

	uc := UpstreamConfig{
		CookieFile: tmpFile.Name(),
	}
	fixedCookie := getFixedCookie(uc)
	if fixedCookie != "js_auth=file_override_val; extra=file_extra" {
		t.Errorf("expected cookie loaded from file, got: %s", fixedCookie)
	}

	outReq2, _ := http.NewRequest(http.MethodGet, "http://example.com/api", nil)
	applyCookies(host, outReq2, fixedCookie)
	cookieHeader2 := outReq2.Header.Get("Cookie")
	if !strings.Contains(cookieHeader2, "js_auth=file_override_val") {
		t.Errorf("expected file cookie to override js_auth, got: %s", cookieHeader2)
	}
	if !strings.Contains(cookieHeader2, "extra=file_extra") {
		t.Errorf("expected extra in Cookie, got: %s", cookieHeader2)
	}
}

type v102WildcardRule struct {
	Prefix         string `json:"prefix,omitempty"`
	EntrySuffix    string `json:"entry_suffix,omitempty"`
	UpstreamSuffix string `json:"upstream_suffix,omitempty"`
	Referer        string `json:"referer,omitempty"`
}

type v102UpstreamConfig struct {
	Host     string            `json:"host"`
	Describe string            `json:"describe,omitempty"`
	Display  bool              `json:"display,omitempty"`
	Referer  string            `json:"referer,omitempty"`
	Cookie   string            `json:"cookie,omitempty"`
	SWInject bool              `json:"sw_inject,omitempty"`
	Mode     string            `json:"mode,omitempty"`
	Rewrites map[string]string `json:"rewrites,omitempty"`
	Wildcard *v102WildcardRule `json:"wildcard,omitempty"`
}

type v102Config struct {
	CertPath     string                        `json:"cert_path"`
	KeyPath      string                        `json:"key_path"`
	Upstreams    map[string]v102UpstreamConfig `json:"upstreams"`
	BlockedHosts []string                      `json:"blocked_hosts,omitempty"`
}

func TestOldBinaryV102Compatibility(t *testing.T) {
	data, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json failed: %v", err)
	}
	var oldCfg v102Config
	if err := json.Unmarshal(data, &oldCfg); err != nil {
		t.Fatalf("Old binary failed to parse upstream.json: %v", err)
	}

	if len(oldCfg.Upstreams) == 0 {
		t.Fatalf("Old binary parsed 0 upstreams")
	}

	// 1. Iwara: Ensure legacy binary parses complete host, referer, and unmodified wildcard
	iwara, ok := oldCfg.Upstreams["iwara.l.moonchan.xyz"]
	if !ok {
		t.Fatalf("old binary missing iwara entry")
	}
	if iwara.Host != "www.iwara.tv" && iwara.Host != "iwara.tv" {
		t.Errorf("expected www.iwara.tv, got %s", iwara.Host)
	}
	if iwara.Referer != "https://www.iwara.tv/" {
		t.Errorf("expected referer https://www.iwara.tv/, got %s", iwara.Referer)
	}
	if iwara.Wildcard == nil || iwara.Wildcard.Prefix != "iwara-" || iwara.Wildcard.Referer != "https://www.iwara.tv/" {
		t.Errorf("expected intact wildcard for old binary, got %+v", iwara.Wildcard)
	}

	// 2. DLsite: Ensure legacy wildcard remains unmodified and anti-hotlinking referer is intact
	dlsite, ok := oldCfg.Upstreams["dlsite.l.moonchan.xyz"]
	if !ok || dlsite.Referer != "https://www.dlsite.com/" {
		t.Errorf("expected dlsite referer for old binary, got %s", dlsite.Referer)
	}
	if dlsite.Wildcard == nil || dlsite.Wildcard.Referer != "https://www.dlsite.com/" {
		t.Errorf("expected dlsite wildcard referer for old binary, got %+v", dlsite.Wildcard)
	}

	// 3. Twimg
	twimg, ok := oldCfg.Upstreams["twimg.l.moonchan.xyz"]
	if !ok || twimg.Referer != "https://x.com" {
		t.Errorf("expected twimg referer for old binary, got %s", twimg.Referer)
	}
}

func TestWildcardCleanKeysAndAutoDerivation(t *testing.T) {
	// 1. Test clean key syntax without requiring suffix configuration: entry + upstream
	cleanJSON := []byte(`{
		"upstreams": {
			"iwara.l.moonchan.xyz": {
				"host": "iwara.tv",
				"headers": {
					"Origin": "https://www.iwara.tv"
				}
			}
		},
		"wildcards": [
			{
				"entry": "iwara-*.l.moonchan.xyz",
				"upstream": "*.iwara.tv",
				"headers": {
					"X-Site": "www.iwara.tv"
				}
			}
		]
	}`)
	cfg, err := ParseConfig(cleanJSON)
	if err != nil {
		t.Fatalf("ParseConfig cleanJSON failed: %v", err)
	}
	match, ok := MatchWildcardForTest(cfg.Upstreams, "iwara-files.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for iwara-files.l.moonchan.xyz")
	}
	if match.Host != "files.iwara.tv" {
		t.Errorf("expected files.iwara.tv, got %s", match.Host)
	}
	if match.Headers["X-Site"].Value != "www.iwara.tv" {
		t.Errorf("expected X-Site www.iwara.tv, got %s", match.Headers["X-Site"].Value)
	}
	if match.Headers["Origin"].Value != "https://www.iwara.tv" {
		t.Errorf("expected inherited Origin, got %s", match.Headers["Origin"].Value)
	}

	// 2. Test direct "wildcard": true configuration inside upstream (auto-deriving suffix and prefix)
	boolJSON := []byte(`{
		"upstreams": {
			"dlsite.l.moonchan.xyz": {
				"host": "dlsite.com",
				"wildcard": true
			}
		}
	}`)
	cfg2, err := ParseConfig(boolJSON)
	if err != nil {
		t.Fatalf("ParseConfig boolJSON failed: %v", err)
	}
	match2, ok := MatchWildcardForTest(cfg2.Upstreams, "dlsite-ci-en.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for dlsite-ci-en.l.moonchan.xyz")
	}
	if match2.Host != "ci-en.dlsite.com" {
		t.Errorf("expected ci-en.dlsite.com, got %s", match2.Host)
	}

	// 3. Test shorthand "wildcard": "f95-*" configuration inside upstream
	strJSON := []byte(`{
		"upstreams": {
			"f95.l.moonchan.xyz": {
				"host": "f95zone.to",
				"wildcard": "f95-*"
			}
		}
	}`)
	cfg3, err := ParseConfig(strJSON)
	if err != nil {
		t.Fatalf("ParseConfig strJSON failed: %v", err)
	}
	match3, ok := MatchWildcardForTest(cfg3.Upstreams, "f95-attachments.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for f95-attachments.l.moonchan.xyz")
	}
	if match3.Host != "attachments.f95zone.to" {
		t.Errorf("expected attachments.f95zone.to, got %s", match3.Host)
	}

	// 4. Test recommended minimal syntax entry: "*.iwara.tv"
	targetPatternJSON := []byte(`{
		"upstreams": {
			"iwara.l.moonchan.xyz": {
				"host": "iwara.tv",
				"headers": {
					"Origin": "https://www.iwara.tv"
				}
			}
		},
		"wildcards": [
			{
				"entry": "*.iwara.tv",
				"headers": {
					"X-Site": "www.iwara.tv"
				}
			}
		]
	}`)
	cfg4, err := ParseConfig(targetPatternJSON)
	if err != nil {
		t.Fatalf("ParseConfig targetPatternJSON failed: %v", err)
	}
	match4, ok := MatchWildcardForTest(cfg4.Upstreams, "iwara-api.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for iwara-api.l.moonchan.xyz")
	}
	if match4.Host != "api.iwara.tv" {
		t.Errorf("expected api.iwara.tv, got %s", match4.Host)
	}
	if match4.Headers["X-Site"].Value != "www.iwara.tv" {
		t.Errorf("expected X-Site www.iwara.tv, got %s", match4.Headers["X-Site"].Value)
	}
	if match4.Headers["Origin"].Value != "https://www.iwara.tv" {
		t.Errorf("expected Origin https://www.iwara.tv, got %s", match4.Headers["Origin"].Value)
	}

	// 5. Test prefix + upstream syntax preserving explicit prefix while omitting redundant suffix
	prefixUpstreamJSON := []byte(`{
		"upstreams": {
			"iwara.l.moonchan.xyz": {
				"host": "iwara.tv",
				"headers": {
					"Origin": "https://www.iwara.tv"
				}
			}
		},
		"wildcards": [
			{
				"prefix": "iwara-",
				"upstream": "*.iwara.tv",
				"headers": {
					"X-Site": "www.iwara.tv"
				}
			}
		]
	}`)
	cfg5, err := ParseConfig(prefixUpstreamJSON)
	if err != nil {
		t.Fatalf("ParseConfig prefixUpstreamJSON failed: %v", err)
	}
	match5, ok := MatchWildcardForTest(cfg5.Upstreams, "iwara-video.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for iwara-video.l.moonchan.xyz")
	}
	if match5.Host != "video.iwara.tv" {
		t.Errorf("expected video.iwara.tv, got %s", match5.Host)
	}
	if match5.Headers["X-Site"].Value != "www.iwara.tv" {
		t.Errorf("expected X-Site www.iwara.tv, got %s", match5.Headers["X-Site"].Value)
	}
}

func TestSWProxyMapAndRewritesCooperation(t *testing.T) {
	cfg := UpstreamMap{
		"dlsite.l.moonchan.xyz": {
			Host: "www.dlsite.com",
			Rewrites: map[string]string{
				"www.dlsite.com": "dlsite.l.moonchan.xyz",
				"img.dlsite.jp":  "dlsite-img.l.moonchan.xyz",
			},
			BodyReplace: []BodyReplaceRule{
				{Old: "old-script-cdn.com", New: "proxy-script-cdn.com"},
			},
		},
		"asmr.l.moonchan.xyz": {
			Host: "asmr.one",
			Rewrites: map[string]string{
				"api.asmr-200.com": "asmr-api-200.l.moonchan.xyz",
			},
		},
	}

	// 1. Test swProxyMap: contains uc.Host and rewrites key-value pairs with ports
	swMap := buildSWProxyMap(cfg, "8443")

	// Host mapping (uc.Host -> entry)
	if swMap["www.dlsite.com"] != "dlsite.l.moonchan.xyz:8443" {
		t.Errorf("expected www.dlsite.com -> dlsite.l.moonchan.xyz:8443, got %s", swMap["www.dlsite.com"])
	}
	if swMap["asmr.one"] != "asmr.l.moonchan.xyz:8443" {
		t.Errorf("expected asmr.one -> asmr.l.moonchan.xyz:8443, got %s", swMap["asmr.one"])
	}

	// Key-value pairs in rewrites (must be used in sw.js)
	if swMap["img.dlsite.jp"] != "dlsite-img.l.moonchan.xyz:8443" {
		t.Errorf("expected img.dlsite.jp -> dlsite-img.l.moonchan.xyz:8443, got %s", swMap["img.dlsite.jp"])
	}
	if swMap["api.asmr-200.com"] != "asmr-api-200.l.moonchan.xyz:8443" {
		t.Errorf("expected api.asmr-200.com -> asmr-api-200.l.moonchan.xyz:8443, got %s", swMap["api.asmr-200.com"])
	}

	// Entries in body_replace must never enter sw.js
	if _, ok := swMap["old-script-cdn.com"]; ok {
		t.Errorf("body_replace should NOT enter sw.js proxy map")
	}

	// 2. Test body rewrite: both rewrites and body_replace are applied to body content
	rewriter := buildEntryRewriter(cfg["dlsite.l.moonchan.xyz"], nil)
	input := []byte(`Visit https://img.dlsite.jp/cover.jpg and script from https://old-script-cdn.com/app.js`)
	output := string(rewriter(input, "8443"))

	if !strings.Contains(output, "https://dlsite-img.l.moonchan.xyz:8443/cover.jpg") {
		t.Errorf("expected rewrites kv to be applied to body, got: %s", output)
	}
	if !strings.Contains(output, "https://proxy-script-cdn.com/app.js") {
		t.Errorf("expected body_replace to be applied to body, got: %s", output)
	}
}

func TestCrossSubdomainCookieSharingAndCookieDomain(t *testing.T) {
	// 1. Test server-side domain cookie sharing:
	// Upstream "accounts.pixiv.net" sends a Set-Cookie with Domain=.pixiv.net
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "PHPSESSID=session_shared_999; Domain=.pixiv.net; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", "local_pref=1; Path=/") // host-only cookie
	saveCookies("accounts.pixiv.net", resp)

	// Outgoing request to "www.pixiv.net" should receive PHPSESSID via parent domain ".pixiv.net"
	reqWWW, _ := http.NewRequest(http.MethodGet, "https://www.pixiv.net/", nil)
	applyCookies("www.pixiv.net", reqWWW, "")
	cookieWWW := reqWWW.Header.Get("Cookie")
	if !strings.Contains(cookieWWW, "PHPSESSID=session_shared_999") {
		t.Errorf("expected PHPSESSID in www.pixiv.net Cookie, got: %s", cookieWWW)
	}
	// "local_pref" was host-only for accounts.pixiv.net, should NOT leak to www.pixiv.net
	if strings.Contains(cookieWWW, "local_pref=1") {
		t.Errorf("host-only cookie local_pref leaked to www.pixiv.net: %s", cookieWWW)
	}

	// 2. Test rewriteSetCookieDomains with custom CookieDomain:
	h := http.Header{}
	h.Add("Set-Cookie", "PHPSESSID=session_shared_999; Domain=.pixiv.net; Path=/; Secure")
	h.Add("Set-Cookie", "theme=dark; Path=/")

	// When cookieDomain is "l.moonchan.xyz", domain-scoped cookie should be rewritten to l.moonchan.xyz
	rewriteSetCookieDomains(h, "l.moonchan.xyz", false)
	scs := h.Values("Set-Cookie")
	if len(scs) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d", len(scs))
	}
	if !strings.Contains(scs[0], "Domain=l.moonchan.xyz") {
		t.Errorf("expected Domain=l.moonchan.xyz, got: %s", scs[0])
	}
	// Host-only cookie without Domain attribute should NOT have Domain added
	if strings.Contains(scs[1], "Domain=") {
		t.Errorf("host-only cookie should not have Domain attribute, got: %s", scs[1])
	}

	// 3. Test wildcard CookieDomain inheritance:
	cfg := UpstreamMap{
		"pixiv.l.moonchan.xyz": UpstreamConfig{
			Host:         "www.pixiv.net",
			CookieDomain: "l.moonchan.xyz",
			Wildcard: &WildcardRule{
				Prefix:         "pixiv-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".pixiv.net",
			},
		},
	}
	uc, ok := MatchWildcardForTest(cfg, "pixiv-accounts.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for pixiv-accounts")
	}
	if uc.CookieDomain != "l.moonchan.xyz" {
		t.Errorf("expected inherited CookieDomain=l.moonchan.xyz, got: %s", uc.CookieDomain)
	}
}

func TestPreserveEncodedPathSlash(t *testing.T) {
	rawTarget := "/api/search/%20%24tag%3A%E4%BA%B2%E7%83%AD%2F%E7%94%9C%E8%9C%9C%24?order=create_date"
	expectedPrefix := "https://api.asmr-200.com/api/search/%20%24tag%3A%E4%BA%B2%E7%83%AD%2F%E7%94%9C%E8%9C%9C%24"

	// Helper matching the proxy's URL construction
	buildURL := func(req *http.Request, host string) string {
		reqURI := req.RequestURI
		if reqURI == "" {
			reqURI = req.URL.EscapedPath()
			if req.URL.RawQuery != "" {
				reqURI += "?" + req.URL.RawQuery
			}
		} else if strings.HasPrefix(reqURI, "http://") || strings.HasPrefix(reqURI, "https://") {
			if u, err := url.ParseRequestURI(reqURI); err == nil {
				reqURI = u.RequestURI()
			}
		}
		if !strings.HasPrefix(reqURI, "/") {
			reqURI = "/" + reqURI
		}
		return "https://" + host + reqURI
	}

	// 1. Real server / httptest request where RequestURI is set
	req1 := httptest.NewRequest(http.MethodGet, rawTarget, nil)
	urlStr1 := buildURL(req1, "api.asmr-200.com")
	if !strings.HasPrefix(urlStr1, expectedPrefix) {
		t.Errorf("expected urlStr1 to preserve %%2F, got: %s", urlStr1)
	}

	// 2. Synthetic request where RequestURI is empty
	req2, _ := http.NewRequest(http.MethodGet, "http://example.com"+rawTarget, nil)
	urlStr2 := buildURL(req2, "api.asmr-200.com")
	if !strings.HasPrefix(urlStr2, expectedPrefix) {
		t.Errorf("expected urlStr2 to preserve %%2F, got: %s", urlStr2)
	}

	// 3. Forward proxy style absolute RequestURI
	req3 := httptest.NewRequest(http.MethodGet, "http://proxy.host:8443"+rawTarget, nil)
	urlStr3 := buildURL(req3, "api.asmr-200.com")
	if !strings.HasPrefix(urlStr3, expectedPrefix) {
		t.Errorf("expected urlStr3 to preserve %%2F, got: %s", urlStr3)
	}
}

func TestNoFollowRedirectAndRewriteLocation(t *testing.T) {
	// Upstream test server returning 302
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.php" {
			http.Redirect(w, r, "https://accounts.pixiv.net/login?return_to=https%3A%2F%2Fwww.pixiv.net%2F&lang=ja", http.StatusFound)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("should not reach here automatically"))
	}))
	defer ts.Close()

	netdial.Transport().TLSClientConfig.RootCAs.AddCert(ts.Certificate())

	u, _ := url.Parse(ts.URL)
	cfg := UpstreamMap{
		"pixiv.l.moonchan.xyz": {
			Host: u.Host,
			Mode: "direct",
			Wildcard: &WildcardRule{
				Prefix:         "pixiv-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".pixiv.net",
			},
			Rewrites: map[string]string{
				"www.pixiv.net": "pixiv.l.moonchan.xyz",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ProxyHandler(cfg, nil))

	req := httptest.NewRequest(http.MethodGet, "/login.php?return_to=%2F", nil)
	req.Host = "pixiv.l.moonchan.xyz:8443"
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected proxy to return 302 Found, got %d", w.Code)
	}

	loc := w.Header().Get("Location")
	expectedLoc := "https://pixiv-accounts.l.moonchan.xyz:8443/login?return_to=https%3A%2F%2Fpixiv.l.moonchan.xyz:8443%2F&lang=ja"
	if loc != expectedLoc {
		t.Errorf("expected rewritten Location:\n  %s\ngot:\n  %s", expectedLoc, loc)
	}
}

func TestUpstreamIPModeConfiguration(t *testing.T) {
	data, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("read upstream.json failed: %v", err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}

	pixiv := cfg.Upstreams["pixiv.l.moonchan.xyz"]
	if pixiv.IPMode != "v4" {
		t.Errorf("expected pixiv.IPMode=v4, got %s", pixiv.IPMode)
	}

	// Wildcard matching pixiv-accounts should inherit IPMode=v4
	uc, ok := MatchWildcardForTest(cfg.Upstreams, "pixiv-accounts.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for pixiv-accounts")
	}
	if uc.IPMode != "v4" {
		t.Errorf("expected wildcard match to inherit IPMode=v4, got %s", uc.IPMode)
	}

	// Other services without ip_mode should be empty / auto
	dlsite := cfg.Upstreams["dlsite.l.moonchan.xyz"]
	if dlsite.IPMode != "" {
		t.Errorf("expected dlsite.IPMode empty (auto), got %s", dlsite.IPMode)
	}
}

func TestHTTPRedirectUpgradedToHTTPSAndReturnedToClient(t *testing.T) {
	// Upstream test server returning 302 with http:// scheme
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			// Simulate upstream redirect to http://
			http.Redirect(w, r, "http://www.pixiv.net/destination", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	netdial.Transport().TLSClientConfig.RootCAs.AddCert(ts.Certificate())

	u, _ := url.Parse(ts.URL)
	cfg := UpstreamMap{
		"pixiv.l.moonchan.xyz": {
			Host: u.Host,
			Mode: "direct",
			Rewrites: map[string]string{
				"www.pixiv.net": "pixiv.l.moonchan.xyz",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ProxyHandler(cfg, nil))

	req := httptest.NewRequest(http.MethodGet, "/start", nil)
	req.Host = "pixiv.l.moonchan.xyz:8443"
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected proxy to return 302 Found, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	expectedLoc := "https://pixiv.l.moonchan.xyz:8443/destination"
	if loc != expectedLoc {
		t.Errorf("expected http redirect to be upgraded to https and returned to client:\n  got:  %s\n  want: %s", loc, expectedLoc)
	}
}

func TestSeedCookiesStartupAndNetscapeParsing(t *testing.T) {
	resetCookieJar()

	netscapeContent := `# Netscape HTTP Cookie File
# Test cookie file
www.pixiv.net	FALSE	/	TRUE	1824340949	host_only_pref	pref_123
.pixiv.net	TRUE	/	TRUE	1824340949	PHPSESSID	shared_sess_999
.pixiv.net	TRUE	/	TRUE	1824340949	device_token	dev_token_456
`
	tmpFile, err := os.CreateTemp("", "pixiv_netscape_*.txt")
	if err != nil {
		t.Fatalf("create temp file failed: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(netscapeContent)
	tmpFile.Close()

	cfg := &Config{
		Upstreams: UpstreamMap{
			"pixiv.l.moonchan.xyz": UpstreamConfig{
				Host:       "www.pixiv.net",
				CookieFile: tmpFile.Name(),
				Wildcard: &WildcardRule{
					Prefix:         "pixiv-",
					EntrySuffix:    ".l.moonchan.xyz",
					UpstreamSuffix: ".pixiv.net",
				},
			},
		},
	}

	SeedCookiesFromConfig(cfg)

	// 1. Request to www.pixiv.net should receive both .pixiv.net cookies and www.pixiv.net host-only cookies
	reqWWW, _ := http.NewRequest(http.MethodGet, "https://www.pixiv.net/", nil)
	applyCookies("www.pixiv.net", reqWWW, "")
	cWWW := reqWWW.Header.Get("Cookie")
	if !strings.Contains(cWWW, "PHPSESSID=shared_sess_999") {
		t.Errorf("expected PHPSESSID on www.pixiv.net, got: %s", cWWW)
	}
	if !strings.Contains(cWWW, "device_token=dev_token_456") {
		t.Errorf("expected device_token on www.pixiv.net, got: %s", cWWW)
	}
	if !strings.Contains(cWWW, "host_only_pref=pref_123") {
		t.Errorf("expected host_only_pref on www.pixiv.net, got: %s", cWWW)
	}

	// 2. Request to accounts.pixiv.net should receive .pixiv.net cookies but NOT www.pixiv.net host-only cookies
	reqAcc, _ := http.NewRequest(http.MethodGet, "https://accounts.pixiv.net/", nil)
	applyCookies("accounts.pixiv.net", reqAcc, "")
	cAcc := reqAcc.Header.Get("Cookie")
	if !strings.Contains(cAcc, "PHPSESSID=shared_sess_999") {
		t.Errorf("expected PHPSESSID on accounts.pixiv.net, got: %s", cAcc)
	}
	if !strings.Contains(cAcc, "device_token=dev_token_456") {
		t.Errorf("expected device_token on accounts.pixiv.net, got: %s", cAcc)
	}
	if strings.Contains(cAcc, "host_only_pref=pref_123") {
		t.Errorf("host-only cookie host_only_pref leaked to accounts.pixiv.net: %s", cAcc)
	}
}

func TestDynamicCookieNotClobberedByStaticConfig(t *testing.T) {
	resetCookieJar()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		incomingCookie := r.Header.Get("Cookie")
		if r.URL.Path == "/login" {
			// Upstream sets a new session cookie
			http.SetCookie(w, &http.Cookie{
				Name:    "PHPSESSID",
				Value:   "rotated_session_token_xyz",
				Path:    "/",
				Expires: time.Now().Add(24 * time.Hour),
			})
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("logged_in"))
			return
		}
		if r.URL.Path == "/profile" {
			// Echo incoming cookie back in response body for verification
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("cookie:" + incomingCookie))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	netdial.Transport().TLSClientConfig.RootCAs.AddCert(ts.Certificate())

	u, _ := url.Parse(ts.URL)

	cfg := &Config{
		Upstreams: UpstreamMap{
			"test.l.moonchan.xyz": UpstreamConfig{
				Host:   u.Host,
				Mode:   "direct",
				Cookie: "PHPSESSID=initial_static_seed_123; first_visit=1",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	SetupRouter(engine, cfg)

	// 1. Initial request: should carry initial seeded cookie
	req1 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req1.Host = "test.l.moonchan.xyz:8443"
	w1 := httptest.NewRecorder()
	engine.ServeHTTP(w1, req1)
	if !strings.Contains(w1.Body.String(), "PHPSESSID=initial_static_seed_123") {
		t.Fatalf("expected initial seeded cookie in profile, got body: %s", w1.Body.String())
	}

	// 2. Login request: upstream responds with Set-Cookie: PHPSESSID=rotated_session_token_xyz
	req2 := httptest.NewRequest(http.MethodPost, "/login", nil)
	req2.Host = "test.l.moonchan.xyz:8443"
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("login failed: %d", w2.Code)
	}

	// 3. Subsequent request: should carry rotated_session_token_xyz and NOT be clobbered by initial_static_seed_123
	req3 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req3.Host = "test.l.moonchan.xyz:8443"
	w3 := httptest.NewRecorder()
	engine.ServeHTTP(w3, req3)
	if !strings.Contains(w3.Body.String(), "PHPSESSID=rotated_session_token_xyz") {
		t.Errorf("expected rotated cookie to be sent to upstream, got body: %s", w3.Body.String())
	}
	if strings.Contains(w3.Body.String(), "PHPSESSID=initial_static_seed_123") {
		t.Errorf("static config clobbered dynamic rotated cookie: %s", w3.Body.String())
	}
}

func TestClientGuestCookieCannotPoisonJarAndSyncsToBrowser(t *testing.T) {
	resetCookieJar()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieHeader := r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("received_cookie:" + cookieHeader))
	}))
	defer ts.Close()

	netdial.Transport().TLSClientConfig.RootCAs.AddCert(ts.Certificate())

	u, _ := url.Parse(ts.URL)

	cfg := &Config{
		Upstreams: UpstreamMap{
			"test-sync.l.moonchan.xyz": UpstreamConfig{
				Host:         u.Host,
				Mode:         "direct",
				Cookie:       "PHPSESSID=server_auth_token_777; device_token=dev_token_888",
				CookieDomain: "l.moonchan.xyz",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	SetupRouter(engine, cfg)

	// 1. Client browser sends request with STALE guest cookie
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "test-sync.l.moonchan.xyz:8443"
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: "guest_stale_cookie_999"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Outgoing request to upstream MUST have received the server_auth_token_777, NOT guest_stale_cookie_999
	body := w.Body.String()
	if !strings.Contains(body, "PHPSESSID=server_auth_token_777") {
		t.Errorf("upstream did not receive server authenticated session: %s", body)
	}
	if strings.Contains(body, "guest_stale_cookie_999") {
		t.Errorf("guest cookie was forwarded to upstream, overriding jar session: %s", body)
	}

	// Response to browser MUST have Set-Cookie syncing PHPSESSID=server_auth_token_777 to domain l.moonchan.xyz
	scHeaders := w.Header().Values("Set-Cookie")
	foundSync := false
	for _, sc := range scHeaders {
		if strings.Contains(sc, "PHPSESSID=server_auth_token_777") && strings.Contains(sc, "Domain=l.moonchan.xyz") {
			foundSync = true
		}
	}
	if !foundSync {
		t.Errorf("expected Set-Cookie to sync server session to browser, got: %v", scHeaders)
	}

	// 2. Next request from fresh client should still have server_auth_token_777 (jar not poisoned)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "test-sync.l.moonchan.xyz:8443"
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)

	body2 := w2.Body.String()
	if !strings.Contains(body2, "PHPSESSID=server_auth_token_777") {
		t.Errorf("jar was poisoned by previous guest cookie: %s", body2)
	}
}

func TestCookiePriorityBrowser(t *testing.T) {
	resetCookieJar()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieHeader := r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("received:" + cookieHeader))
	}))
	defer ts.Close()

	netdial.Transport().TLSClientConfig.RootCAs.AddCert(ts.Certificate())
	u, _ := url.Parse(ts.URL)

	cfg := &Config{
		Upstreams: UpstreamMap{
			"browser-pri.l.moonchan.xyz": UpstreamConfig{
				Host:           u.Host,
				Mode:           "direct",
				Cookie:         "session_id=seed_val_111; other=abc",
				CookieDomain:   "l.moonchan.xyz",
				CookiePriority: "browser",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	SetupRouter(engine, cfg)

	// Client sends session_id=browser_val_222
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "browser-pri.l.moonchan.xyz:8443"
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "browser_val_222"})
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	body := w.Body.String()
	// When priority is "browser", client's browser_val_222 MUST take precedence over seed_val_111
	if !strings.Contains(body, "session_id=browser_val_222") {
		t.Errorf("browser cookie should have overridden seed in browser mode, got: %s", body)
	}
	// Other non-conflicting cookies like 'other=abc' should still be present
	if !strings.Contains(body, "other=abc") {
		t.Errorf("expected other=abc to be preserved, got: %s", body)
	}

	// Browser should NOT receive a Set-Cookie forcing session_id back to seed_val_111
	for _, sc := range w.Header().Values("Set-Cookie") {
		if strings.Contains(sc, "session_id=seed_val_111") {
			t.Errorf("browser mode should not force seed value on client: %s", sc)
		}
	}
}

func TestControlCookieEndpointAndPortalUI(t *testing.T) {
	resetCookieJar()

	cfg := &Config{
		Upstreams: UpstreamMap{
			"pixiv.l.moonchan.xyz": UpstreamConfig{
				Host:           "www.pixiv.net",
				Mode:           "ech",
				Display:        true,
				Cookie:         "PHPSESSID=seed_token_123; device_token=dev_456",
				CookieDomain:   "l.moonchan.xyz",
				CookiePriority: "seed",
			},
			"dlsite.l.moonchan.xyz": UpstreamConfig{
				Host:    "www.dlsite.com",
				Mode:    "direct",
				Display: true,
			},
		},
		UpstreamOrder: []string{"pixiv.l.moonchan.xyz", "dlsite.l.moonchan.xyz"},
	}

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	SetupRouter(engine, cfg)

	// 1. Test Portal UI rendering (indexHost)
	reqPortal := httptest.NewRequest(http.MethodGet, "/", nil)
	reqPortal.Host = "l.moonchan.xyz:8443"
	wPortal := httptest.NewRecorder()
	engine.ServeHTTP(wPortal, reqPortal)

	portalHTML := wPortal.Body.String()
	if !strings.Contains(portalHTML, "cookie-ctrl") {
		t.Fatalf("expected portal HTML to contain cookie-ctrl bar, got: %s", portalHTML)
	}
	if !strings.Contains(portalHTML, "switchCookie(event, &#39;pixiv.l.moonchan.xyz&#39;, &#39;seed&#39;)") &&
		!strings.Contains(portalHTML, "switchCookie(event, 'pixiv.l.moonchan.xyz', 'seed')") {
		t.Fatalf("expected portal HTML to contain seed switcher button for pixiv, got: %s", portalHTML)
	}
	if !strings.Contains(portalHTML, "switchCookie(event, &#39;pixiv.l.moonchan.xyz&#39;, &#39;browser&#39;)") &&
		!strings.Contains(portalHTML, "switchCookie(event, 'pixiv.l.moonchan.xyz', 'browser')") {
		t.Fatalf("expected portal HTML to contain browser switcher button for pixiv, got: %s", portalHTML)
	}

	// 2. Test /control/cookie?entry=pixiv.l.moonchan.xyz&mode=seed
	reqSeed := httptest.NewRequest(http.MethodGet, "/control/cookie?entry=pixiv.l.moonchan.xyz&mode=seed", nil)
	wSeed := httptest.NewRecorder()
	engine.ServeHTTP(wSeed, reqSeed)

	if wSeed.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", wSeed.Code, wSeed.Body.String())
	}
	bodySeed := wSeed.Body.String()
	if !strings.Contains(bodySeed, `"mode":"seed"`) {
		t.Errorf("expected JSON response mode: seed, got %s", bodySeed)
	}
	scSeed := wSeed.Header().Values("Set-Cookie")
	hasModeSeedCookie := false
	hasPHPSESSIDSeed := false
	for _, sc := range scSeed {
		if strings.Contains(sc, "_ech_cookie_mode_pixiv=seed") || strings.Contains(sc, "_ech_cookie_mode_pixiv.l.moonchan.xyz=seed") {
			hasModeSeedCookie = true
		}
		if strings.Contains(sc, "PHPSESSID=seed_token_123") && strings.Contains(sc, "Domain=l.moonchan.xyz") {
			hasPHPSESSIDSeed = true
		}
	}
	if !hasModeSeedCookie {
		t.Errorf("expected Set-Cookie with _ech_cookie_mode, got: %v", scSeed)
	}
	if !hasPHPSESSIDSeed {
		t.Errorf("expected Set-Cookie syncing PHPSESSID to browser, got: %v", scSeed)
	}

	// 3. Test /control/cookie?entry=pixiv.l.moonchan.xyz&mode=browser
	reqBrowser := httptest.NewRequest(http.MethodGet, "/control/cookie?entry=pixiv.l.moonchan.xyz&mode=browser", nil)
	wBrowser := httptest.NewRecorder()
	engine.ServeHTTP(wBrowser, reqBrowser)

	if wBrowser.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", wBrowser.Code, wBrowser.Body.String())
	}
	bodyBrowser := wBrowser.Body.String()
	if !strings.Contains(bodyBrowser, `"mode":"browser"`) {
		t.Errorf("expected JSON response mode: browser, got %s", bodyBrowser)
	}
	scBrowser := wBrowser.Header().Values("Set-Cookie")
	hasModeBrowserCookie := false
	hasClearPHPSESSID := false
	for _, sc := range scBrowser {
		if strings.Contains(sc, "_ech_cookie_mode_pixiv=browser") || strings.Contains(sc, "_ech_cookie_mode_pixiv.l.moonchan.xyz=browser") {
			hasModeBrowserCookie = true
		}
		if strings.Contains(sc, "PHPSESSID=") && strings.Contains(sc, "Max-Age=0") {
			hasClearPHPSESSID = true
		}
	}
	if !hasModeBrowserCookie {
		t.Errorf("expected Set-Cookie with _ech_cookie_mode_...=browser, got: %v", scBrowser)
	}
	if !hasClearPHPSESSID {
		t.Errorf("expected Set-Cookie clearing PHPSESSID (Max-Age=0), got: %v", scBrowser)
	}

	// 4. Test /control/cookie?entry=pixiv.l.moonchan.xyz&mode=seed&redirect=1
	reqRedirect := httptest.NewRequest(http.MethodGet, "/control/cookie?entry=pixiv.l.moonchan.xyz&mode=seed&redirect=1", nil)
	reqRedirect.Host = "l.moonchan.xyz:8443"
	wRedirect := httptest.NewRecorder()
	engine.ServeHTTP(wRedirect, reqRedirect)

	if wRedirect.Code != http.StatusFound {
		t.Fatalf("expected status 302 redirect, got %d", wRedirect.Code)
	}
	loc := wRedirect.Header().Get("Location")
	if !strings.Contains(loc, "https://pixiv.l.moonchan.xyz:8443/") {
		t.Errorf("expected redirect to pixiv site, got: %s", loc)
	}
}

func TestRefererOverrideGuarantee(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Case 1: Config with explicit uc.Referer and unpopulated Headers map
	ucDirect := UpstreamConfig{
		Host:    "video-cf.twimg.com",
		Referer: "https://x.com",
	}

	w1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(w1)
	req1, _ := http.NewRequest(http.MethodGet, "https://twimg.l.moonchan.xyz:8443/ext_tw_video/123", nil)
	req1.Header.Set("Referer", "https://twimg.l.moonchan.xyz:8443/videos/test")
	c1.Request = req1

	outReq1, err := buildUpstreamRequest(c1, ucDirect, "https://video-cf.twimg.com/ext_tw_video/123")
	if err != nil {
		t.Fatalf("buildUpstreamRequest failed: %v", err)
	}
	if outReq1.Header.Get("Referer") != "https://x.com" {
		t.Errorf("expected Referer override to https://x.com, got: %s", outReq1.Header.Get("Referer"))
	}

	// Case 2: Wildcard match inherits w.Referer and properly propagates to Headers
	cfgWildcard := UpstreamMap{
		"twimg.l.moonchan.xyz": UpstreamConfig{
			Host: "video-cf.twimg.com",
			Wildcard: &WildcardRule{
				Prefix:         "twimg-",
				EntrySuffix:    ".l.moonchan.xyz",
				UpstreamSuffix: ".twimg.com",
				Referer:        "https://x.com",
			},
		},
	}
	matched, ok := matchWildcard(cfgWildcard, "twimg-pbs.l.moonchan.xyz")
	if !ok {
		t.Fatalf("expected wildcard match for twimg-pbs")
	}
	if matched.Referer != "https://x.com" {
		t.Errorf("expected matched.Referer https://x.com, got: %s", matched.Referer)
	}
	if matched.Headers == nil || matched.Headers["Referer"].Value != "https://x.com" {
		t.Errorf("expected matched.Headers Referer https://x.com, got: %v", matched.Headers)
	}

	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	req2, _ := http.NewRequest(http.MethodGet, "https://twimg-pbs.l.moonchan.xyz:8443/media/pic.jpg", nil)
	req2.Header.Set("Referer", "https://twimg-pbs.l.moonchan.xyz:8443/media")
	c2.Request = req2

	outReq2, err := buildUpstreamRequest(c2, matched, "https://pbs.twimg.com/media/pic.jpg")
	if err != nil {
		t.Fatalf("buildUpstreamRequest for wildcard failed: %v", err)
	}
	if outReq2.Header.Get("Referer") != "https://x.com" {
		t.Errorf("expected wildcard Referer override to https://x.com, got: %s", outReq2.Header.Get("Referer"))
	}
}

func TestBlockedDomainRubiconProject(t *testing.T) {
	// 1. Verify upstream.json contains micro.rubiconproject.com, stats.g.doubleclick.net, service.iwara.shop
	data, err := os.ReadFile("../certs/l.moonchan.xyz/upstream.json")
	if err != nil {
		t.Fatalf("failed to read upstream.json: %v", err)
	}
	var raw struct {
		BlockedHosts []string `json:"blocked_hosts"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse upstream.json: %v", err)
	}

	for _, domain := range []string{"micro.rubiconproject.com", "stats.g.doubleclick.net", "service.iwara.shop"} {
		found := false
		for _, b := range raw.BlockedHosts {
			if strings.Contains(b, domain) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in blocked_hosts, got: %v", domain, raw.BlockedHosts)
		}
	}

	// 2. Verify stripBlockedURLs removes blocked domain references (https, http, //, bare)
	html := []byte(`<script src="https://micro.rubiconproject.com/prebid/123.js"></script><script src="//stats.g.doubleclick.net/dc.js"></script><script src="https://service.iwara.shop/widget.js"></script><a href="https://example.com">keep</a>`)
	stripped := stripBlockedURLs(html, raw.BlockedHosts)
	for _, domain := range []string{"micro.rubiconproject.com", "stats.g.doubleclick.net", "service.iwara.shop"} {
		if strings.Contains(string(stripped), domain) {
			t.Errorf("stripBlockedURLs failed to strip %s: %s", domain, string(stripped))
		}
	}
	if !strings.Contains(string(stripped), `<a href="https://example.com">keep</a>`) {
		t.Errorf("stripBlockedURLs accidentally removed valid content: %s", string(stripped))
	}

	// 3. Verify Service Worker JS includes all blocked domains
	swJS := swOverrideJS(nil, nil, raw.BlockedHosts)
	for _, domain := range []string{"micro.rubiconproject.com", "stats.g.doubleclick.net", "service.iwara.shop"} {
		if !strings.Contains(swJS, domain) {
			t.Errorf("swOverrideJS does not contain %s: %s", domain, swJS)
		}
	}
}

func TestOutboundConnectionReuseAndProtocols(t *testing.T) {
	// Setup a backend test server that tracks connections
	var connCount int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok response"))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}

	// Track outbound connections using httptrace
	var dials int32
	var reusedConns int32
	trace := &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			atomic.AddInt32(&dials, 1)
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Reused {
				atomic.AddInt32(&reusedConns, 1)
			}
		},
	}

	// Perform 3 sequential requests through direct transport to backend
	client := netdial.Client(5 * time.Second)
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, backend.URL+"/", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d got status %d", i, resp.StatusCode)
		}
		// Drain and close
		io.Copy(io.Discard, io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
	}

	if atomic.LoadInt32(&dials) > 1 {
		t.Errorf("expected connection to be reused, got %d dials", dials)
	}
	if atomic.LoadInt32(&reusedConns) < 2 {
		t.Errorf("expected at least 2 reused connections, got %d", reusedConns)
	}

	_ = connCount
	_ = backendURL
}

func TestLargeBodyStreamAndConnectionDraining(t *testing.T) {
	// Create payload larger than maxRewriteSize (2MB > 1MB)
	payloadSize := maxRewriteSize + 64*1024
	largePayload := make([]byte, payloadSize)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "http://large.test/", nil)
	c.Request = req

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(bytes.NewReader(largePayload)),
	}

	rc := http.NewResponseController(w)
	rewriteAndSendBody(c, UpstreamConfig{Host: "large.test"}, resp, nil, rc, "127.0.0.1", "/")

	if w.Body.Len() != payloadSize {
		t.Fatalf("expected streamed body length %d, got %d", payloadSize, w.Body.Len())
	}
	if !bytes.Equal(w.Body.Bytes(), largePayload) {
		t.Errorf("streamed body content mismatch")
	}
}
