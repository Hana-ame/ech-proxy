package echproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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

	// 验证从独立 wildcards 列表中合入并生效的通配子域名匹配:
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

	// 1. Iwara: 确保旧二进制解析出完整的 host, referer 及原有未修改的 wildcard
	iwara, ok := oldCfg.Upstreams["iwara.l.moonchan.xyz"]
	if !ok {
		t.Fatalf("old binary missing iwara entry")
	}
	if iwara.Host != "iwara.tv" {
		t.Errorf("expected iwara.tv, got %s", iwara.Host)
	}
	if iwara.Referer != "https://www.iwara.tv/" {
		t.Errorf("expected referer https://www.iwara.tv/, got %s", iwara.Referer)
	}
	if iwara.Wildcard == nil || iwara.Wildcard.Prefix != "iwara-" || iwara.Wildcard.Referer != "https://www.iwara.tv/" {
		t.Errorf("expected intact wildcard for old binary, got %+v", iwara.Wildcard)
	}

	// 2. DLsite: 确保原有 wildcard 未修改，防盗链 referer 完好
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


