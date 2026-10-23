package echproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// setCookieDomainRE 从一条 Set-Cookie 中取出 Domain 属性（无该属性时返回空串）。
var setCookieDomainRE = regexp.MustCompile(`(?i);\s*domain=([^;]*)`)

// TestLiveOriginalDomainPassthroughAcceptance 是 PAC / 443 原域名模式的**手工验收测试**。
//
// 它访问真实上游（pixiv），因此默认跳过；只有显式开启时才会跑：
//
//	ECH_LIVE_ACCEPTANCE=1 go test ./echproxy/ -run TestLiveOriginalDomainPassthroughAcceptance -v
//
// 断言的是 v3.5.26 那个线上故障的回归面：上游下发的 Set-Cookie 带的是父域
// （Domain=.pixiv.net），代理必须逐字节原样透传。历史上 v3.5.26 会把它改写成当前宿主
// （Domain=accounts.pixiv.net），导致 accounts.pixiv.net 登录成功后拿到的会话在
// www.pixiv.net 上完全不可见——表现就是"登录成功又变回未登录"。
func TestLiveOriginalDomainPassthroughAcceptance(t *testing.T) {
	if os.Getenv("ECH_LIVE_ACCEPTANCE") != "1" {
		t.Skip("live acceptance test: set ECH_LIVE_ACCEPTANCE=1 to hit real pixiv upstreams")
	}

	gin.SetMode(gin.TestMode)
	engine := New443Engine(nil, nil)

	cases := []struct {
		host     string
		path     string
		wantCode int
	}{
		{"www.pixiv.net", "/", http.StatusOK},
		{"accounts.pixiv.net", "/login", http.StatusOK},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.host, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+tc.path, nil)
			req.Host = tc.host
			engine.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("%s%s: status = %d, want %d (body: %.200s)",
					tc.host, tc.path, rec.Code, tc.wantCode, rec.Body.String())
			}

			scs := rec.Header().Values("Set-Cookie")
			if len(scs) == 0 {
				t.Skipf("%s returned no Set-Cookie this time; nothing to assert", tc.host)
			}

			parentSeen := 0
			for _, sc := range scs {
				m := setCookieDomainRE.FindStringSubmatch(sc)
				if m == nil {
					continue // host-only cookie，无 Domain 属性，属于正常上游行为
				}
				domain := strings.TrimSpace(strings.TrimPrefix(m[1], "."))
				if strings.EqualFold(domain, tc.host) {
					t.Fatalf("Set-Cookie Domain was rewritten to the request host %q — 原域名模式必须原样透传父域\n%s",
						tc.host, sc)
				}
				if domain == "pixiv.net" {
					parentSeen++
				}
			}
			if parentSeen == 0 {
				t.Errorf("no .pixiv.net parent-domain Set-Cookie observed on %s; upstream shape changed, re-check the assertion", tc.host)
			}

			// v3.5.26 会把 CSP / COOP 这类安全头一并剥掉，原域名模式下必须保留。
			if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
				t.Errorf("Cross-Origin-Opener-Policy = %q, want %q", got, "same-origin")
			}
		})
	}
}
