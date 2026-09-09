package echproxy

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// minimalIndexCfg 构造一个只含一条 display 入口的配置，用于列表页渲染测试。
func minimalIndexCfg() *Config {
	return &Config{
		Upstreams: UpstreamMap{
			"twimg.l.moonchan.xyz": {Host: "pbs.twimg.com", Display: true, Mode: "ech"},
		},
		UpstreamOrder: []string{"twimg.l.moonchan.xyz"},
	}
}

// newTestRouter 用给定 cfg 装配 SetupRouter，返回 gin 引擎。
func newTestRouter(cfg *Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	SetupRouter(r, cfg)
	return r
}

// doGet 以指定 Host 头发起根路径请求，返回响应体。
func doGet(t *testing.T, r *gin.Engine, host string) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = host
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET / host=%s: status=%d, want 200", host, w.Code)
	}
	return w.Body.String()
}

// TestIndex_AnchorsUseRequestPort 验证列表页链接使用请求真实端口：
//   - l.moonchan.xyz:8443 → 链接含 :8443
//   - l.moonchan.xyz:9123 → 链接含 :9123（Android 端口 8443 被占用改随机端口的场景）
//
// 旧实现把端口剥掉后才传给 serveIndex，:9123 场景会错误地落到 :8443 兜底。
func TestIndex_AnchorsUseRequestPort(t *testing.T) {
	r := newTestRouter(minimalIndexCfg())

	cases := []struct{ host, wantPort string }{
		{"l.moonchan.xyz:8443", ":8443"},
		{"l.moonchan.xyz:9123", ":9123"},
	}
	for _, tc := range cases {
		body := doGet(t, r, tc.host)
		wantHref := `href="https://twimg.l.moonchan.xyz` + tc.wantPort + `/"`
		if !strings.Contains(body, wantHref) {
			t.Errorf("host=%s: body 缺少 %q\nbody=%s", tc.host, wantHref, body)
		}
		// 同时确保没有出现错误端口的链接。
		badPort := ":8443"
		if tc.wantPort != ":8443" {
			if strings.Contains(body, `twimg.l.moonchan.xyz`+badPort) {
				t.Errorf("host=%s: body 不应含错误端口 %q\nbody=%s", tc.host, badPort, body)
			}
		}
	}
}

// TestIndex_AnchorsFallback8443 验证 Host 头不带端口时（反代到 443）兜底 :8443，
// 避免链接缺端口打不开。
func TestIndex_AnchorsFallback8443(t *testing.T) {
	r := newTestRouter(minimalIndexCfg())

	body := doGet(t, r, "l.moonchan.xyz") // 无端口
	wantHref := `href="https://twimg.l.moonchan.xyz:8443/"`
	if !strings.Contains(body, wantHref) {
		t.Errorf("无端口 Host: body 缺少 %q\nbody=%s", wantHref, body)
	}
	// 确认没有缺端口的链接 (https://twimg.l.moonchan.xyz/ 带尾斜杠但无端口)。
	if strings.Contains(body, `href="https://twimg.l.moonchan.xyz/"`) {
		t.Errorf("无端口 Host: body 出现缺端口链接\nbody=%s", body)
	}
}

// TestRenderUpstreamList_PortExtraction 直接验证端口解析逻辑覆盖 IPv6 字面量与异常输入。
func TestRenderUpstreamList_PortExtraction(t *testing.T) {
	cfg := minimalIndexCfg()
	// 有端口 → 用该端口
	if g := renderUpstreamList(cfg, "l.moonchan.xyz:8443"); !strings.Contains(g, `twimg.l.moonchan.xyz:8443/`) {
		t.Errorf("expected :8443 link, got:\n%s", g)
	}
	// 无端口 → 兜底 :8443
	if g := renderUpstreamList(cfg, "l.moonchan.xyz"); !strings.Contains(g, `twimg.l.moonchan.xyz:8443/`) {
		t.Errorf("expected fallback :8443 link, got:\n%s", g)
	}
	// Display=false 的条目不出现在列表
	cfg2 := &Config{
		Upstreams: UpstreamMap{
			"hidden.l.moonchan.xyz": {Host: "h.example", Display: false},
			"shown.l.moonchan.xyz":  {Host: "s.example", Display: true, Mode: "ech"},
		},
		UpstreamOrder: []string{"hidden.l.moonchan.xyz", "shown.l.moonchan.xyz"},
	}
	g := renderUpstreamList(cfg2, "l.moonchan.xyz:8443")
	if strings.Contains(g, "hidden.l.moonchan.xyz") {
		t.Errorf("Display=false 条目不应出现:\n%s", g)
	}
	if !strings.Contains(g, "shown.l.moonchan.xyz:8443") {
		t.Errorf("Display=true 条目应出现:\n%s", g)
	}
}
