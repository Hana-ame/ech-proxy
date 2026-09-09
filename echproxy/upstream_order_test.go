package echproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLoadConfig_UpstreamOrder 验证 LoadConfig 用 orderedmap 提取 upstreams
// 在 JSON 中的书写顺序（启动页按配置原顺序展示，不排序）。
func TestLoadConfig_UpstreamOrder(t *testing.T) {
	// upstreams 故意写成非字母序，验证顺序被保留。
	body := `{
		"upstreams": {
			"zebra": {"host": "z.example"},
			"alpha": {"host": "a.example"},
			"mango": {"host": "m.example"}
		}
	}`
	srv := httptest.NewServer(stringReaderHandler(body))
	defer srv.Close()

	cfg, err := LoadConfig(srv.URL)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	want := []string{"zebra", "alpha", "mango"}
	if len(cfg.UpstreamOrder) != len(want) {
		t.Fatalf("UpstreamOrder len = %d, want %d (%v)", len(cfg.UpstreamOrder), len(want), cfg.UpstreamOrder)
	}
	for i, k := range want {
		if cfg.UpstreamOrder[i] != k {
			t.Fatalf("UpstreamOrder[%d] = %q, want %q (full: %v)", i, cfg.UpstreamOrder[i], k, cfg.UpstreamOrder)
		}
	}
}

// stringReaderHandler 返回固定字符串的 http.Handler。
func stringReaderHandler(s string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(s))
	})
}
