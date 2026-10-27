package cloudflare_ech

import (
	"net/http"
	"testing"
)

func respWith(status int, header map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// Cloudflare 的托管质询（cf-mitigated: challenge）是正常业务响应，必须原样交给
// 浏览器执行 JS 去解；把它当路由拒绝会导致质询页被吞掉、浏览器侧只剩 502/永久 403。
func TestChallengeIsNotRouteRejection(t *testing.T) {
	resp := respWith(http.StatusForbidden, map[string]string{"Cf-Mitigated": "challenge"})
	if isCloudflareRouteRejection(resp, "ech") {
		t.Fatal("cf-mitigated: challenge must be relayed to the browser, not treated as route rejection")
	}
}

// 不带质询标记的 403（典型是 CF 边缘不认识该 Host 的域前置拒绝）仍然触发通道兜底。
func TestPlain403IsRouteRejection(t *testing.T) {
	if !isCloudflareRouteRejection(respWith(http.StatusForbidden, nil), "ech") {
		t.Fatal("plain 403 without cf-mitigated should still trigger transport fallback")
	}
}

func TestOtherRouteRejections(t *testing.T) {
	for _, code := range []int{521, 522, 523, 525, 530, 421} {
		if !isCloudflareRouteRejection(respWith(code, nil), "ech") {
			t.Fatalf("status %d should be a route rejection", code)
		}
	}
	if isCloudflareRouteRejection(respWith(http.StatusOK, nil), "ech") {
		t.Fatal("200 must never be a route rejection")
	}
	if isCloudflareRouteRejection(respWith(http.StatusForbidden, map[string]string{"Cf-Mitigated": "challenge"}), "sni") {
		t.Fatal("sni mode must not classify responses as route rejection")
	}
}
