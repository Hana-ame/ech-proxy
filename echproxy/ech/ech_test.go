package cloudflare_ech

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSetIPModeNormalizesAndSNIServerNameContext(t *testing.T) {
	defer SetIPMode("")

	SetIPMode("V4")
	if got := GetIPMode(); got != "v4" {
		t.Errorf("GetIPMode() after SetIPMode(V4) = %q, want v4", got)
	}
	SetIPMode("IPV6")
	if got := GetIPMode(); got != "v6" {
		t.Errorf("GetIPMode() after SetIPMode(IPV6) = %q, want v6", got)
	}
	SetIPMode("DUAL")
	if got := GetIPMode(); got != "dual" {
		t.Errorf("GetIPMode() after SetIPMode(DUAL) = %q, want dual", got)
	}

	if PrimaryDoHURL() != "https://4545810.xyz/doh" {
		t.Errorf("default PrimaryDoHURL = %q, want https://4545810.xyz/doh", PrimaryDoHURL())
	}
	if SecondaryDoHURL() != "https://1.1.1.1/dns-query" {
		t.Errorf("default SecondaryDoHURL = %q, want https://1.1.1.1/dns-query", SecondaryDoHURL())
	}

	ctx := context.Background()
	gotDefault := SNIServerNameFromContext(ctx)
	if gotDefault == "" {
		t.Errorf("default SNIServerName should not be empty, got %q", gotDefault)
	}
	gotNext := SNIServerNameFromContext(ctx)
	if gotNext == "" || gotNext == gotDefault {
		t.Errorf("next SNIServerName should rotate to different domain, got %q (prev: %q)", gotNext, gotDefault)
	}
	ctxCustom := WithSNIServerName(ctx, "custom.sni.example")
	if got := SNIServerNameFromContext(ctxCustom); got != "custom.sni.example" {
		t.Errorf("custom SNIServerName = %q, want custom.sni.example", got)
	}
	ctxNone := WithSNIServerName(ctx, "none")
	if got := SNIServerNameFromContext(ctxNone); got != "" {
		t.Errorf("none SNIServerName = %q, want empty", got)
	}
	if HasCustomSNIServerName(ctx) {
		t.Errorf("HasCustomSNIServerName(ctx) = true, want false")
	}
	if !HasCustomSNIServerName(ctxCustom) {
		t.Errorf("HasCustomSNIServerName(ctxCustom) = false, want true")
	}
	if HasCustomSNIServerName(ctxNone) {
		t.Errorf("HasCustomSNIServerName(ctxNone) = true, want false")
	}
}

func TestDefaultSNIDomainsRotation(t *testing.T) {
	seen := make(map[string]bool)
	hasWildcardResolved := false
	for i := 0; i < len(DefaultSNIDomains)*2; i++ {
		sni := NextDefaultSNIServerName()
		if sni == "" {
			t.Fatalf("NextDefaultSNIServerName() returned empty string at index %d", i)
		}
		if strings.Contains(sni, "*") {
			t.Fatalf("NextDefaultSNIServerName() returned unexpanded wildcard: %q", sni)
		}
		if strings.HasSuffix(sni, ".windowsupdate.com") {
			hasWildcardResolved = true
		}
		seen[sni] = true
	}
	if len(seen) < 5 {
		t.Errorf("expected diverse rotated domains, only got %d unique: %v", len(seen), seen)
	}
	if !hasWildcardResolved {
		t.Errorf("expected *.windowsupdate.com to be resolved into valid subdomains")
	}
}

func TestResolveHostIPsByModeViaMockDoHAndFallback(t *testing.T) {
	primaryFail := false
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if primaryFail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		qtype := r.URL.Query().Get("type")
		qname := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(qname, "noncf") {
			_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"62.112.8.152"}]}`))
			return
		}
		switch qtype {
		case "1":
			_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"104.16.10.20"}]}`))
		case "28":
			_, _ = w.Write([]byte(`{"Answer":[{"type":28,"TTL":120,"data":"2606:4700::10"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer primarySrv.Close()

	secondarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"104.16.99.88"}]}`))
	}))
	defer secondarySrv.Close()

	SetDohURL(primarySrv.URL + "/doh")
	SetFallbackDohURL(secondarySrv.URL + "/dns-query")
	defer func() {
		SetDohURL(defaultDohURL)
		SetFallbackDohURL(fallbackDohURL)
	}()

	v4IPs, err := ResolveHostIPsByMode(context.Background(), "cf-test.example.org", "v4")
	if err != nil || len(v4IPs) != 1 || v4IPs[0] != "104.16.10.20" {
		t.Fatalf("ResolveHostIPsByMode v4 = %v, %v", v4IPs, err)
	}
	v6IPs, err := ResolveHostIPsByMode(context.Background(), "cf-test.example.org", "v6")
	if err != nil || len(v6IPs) != 1 || v6IPs[0] != "2606:4700::10" {
		t.Fatalf("ResolveHostIPsByMode v6 = %v, %v", v6IPs, err)
	}

	mode, confident := DetectTransportModeWithStatus(context.Background(), "cf-test.example.org", "v4")
	if mode != "ech" || !confident {
		t.Errorf("DetectTransportModeWithStatus for CF IP = (%q, %v), want (ech, true)", mode, confident)
	}

	modeNonCF, confidentNonCF := DetectTransportModeWithStatus(context.Background(), "noncf.example.org", "v4")
	if modeNonCF != "fragment" || !confidentNonCF {
		t.Errorf("DetectTransportModeWithStatus for non-CF IP = (%q, %v), want (fragment, true)", modeNonCF, confidentNonCF)
	}

	ctxCustomSNI := WithSNIServerName(context.Background(), "custom.sni.example")
	modeCustomSNI, confidentCustomSNI := DetectTransportModeWithStatus(ctxCustomSNI, "noncf.example.org", "v4")
	if modeCustomSNI != "sni" || !confidentCustomSNI {
		t.Errorf("DetectTransportModeWithStatus with custom SNI = (%q, %v), want (sni, true)", modeCustomSNI, confidentCustomSNI)
	}

	// 验证当首选 DoH (https://4545810.xyz/doh) 故障时自动回退至次选 DoH (https://1.1.1.1/dns-query)
	primaryFail = true
	fbIPs, err := ResolveHostIPsByMode(context.Background(), "fallback-test.example.org", "v4")
	if err != nil || len(fbIPs) != 1 || fbIPs[0] != "104.16.99.88" {
		t.Fatalf("ResolveHostIPsByMode via secondary DoH fallback = %v, %v; want [104.16.99.88]", fbIPs, err)
	}
}

// TestNoDoHSelfResolutionOrMutualRecursion 验证：
// 1. 当 DoH 返回空记录（或仅返回 127.0.0.1 / 0.0.0.0 污染记录）时，ResolveHostIPsByMode 绝不会与 netdial.ResolveIPs 发生无限相互递归；
// 2. 并发请求同一域名时由 Singleflight 合并，不产生重复 DoH 请求风暴。
func TestNoDoHSelfResolutionOrMutualRecursion(t *testing.T) {
	var dohHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dohHits.Add(1)
		qname := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(qname, "dedup") {
			time.Sleep(30 * time.Millisecond)
			_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":120,"data":"104.16.88.77"}]}`))
			return
		}
		// 返回 0.0.0.0 / 127.0.0.1 污染记录或空记录，测试不会触发自我连接或无限递归
		_, _ = w.Write([]byte(`{"Answer":[{"type":1,"TTL":60,"data":"0.0.0.0"},{"type":1,"TTL":60,"data":"127.0.0.1"}]}`))
	}))
	defer srv.Close()

	SetDohURL(srv.URL + "/doh")
	SetFallbackDohURL(srv.URL + "/doh")
	defer func() {
		SetDohURL(defaultDohURL)
		SetFallbackDohURL(fallbackDohURL)
	}()

	// 1. 20 个并发协程同时解析 dedup.example.org，Singleflight 应合并为 1 次 DoH 查询
	dohHits.Store(0)
	errCh := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			ips, err := ResolveHostIPsByMode(context.Background(), "dedup.example.org", "v4")
			if err != nil || len(ips) != 1 || ips[0] != "104.16.88.77" {
				errCh <- io.ErrUnexpectedEOF
				return
			}
			errCh <- nil
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent ResolveHostIPsByMode failed: %v", err)
		}
	}
	if hits := dohHits.Load(); hits != 1 {
		t.Errorf("expected Singleflight to coalesce 20 concurrent lookups into 1 DoH request, got %d", hits)
	}

	// 2. 空/污染记录场景：不得与 netdial.ResolveIPs 发生无限相互递归（应在短超时内立即返回错误，DoH 请求次数受限于 RetryAttempts=3）
	dohHits.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _ = ResolveHostIPsByMode(ctx, "nxdomain-poisoned.invalid", "v4")
	if hits := dohHits.Load(); hits > 6 {
		t.Fatalf("detected recursive DoH storm: got %d DoH hits for a single lookup", hits)
	}
}

func TestRaceModesConcurrentWinnerSelection(t *testing.T) {
	clearCachedRoute("race.example.org")
	defer clearCachedRoute("race.example.org")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("winner"))
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Host = "race.example.org"

	resp, err := raceModes(req, []string{"direct"}, "v4", "race.example.org")
	if err != nil {
		t.Fatalf("raceModes failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("raceModes status = %d, want 200", resp.StatusCode)
	}
	if cached, ok := getCachedRoute("race.example.org"); !ok || cached != "direct" {
		t.Errorf("getCachedRoute = (%q, %v), want (direct, true)", cached, ok)
	}
}

func TestNyaaFragmentDo(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://nyaa.si/favicon.ico", nil)
	resp, err := FragmentDo(req, "v4")
	if err != nil {
		if strings.Contains(err.Error(), "ddos-guard") || strings.Contains(err.Error(), "certificate does not match") {
			t.Skipf("nyaa.si returned DDoS-Guard interstitial challenge certificate: %v", err)
			return
		}
		t.Fatalf("FragmentDo to nyaa.si failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 0 {
		t.Errorf("expected valid HTTP response, got status %d", resp.StatusCode)
	}
}

func TestRaceModesBodyStreamingNotCanceled(t *testing.T) {
	clearCachedRoute("race-stream.example.org")
	defer clearCachedRoute("race-stream.example.org")

	const payloadSize = 64 * 1024
	expectedData := make([]byte, payloadSize)
	for i := range expectedData {
		expectedData[i] = byte(i % 256)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(payloadSize))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(expectedData)
	}))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Host = "race-stream.example.org"

	// 传入多个模式触发多路并发竞速分支
	resp, err := raceModes(req, []string{"direct", "direct"}, "v4", "race-stream.example.org")
	if err != nil {
		t.Fatalf("raceModes failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body failed (premature cancel bug): %v", err)
	}
	if len(body) != payloadSize {
		t.Fatalf("read %d bytes, want %d", len(body), payloadSize)
	}
	if !bytes.Equal(body, expectedData) {
		t.Errorf("read body data mismatch")
	}
}

type testPipeConn struct {
	net.Conn
	w io.Writer
}

func (c *testPipeConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func TestTLSFragmentConnWriteFullLength(t *testing.T) {
	var buf bytes.Buffer
	fc := newTLSFragmentConn(&testPipeConn{w: &buf}, 64)

	fakeClientHello := make([]byte, 200)
	fakeClientHello[0] = 0x16
	fakeClientHello[1] = 0x03
	fakeClientHello[2] = 0x03
	fakeClientHello[3] = 0x00
	fakeClientHello[4] = 195

	n, err := fc.Write(fakeClientHello)
	if err != nil {
		t.Fatalf("fc.Write returned error: %v", err)
	}
	if n != len(fakeClientHello) {
		t.Fatalf("fc.Write returned %d bytes, want %d (short write)", n, len(fakeClientHello))
	}
	// Verify written bytes form valid TLS records delivering 195 bytes total payload
	written := buf.Bytes()
	var totalPayload int
	for len(written) >= 5 {
		if written[0] != 0x16 {
			t.Fatalf("expected TLS record 0x16, got 0x%x", written[0])
		}
		recLen := int(written[3])<<8 | int(written[4])
		written = written[5:]
		if len(written) < recLen {
			t.Fatalf("truncated TLS record in buffer")
		}
		totalPayload += recLen
		written = written[recLen:]
	}
	if totalPayload != 195 {
		t.Fatalf("total fragmented payload = %d bytes, want 195", totalPayload)
	}
}

func TestPximgLiveRoundTrip(t *testing.T) {
	clearCachedRoute("i.pximg.net")
	defer clearCachedRoute("i.pximg.net")

	req, _ := http.NewRequest(http.MethodGet, "https://i.pximg.net/c/1200x1200_80_webp/img-master/img/2026/05/05/10/51/22/144386158_p0_master1200.jpg", nil)
	req.Header.Set("Referer", "https://www.pixiv.net/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := RoundTrip(req, "auto", "v4")
	if err != nil {
		t.Fatalf("RoundTrip to i.pximg.net failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading full image body failed: %v", err)
	}
	if len(body) != 159780 {
		t.Errorf("read %d bytes, want 159780", len(body))
	}
}

func TestPixivLiveRoundTrip(t *testing.T) {
	ips, err := ResolveHostIPsByMode(context.Background(), "www.pixiv.net", "v4")
	if err != nil || len(ips) == 0 {
		t.Fatalf("ResolveHostIPsByMode for www.pixiv.net failed: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://www.pixiv.net/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := RoundTrip(req, "auto", "v4")
	if err != nil {
		t.Fatalf("RoundTrip to www.pixiv.net failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Pixiv status = %d, want 200", resp.StatusCode)
	}
}

// TestRetryExponentialSurvivesMoreThanThreeFailures 回归用例：DoH 偶发
// 「连接被远端强制关闭」（wsarecv connection reset）时，旧实现固定 3 次 ×
// 1.5s 预算（约 4.5 秒）不足以覆盖几十秒~几分钟的抖动窗口，导致 ECH 初始化
// 整体失败、代理起不来。本用例验证新实现能重试超过 3 次（5 连败后第 6 次成功）。
func TestRetryExponentialSurvivesMoreThanThreeFailures(t *testing.T) {
	failures := 0
	got, err := retryExponential(context.Background(), 10, time.Millisecond, 4*time.Millisecond, func() ([]byte, error) {
		failures++
		if failures < 6 {
			return nil, errors.New("connection reset by peer")
		}
		return []byte("ok"), nil
	})
	if err != nil {
		t.Fatalf("retryExponential = %v, want success after >3 failures", err)
	}
	if string(got) != "ok" {
		t.Fatalf("got %q, want ok", got)
	}
	if failures != 6 {
		t.Fatalf("attempts = %d, want 6 (must retry beyond the old 3)", failures)
	}
}

// TestRetryExponentialGivesUpAfterConfiguredAttempts 验证退避封顶与尝试次数上限：
// 全程失败时返回最后一次错误，且尝试次数不超过 echFetchAttempts。
func TestRetryExponentialGivesUpAfterConfiguredAttempts(t *testing.T) {
	attempts := 0
	_, err := retryExponential(context.Background(), echFetchAttempts, time.Millisecond, 2*time.Millisecond, func() ([]byte, error) {
		attempts++
		return nil, errors.New("boom")
	})
	if err == nil || err.Error() != "boom" {
		t.Fatalf("err = %v, want boom", err)
	}
	if attempts != echFetchAttempts {
		t.Fatalf("attempts = %d, want echFetchAttempts=%d", attempts, echFetchAttempts)
	}
}

// TestRetryExponentialRespectsContextCancel 验证退避等待期间 ctx 取消会立即返回。
// 用 firstCall 通道 + 超长退避保证 cancel 必然落在第一次退避等待中（确定性，
// 不依赖墙钟竞速）。
func TestRetryExponentialRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	firstCall := make(chan struct{})
	calls := 0
	done := make(chan struct{})
	var err error
	go func() {
		_, err = retryExponential(ctx, 10, time.Hour, time.Hour, func() ([]byte, error) {
			calls++
			close(firstCall)
			return nil, errors.New("reset")
		})
		close(done)
	}()
	<-firstCall // 第一次失败已发生，函数正处于 1 小时的退避等待中
	cancel()
	select {
	case <-done:
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retryExponential did not return after ctx cancel")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (cancelled during backoff, no second attempt)", calls)
	}
}
