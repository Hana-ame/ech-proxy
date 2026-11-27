package main

// apiProxyHandler 的控制面重定向跟随单元测试。
//
// 背景：ECH client 不自动跟随 3xx（CheckRedirect: ErrUseLastResponse），
// 而后端 `/api/twitter/<username>` 有 302 → `.json.gz?t=`（go 仓库
// api/handlers_v1.go:198）。apiProxyHandler 手动跟随**同主机**重定向，
// Location 仍走 ECH；跳到别处（跨主机/非 http(s)）原样回传客户端。
// 本测试钉住 resolveSameHost 的跟随边界，防止将来把客户端引去直连被墙域名。

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestIsRedirect(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{301, true},
		{302, true},
		{303, true},
		{307, true},
		{308, true},
		{200, false},
		{404, false},
		{500, false},
	}
	for _, c := range cases {
		if got := isRedirect(c.code); got != c.want {
			t.Errorf("isRedirect(%d) = %v, want %v", c.code, got, c.want)
		}
	}
}

func TestResolveSameHost(t *testing.T) {
	const host = "x.moonchan.xyz"
	cases := []struct {
		name string
		loc  string
		want string
	}{
		{
			name: "相对路径（后端 302 实际形态）",
			loc:  "/api/twitter/alice.json.gz?t=2026-11-08",
			want: "https://x.moonchan.xyz/api/twitter/alice.json.gz?t=2026-11-08",
		},
		{
			name: "同主机绝对 URL",
			loc:  "https://x.moonchan.xyz/api/twitter/bob.json.gz",
			want: "https://x.moonchan.xyz/api/twitter/bob.json.gz",
		},
		{
			name: "同主机带端口",
			loc:  "https://x.moonchan.xyz:8443/api/x",
			want: "https://x.moonchan.xyz:8443/api/x",
		},
		{
			name: "跨主机不跟随",
			loc:  "https://video-cf.twimg.com/media/x.mp4",
			want: "",
		},
		{
			name: "跨主机 http 不跟随",
			loc:  "http://other.example.com/path",
			want: "",
		},
		{
			// 同主机但降级到明文 http：ECH 通道的价值全在 TLS，跟随等于自拆保护。
			name: "同主机 http 降级不跟随",
			loc:  "http://x.moonchan.xyz/api/x",
			want: "",
		},
		{
			// 协议相对 URL 也以 "/" 开头，曾被当成站内路径拼成
			// https://x.moonchan.xyz//cdn.other.com/a（必然 404）。
			name: "协议相对 URL 不跟随",
			loc:  "//cdn.other.com/a",
			want: "",
		},
		{
			name: "协议相对且同主机也不跟随",
			loc:  "//x.moonchan.xyz/api/x",
			want: "",
		},
		{
			// "///x" 不是协议相对引用，是站内路径（RFC 3986 §4.2 只认两个斜杠）。
			name: "三斜杠仍是站内路径",
			loc:  "///a/b",
			want: "https://x.moonchan.xyz///a/b",
		},
		{
			name: "主机名大小写不敏感",
			loc:  "https://X.MoonChan.XYZ/api/x",
			want: "https://X.MoonChan.XYZ/api/x",
		},
		{
			// 尾点在 DNS 上等价，但原样进 SNI 会握手失败，必须归一化。
			name: "主机名尾点归一化",
			loc:  "https://x.moonchan.xyz.:8443/api/x",
			want: "https://x.moonchan.xyz:8443/api/x",
		},
		{
			name: "带 userinfo 不跟随",
			loc:  "https://u:p@x.moonchan.xyz/api/x",
			want: "",
		},
		{
			name: "非 http(s) 协议不跟随",
			loc:  "ftp://x.moonchan.xyz/api/x",
			want: "",
		},
		{
			name: "空 Location",
			loc:  "",
			want: "",
		},
		{
			name: "非法 URL",
			loc:  "://bad",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveSameHost(c.loc, host); got != c.want {
				t.Errorf("resolveSameHost(%q) = %q, want %q", c.loc, got, c.want)
			}
		})
	}
}

// TestIsMethodPreservingRedirect 钉住「哪些 3xx 不许改写成 GET」。
// 混淆这两类会让 POST /api/twitter/<username>（保存标签）在重定向后
// 变成一次 GET —— 上游要么 405，要么按查询语义误处理。
func TestIsMethodPreservingRedirect(t *testing.T) {
	cases := []struct {
		code int
		want bool
	}{
		{301, false},
		{302, false},
		{303, false},
		{307, true},
		{308, true},
		{200, false},
	}
	for _, c := range cases {
		if got := isMethodPreservingRedirect(c.code); got != c.want {
			t.Errorf("isMethodPreservingRedirect(%d) = %v, want %v", c.code, got, c.want)
		}
	}
}

// TestHasRequestBody 钉住「有 body」的判定：长度未知（-1，chunked）必须
// 按有 body 处理，否则带 chunked body 的 307 会被当成可安全重放。
func TestHasRequestBody(t *testing.T) {
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"nil request", nil, false},
		{"无 body（NoBody/0）", &http.Request{Body: http.NoBody, ContentLength: 0}, false},
		{"Body 为 nil", &http.Request{ContentLength: 0}, false},
		{"已知长度 body", &http.Request{Body: io.NopCloser(strings.NewReader("x")), ContentLength: 1}, true},
		{"长度未知 chunked", &http.Request{Body: io.NopCloser(strings.NewReader("x")), ContentLength: -1}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasRequestBody(c.req); got != c.want {
				t.Errorf("hasRequestBody(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}
