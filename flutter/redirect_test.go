package main

// apiProxyHandler 的控制面重定向跟随单元测试。
//
// 背景：ECH client 不自动跟随 3xx（CheckRedirect: ErrUseLastResponse），
// 而后端 `/api/twitter/<username>` 有 302 → `.json.gz?t=`（go 仓库
// api/handlers_v1.go:198）。apiProxyHandler 手动跟随**同主机**重定向，
// Location 仍走 ECH；跳到别处（跨主机/非 http(s)）原样回传客户端。
// 本测试钉住 resolveSameHost 的跟随边界，防止将来把客户端引去直连被墙域名。

import "testing"

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
