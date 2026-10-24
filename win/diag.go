package main

// 单项功能诊断：ech-proxy diag -test <name> -host <域名>
//
// 设计目的：把「all transport modes failed」这种把 DNS / TCP / TLS / HTTP / 兜底
// 全部混在一起的结论拆开。每一层单独可测，才能定位到底是解析不到、建连黑洞、
// TLS 被 RST、还是只是这一层通了但下一层挂了。

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
	echconfig "github.com/Hana-ame/ech-proxy/echproxy/config"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

// diagTests 是 -test 接受的取值，顺序即 `diag -test all` 的执行顺序。
var diagTests = []struct {
	name string
	desc string
}{
	{"dns", "DoH 解析：列出解析到的 IP 与所用 DoH 端点"},
	{"tcp", "逐 IP 的 TCP 443 建连计时：区分黑洞(timeout) / RST / refused"},
	{"tls", "TLS 握手：版本、套件、ALPN、证书签发者与 hostname 校验（-sni 可切伪装 SNI）"},
	{"http", "单通道完整 HTTP GET 并打印响应头与字节数（-transport 选通道）"},
	{"transport", "逐通道 HTTP：direct/fragment/sni/ech/auto 各打一次（等价于 probe）"},
	{"cookie", "原域名模式 Set-Cookie 透传：检查 Domain 是否被改写成请求 host"},
	{"fallback", "只测上游兜底代理（-fallback）能否打通"},
	{"config", "拉取/校验上游配置，并打印目标域名命中的 upstream 条目"},
	{"pac", "目标域名在 PAC 白名单里是否命中"},
}

func diagUsageText() string {
	var b strings.Builder
	b.WriteString("=== ech-proxy diag：单项功能诊断 ===\n")
	b.WriteString("用法：ech-proxy diag -test <功能> -host <域名> [其他 flag]\n\n")
	b.WriteString("可选 -test：\n")
	for _, t := range diagTests {
		b.WriteString(fmt.Sprintf("  %-10s %s\n", t.name, t.desc))
	}
	b.WriteString("  all        依次跑 dns → tcp → tls → http → fallback\n")
	b.WriteString("\n常用组合：\n")
	b.WriteString("  diag -test dns -host manhuagui.com -ip 4\n")
	b.WriteString("  diag -test tcp -host manhuagui.com -ip 4\n")
	b.WriteString("  diag -test tls -host manhuagui.com -sni fake\n")
	b.WriteString("  diag -test http -host manhuagui.com -transport sni\n")
	b.WriteString("  diag -test cookie -host www.pixiv.net\n")
	b.WriteString("  diag -test fallback -host manhuagui.com -fallback 127.0.0.1:10809\n")
	b.WriteString("\n其他 flag：-ip 4|6|dual  -timeout <时长>  -path <路径>  -port <端口>  -sni real|fake  -fallback <代理>\n")
	return b.String()
}

func diagNormalizeHost(raw string) string {
	h := strings.TrimSpace(strings.ToLower(raw))
	h = strings.TrimPrefix(h, "http://")
	h = strings.TrimPrefix(h, "https://")
	if idx := strings.Index(h, "/"); idx >= 0 {
		h = h[:idx]
	}
	return strings.TrimSpace(h)
}

func diagTimeout(cmd CLICommand) time.Duration {
	if cmd.ProbeTimeout > 0 {
		return cmd.ProbeTimeout
	}
	return 20 * time.Second
}

func runDiag(cmd CLICommand, out io.Writer) int {
	test := strings.ToLower(strings.TrimSpace(cmd.DiagTest))
	if test == "" || test == "list" || test == "help" {
		fmt.Fprint(out, diagUsageText())
		return 2
	}
	host := diagNormalizeHost(cmd.ProbeHost)
	ipMode := strings.TrimSpace(cmd.IPMode)
	if ipMode == "" {
		ipMode = "v4"
	}
	timeout := diagTimeout(cmd)

	if test != "config" && host == "" {
		fmt.Fprintln(out, "ERROR: 该测试需要 -host <域名>（-config 除外）")
		fmt.Fprint(out, diagUsageText())
		return 2
	}

	// config / pac 只依赖本地配置，不需要 DoH 初始化
	if test != "config" && test != "pac" {
		if err := echproxy.InitECH(cmd.BootstrapIP, ipMode); err != nil {
			fmt.Fprintf(out, "WARNING: InitECH failed (%v) — 继续，但 DoH 解析可能退化\n", err)
		}
	}

	switch test {
	case "dns":
		return diagDNS(out, host, ipMode, timeout)
	case "tcp":
		return diagTCP(out, host, ipMode, cmd.DiagPort, timeout)
	case "tls":
		return diagTLS(out, host, ipMode, cmd.DiagPort, cmd.DiagSNI, timeout)
	case "http":
		return diagHTTP(out, cmd, host, ipMode, timeout)
	case "transport":
		return runTransportProbe(cmd, out)
	case "cookie":
		return diagCookie(out, cmd, host, ipMode, timeout)
	case "fallback":
		return diagFallback(out, cmd, host, timeout)
	case "config":
		return diagConfig(out, cmd, host)
	case "pac":
		return diagPAC(out, cmd, host)
	case "all":
		code := 0
		for _, t := range []string{"dns", "tcp", "tls", "http", "fallback"} {
			if r := runDiagWith(cmd, out, t, host, ipMode, timeout); r != 0 {
				code = r
			}
			fmt.Fprintln(out)
		}
		return code
	default:
		fmt.Fprintf(out, "ERROR: 未知 -test %q\n\n", cmd.DiagTest)
		fmt.Fprint(out, diagUsageText())
		return 2
	}
}

// runDiagWith 供 -test all 复用：跳过用法校验与 DoH 初始化（已在 runDiag 做过）。
func runDiagWith(cmd CLICommand, out io.Writer, test, host, ipMode string, timeout time.Duration) int {
	switch test {
	case "dns":
		return diagDNS(out, host, ipMode, timeout)
	case "tcp":
		return diagTCP(out, host, ipMode, cmd.DiagPort, timeout)
	case "tls":
		return diagTLS(out, host, ipMode, cmd.DiagPort, cmd.DiagSNI, timeout)
	case "http":
		return diagHTTP(out, cmd, host, ipMode, timeout)
	case "fallback":
		return diagFallback(out, cmd, host, timeout)
	}
	return 0
}

func diagPort(cmd CLICommand) string {
	if cmd.DiagPort > 0 {
		return fmt.Sprintf("%d", cmd.DiagPort)
	}
	return "443"
}

func diagResolve(out io.Writer, host, ipMode string, timeout time.Duration) ([]string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ips, err := cloudflare_ech.ResolveHostIPsByMode(ctx, host, ipMode)
	if err != nil {
		fmt.Fprintf(out, "   FAIL resolve: %v\n", err)
		return nil, false
	}
	if len(ips) == 0 {
		fmt.Fprintln(out, "   FAIL resolve: 解析结果为空")
		return nil, false
	}
	return ips, true
}

func diagDNS(out io.Writer, host, ipMode string, timeout time.Duration) int {
	fmt.Fprintf(out, "== dns: DoH 解析 %s (ipmode=%s) ==\n", host, ipMode)
	fmt.Fprintf(out, "   primary DoH   : %s\n", cloudflare_ech.PrimaryDoHURL())
	fmt.Fprintf(out, "   secondary DoH : %s\n", cloudflare_ech.SecondaryDoHURL())
	start := time.Now()
	ips, ok := diagResolve(out, host, ipMode, timeout)
	if !ok {
		return 1
	}
	d := time.Since(start)
	for i, ip := range ips {
		fmt.Fprintf(out, "   [%d] %s\n", i, ip)
	}
	fmt.Fprintf(out, "   OK %d 个 IP (%v)\n", len(ips), d.Truncate(time.Millisecond))
	return 0
}

func diagTCP(out io.Writer, host, ipMode string, port int, timeout time.Duration) int {
	p := diagPortFromInt(port)
	fmt.Fprintf(out, "== tcp: 逐 IP 建连 %s:%s (ipmode=%s) ==\n", host, p, ipMode)
	ips, ok := diagResolve(out, host, ipMode, timeout)
	if !ok {
		return 1
	}
	anyOK := false
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, p)
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: timeout}).DialContext(context.Background(), "tcp", addr)
		d := time.Since(start)
		if err != nil {
			fmt.Fprintf(out, "   %-22s FAIL %-10v %s\n", addr, d.Truncate(time.Millisecond), classifyDialErr(err))
			continue
		}
		_ = conn.Close()
		anyOK = true
		fmt.Fprintf(out, "   %-22s OK   %-10v connected\n", addr, d.Truncate(time.Millisecond))
	}
	if !anyOK {
		return 1
	}
	return 0
}

// classifyDialErr 把建连失败分成三类，这三类对应的对策完全不同：
//   - timeout    → 目的 IP 被黑洞（丢包），换端口/通道都没用，只能换 IP 或走上游代理
//   - reset      → 对端/中间设备主动 RST，通常是握手内容触发了审查，换 SNI/分片可能有效
//   - refused    → 端口没开，是站点自身问题
func classifyDialErr(err error) string {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout（黑洞/丢包，换通道无效，只能换 IP 或走兜底代理）"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "forcibly closed"), strings.Contains(msg, "reset"), strings.Contains(msg, "connection reset"):
		return "RST（被主动重置，换 SNI/分片可能有效）"
	case strings.Contains(msg, "refused"):
		return "refused（端口未开放，站点自身问题）"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "unreachable"):
		return "unreachable（本机网络/路由不通）"
	default:
		return msg
	}
}

func diagTLS(out io.Writer, host, ipMode string, port int, sniMode string, timeout time.Duration) int {
	p := diagPortFromInt(port)
	serverName := host
	if strings.EqualFold(strings.TrimSpace(sniMode), "fake") || strings.EqualFold(strings.TrimSpace(sniMode), "mask") {
		serverName = cloudflare_ech.ConsistentDefaultSNIForHost(host)
	}
	fmt.Fprintf(out, "== tls: 握手 %s:%s (SNI=%s, ipmode=%s) ==\n", host, p, serverName, ipMode)
	fmt.Fprintln(out, "   注：这里是标准库 TLS 直连握手，不含 uTLS 指纹伪装与 ClientHello 分片。")
	fmt.Fprintln(out, "       若本项 RST 而 `diag -test http` 成功，说明是分片/指纹伪装起了作用。")
	ips, ok := diagResolve(out, host, ipMode, timeout)
	if !ok {
		return 1
	}
	anyOK := false
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, p)
		start := time.Now()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // 诊断需要看到证书本身，校验结果单独打印
			NextProtos:         []string{"h2", "http/1.1"},
		})
		d := time.Since(start)
		if err != nil {
			fmt.Fprintf(out, "   %-22s FAIL %-10v %s\n", addr, d.Truncate(time.Millisecond), classifyDialErr(err))
			continue
		}
		anyOK = true
		st := conn.ConnectionState()
		fmt.Fprintf(out, "   %-22s OK   %-10v %s | %s | ALPN=%s\n",
			addr, d.Truncate(time.Millisecond), tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol)
		if len(st.PeerCertificates) > 0 {
			c := st.PeerCertificates[0]
			verifyErr := ""
			if err := c.VerifyHostname(host); err != nil {
				verifyErr = fmt.Sprintf("  [证书对不上 %s：%v]", host, err)
			}
			fmt.Fprintf(out, "        subject=%s issuer=%s expires=%s%s\n",
				c.Subject.CommonName, c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"), verifyErr)
		}
		_ = conn.Close()
	}
	if !anyOK {
		return 1
	}
	return 0
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// normalizeTransportMode 把 -transport 归一到真实通道名。
// "smart" 是运行方案名而不是通道名，落到单通道测试时按 auto 处理。
func normalizeTransportMode(raw string) string {
	switch m := strings.ToLower(strings.TrimSpace(raw)); m {
	case "", "smart", "all":
		return "auto"
	default:
		return m
	}
}

func diagPortFromInt(port int) string {
	if port > 0 {
		return fmt.Sprintf("%d", port)
	}
	return "443"
}

// diagHTTP 打一次完整 GET 并打印响应头；失败时经兜底代理重试一次并标注来源。
func diagHTTP(out io.Writer, cmd CLICommand, host, ipMode string, timeout time.Duration) int {
	path := strings.TrimSpace(cmd.ProbePath)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	mode := normalizeTransportMode(cmd.ProbeMode)
	fmt.Fprintf(out, "== http: GET https://%s%s (transport=%s, ipmode=%s) ==\n", host, path, mode, ipMode)
	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		fmt.Fprintf(out, "   FAIL 构造请求: %v\n", err)
		return 1
	}
	req.Host = host
	req.Header.Set("User-Agent", probeUserAgent)
	req.Header.Set("Accept", "*/*")
	start := time.Now()
	resp, err := cloudflare_ech.RoundTrip(req, mode, ipMode)
	d := time.Since(start)
	if err != nil {
		fbResp, fbErr, fbD := probeViaFallback(host, path, timeout)
		if fbErr == nil && fbResp != nil {
			defer fbResp.Body.Close()
			n, _ := io.Copy(io.Discard, io.LimitReader(fbResp.Body, 64*1024))
			fmt.Fprintf(out, "   直连失败: %v\n", err)
			fmt.Fprintf(out, "   OK   %d  %v  %d bytes  [via fallback %s]\n", fbResp.StatusCode, fbD.Truncate(time.Millisecond), n, echproxy.GetFallbackProxy())
			printRespHeaders(out, fbResp)
			return 0
		}
		if fbErr != nil {
			fmt.Fprintf(out, "   FAIL %-10v %v; fallback(%s) 也失败: %v\n", d.Truncate(time.Millisecond), err, echproxy.GetFallbackProxy(), fbErr)
		} else {
			fmt.Fprintf(out, "   FAIL %-10v %v\n", d.Truncate(time.Millisecond), err)
		}
		return 1
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	fmt.Fprintf(out, "   OK   %d  %v  %d bytes\n", resp.StatusCode, d.Truncate(time.Millisecond), n)
	printRespHeaders(out, resp)
	return 0
}

func printRespHeaders(out io.Writer, resp *http.Response) {
	for _, k := range []string{"Server", "Location", "Content-Type", "Cross-Origin-Opener-Policy", "Strict-Transport-Security", "Vary"} {
		if v := resp.Header.Get(k); v != "" {
			fmt.Fprintf(out, "        %s: %s\n", k, truncate(v, 100))
		}
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) > 0 {
		fmt.Fprintf(out, "        Set-Cookie: %d 条（用 diag -test cookie 看详情）\n", len(sc))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// diagCookie 验证原域名模式的核心承诺：Set-Cookie 必须原样透传，
// 不能把 Domain=.pixiv.net 改写成 Domain=www.pixiv.net（后者会导致跨子域登录态断裂）。
func diagCookie(out io.Writer, cmd CLICommand, host, ipMode string, timeout time.Duration) int {
	path := strings.TrimSpace(cmd.ProbePath)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	mode := normalizeTransportMode(cmd.ProbeMode)
	fmt.Fprintf(out, "== cookie: 原域名模式 Set-Cookie 透传 %s%s (transport=%s) ==\n", host, path, mode)
	req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		fmt.Fprintf(out, "   FAIL 构造请求: %v\n", err)
		return 1
	}
	req.Host = host
	req.Header.Set("User-Agent", probeUserAgent)
	if ck := strings.TrimSpace(cmd.DiagCookie); ck != "" {
		req.Header.Set("Cookie", ck)
		fmt.Fprintf(out, "   带请求 Cookie: %s\n", truncate(ck, 80))
	}
	resp, err := cloudflare_ech.RoundTrip(req, mode, ipMode)
	if err != nil {
		fbResp, fbErr, _ := probeViaFallback(host, path, timeout)
		if fbErr == nil && fbResp != nil {
			defer fbResp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(fbResp.Body, 64*1024))
			resp = fbResp
			fmt.Fprintf(out, "   [via fallback %s] HTTP %d\n", echproxy.GetFallbackProxy(), resp.StatusCode)
		} else {
			fmt.Fprintf(out, "   FAIL %v\n", err)
			return 1
		}
	} else {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	}
	raw := resp.Header.Values("Set-Cookie")
	if len(raw) == 0 {
		fmt.Fprintf(out, "   响应无 Set-Cookie（HTTP %d）\n", resp.StatusCode)
		return 0
	}
	fmt.Fprintf(out, "   HTTP %d，共 %d 条 Set-Cookie：\n", resp.StatusCode, len(raw))
	bad := 0
	for i, line := range raw {
		c, perr := http.ParseSetCookie(line)
		fmt.Fprintf(out, "   [%d] %s\n", i, truncate(line, 140))
		if perr != nil {
			fmt.Fprintf(out, "        (解析失败: %v)\n", perr)
			continue
		}
		attrs := []string{}
		if c.Secure {
			attrs = append(attrs, "Secure")
		}
		if c.HttpOnly {
			attrs = append(attrs, "HttpOnly")
		}
		if c.SameSite != 0 {
			attrs = append(attrs, fmt.Sprintf("SameSite=%d", c.SameSite))
		}
		switch {
		case c.Domain == "":
			fmt.Fprintf(out, "        name=%s domain=<host-only> %v\n", c.Name, attrs)
		case strings.EqualFold(strings.TrimPrefix(c.Domain, "."), host):
			bad++
			fmt.Fprintf(out, "        name=%s domain=%s %v  <== 与请求 host 完全一致：跨子域无法携带（若上游原文就是如此则属正常）\n", c.Name, c.Domain, attrs)
		case strings.HasSuffix(host, strings.TrimPrefix(c.Domain, ".")):
			fmt.Fprintf(out, "        name=%s domain=%s %v  父域，可跨子域共享 ✓\n", c.Name, c.Domain, attrs)
		default:
			fmt.Fprintf(out, "        name=%s domain=%s %v  （与 %s 无后缀关系，原样透传）\n", c.Name, c.Domain, attrs, host)
		}
	}
	if bad > 0 {
		fmt.Fprintf(out, "   结论：%d 条 cookie 的 Domain 与请求 host 一致——请与上游原文比对；\n", bad)
		fmt.Fprintf(out, "         若上游返回的是父域而这里被改写成 host，说明透传被破坏。\n")
		return 1
	}
	fmt.Fprintln(out, "   结论：无 Domain 被改写成请求 host 的情况 ✓")
	return 0
}

func diagFallback(out io.Writer, cmd CLICommand, host string, timeout time.Duration) int {
	path := strings.TrimSpace(cmd.ProbePath)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	fb := echproxy.GetFallbackProxy()
	fmt.Fprintf(out, "== fallback: 仅经上游兜底代理访问 %s%s ==\n", host, path)
	if fb == "" {
		fmt.Fprintln(out, "   SKIP 未配置兜底代理（用 -fallback 127.0.0.1:10809 指定）")
		return 2
	}
	resp, err, d := probeViaFallback(host, path, timeout)
	if err != nil {
		fmt.Fprintf(out, "   FAIL %-10v %v  (fallback=%s)\n", d.Truncate(time.Millisecond), err, fb)
		return 1
	}
	if resp == nil {
		fmt.Fprintln(out, "   SKIP 兜底 transport 未就绪")
		return 2
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	fmt.Fprintf(out, "   OK   %d  %v  %d bytes  (fallback=%s)\n", resp.StatusCode, d.Truncate(time.Millisecond), n, fb)
	printRespHeaders(out, resp)
	return 0
}

func diagConfig(out io.Writer, cmd CLICommand, host string) int {
	src := cmd.ConfigURL
	if src == "" {
		src = echproxy.DefaultUpstreamConfigURL
	}
	fmt.Fprintf(out, "== config: 上游配置 %s ==\n", src)
	buf, err := echproxy.FetchBytes(src)
	if err != nil {
		fmt.Fprintf(out, "   FAIL 拉取失败: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "   OK %d 字节\n", len(buf))
	issues, err := echproxy.ValidateConfig(buf)
	if err != nil {
		fmt.Fprintf(out, "   FAIL JSON 非法: %v\n", err)
		return 1
	}
	cfg, _ := echproxy.ParseConfig(buf)
	if cfg == nil {
		fmt.Fprintln(out, "   FAIL 配置解析为空")
		return 1
	}
	upstreams, blocked := cfg.Snapshot()
	fmt.Fprintf(out, "   upstream 条目: %d，blocked: %d\n", len(upstreams), len(blocked))
	fmt.Fprintf(out, "   校验: %s\n", strings.TrimSpace(echproxy.FormatConfigIssues(issues)))
	if host == "" {
		return 0
	}
	uc, ok := echconfig.Resolve(upstreams, host)
	if !ok {
		fmt.Fprintf(out, "   %s 未命中任何 upstream（会被 502 no upstream）\n", host)
		return 1
	}
	fmt.Fprintf(out, "   %s 命中: entry=%s mode=%s ipmode=%s sni=%s wildcard=%v\n",
		host, uc.Host, uc.Mode, uc.IPMode, uc.SNIServerName, uc.Wildcard != nil)
	fmt.Fprintf(out, "   原域名模式=%v\n", echconfig.IsOriginalDomainMode(host))
	return 0
}

// diagPAC 判断目标域名会不会被 PAC 送进代理。
//
// 注意 GeneratePACWithFallback 的第一个参数是 `_`（cfg 被丢弃），白名单只来自 extraWhitelist，
// 所以这里必须先拉 pac.txt 再喂进去——直接 GeneratePAC(cfg) 得到的是空名单，恒不命中，等于没测。
func diagPAC(out io.Writer, cmd CLICommand, host string) int {
	src := strings.TrimSpace(cmd.WhitelistURL)
	if src == "" {
		src = echproxy.DefaultWhitelistURL
	}
	fmt.Fprintf(out, "== pac: %s 是否会被 PAC 送进代理 ==\n", host)
	fmt.Fprintf(out, "   白名单源: %s\n", src)
	buf, err := echproxy.FetchBytes(src)
	if err != nil {
		fmt.Fprintf(out, "   FAIL 拉取白名单失败: %v\n", err)
		return 1
	}
	var whitelist []string
	for _, line := range strings.Split(string(buf), "\n") {
		if d := netdial.NormalizeDomainEntry(line); d != "" {
			whitelist = append(whitelist, d)
		}
	}
	fmt.Fprintf(out, "   白名单条目: %d\n", len(whitelist))

	hit, matched := false, ""
	for _, d := range whitelist {
		if d == host || strings.HasSuffix(host, "."+d) {
			hit, matched = true, d
			break
		}
	}
	if hit {
		fmt.Fprintf(out, "   命中白名单条目: %s ✓（浏览器会把 %s 送进 ech-proxy）\n", matched, host)
	} else {
		fmt.Fprintf(out, "   %s 不在白名单中（默认直连；只有 -all 全局模式或 443/hosts 方案才会走代理）\n", host)
	}

	// 再用真实生成的 PAC 复核一次，确认域名确实出现在脚本里
	pac := echconfig.GeneratePACWithFallback(nil, "127.0.0.1:8443", false, "", whitelist)
	inPAC := strings.Contains(pac, "\""+host+"\"") || strings.Contains(pac, "\""+matched+"\"")
	fmt.Fprintf(out, "   生成的 PAC 脚本中出现该域名: %v (%d 字节)\n", inPAC, len(pac))
	if hit && !inPAC {
		fmt.Fprintf(out, "   WARN 白名单命中但 PAC 脚本里没找到——生成逻辑可能漏了该项\n")
		return 1
	}
	return 0
}
