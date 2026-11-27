package main

// 控制面 API 重定向跟随的纯 Go 辅助函数。
//
// 为什么单独一个文件：flutter/main.go 是 cgo 文件（import "C"），在
// CI 的 GOOS=windows CGO_ENABLED=0 go vet 目标下会被整体排除；若这两个
// 函数留在 main.go，redirect_test.go（纯 Go）单独编译时会 undefined。
// 放这里后，CGO_ENABLED=0/1 两种目标下测试都能编译。

import (
	"net/http"
	"net/url"
	"strings"
)

// isRedirect 判断状态码是否属于需要跟随的重定向。
func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

// isMethodPreservingRedirect 判断 3xx 是否要求原样保留请求方法。
//
// 307/308 的语义就是「方法和请求体都不变」（RFC 9110 §15.4.8 / §15.4.9）；
// 301/302/303 则按浏览器惯例降级成 GET（303 规范本身就直接要求 GET）。
// 跟随逻辑必须区分这两类，否则把 POST 静默改成 GET 会让上游把「写」当「读」。
func isMethodPreservingRedirect(code int) bool {
	return code == http.StatusTemporaryRedirect || code == http.StatusPermanentRedirect
}

// hasRequestBody 判断入站请求是否携带请求体。
//
// ContentLength == -1 表示长度未知（chunked），按「有 body」保守处理：宁可
// 放弃跟随 307/308 把 3xx 交回客户端，也不要发出一个语义被篡改的请求。
func hasRequestBody(r *http.Request) bool {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return false
	}
	return r.ContentLength != 0
}

// sameHostname 比较两个主机名是否指向同一站点。
//
// DNS 不区分大小写（`X.MoonChan.XYZ` 与 `x.moonchan.xyz` 是同一台），
// 末尾的根点（`x.example.com.`）在解析上也与无点形式等价；两个方向都要
// 归一化，否则合法同站重定向会被误判成跨站而放弃跟随。
func sameHostname(a, b string) bool {
	a = strings.TrimSuffix(a, ".")
	b = strings.TrimSuffix(b, ".")
	if a == "" || b == "" {
		return false
	}
	return strings.EqualFold(a, b)
}

// resolveSameHost 解析重定向 Location：仅当目标是 [targetHost] 的 https URL
// （或同站相对路径）时返回可跟随的完整 URL，否则返回空串（表示不跟随）。
//
// 四个边界，都是历史缺陷：
//   - 协议相对 URL（`//other.com/x`）同样以 "/" 开头，会被当成站内路径拼成
//     `https://targetHost//other.com/x` —— 一个必然 404 的错误地址，把
//     「不跟随」悄悄变成「跟随到错误路径」。必须先排除 "//" 前缀。
//   - 主机名比对用过 `==`，大小写不同就漏判（见 sameHostname）。
//   - 原实现允许 `http://`：语义上仍是同主机，但 ECH 通道本就是靠 TLS 拿
//     加密与抗封锁的，降级到明文 http 等于自己把保护拆掉，只跟随 https。
//   - 带 userinfo 的 URL（`https://user:pw@target/`）会让日志与鉴权语义都
//     变得可疑，一律不跟随。
func resolveSameHost(loc, targetHost string) string {
	if loc == "" {
		return ""
	}
	// 协议相对 URL 必须以 "//" 开头且第三个字符不是 "/"（"///x" 是站内路径）。
	if strings.HasPrefix(loc, "//") && !strings.HasPrefix(loc, "///") {
		return ""
	}
	if strings.HasPrefix(loc, "/") {
		return "https://" + targetHost + loc
	}
	u, err := url.Parse(loc)
	if err != nil {
		// url.Parse 会拒绝含控制字符的 Location，天然挡掉 CR/LF 注入。
		return ""
	}
	if u.Scheme != "https" || u.User != nil {
		return ""
	}
	if !sameHostname(u.Hostname(), targetHost) {
		return ""
	}
	// 主机名带尾点：DNS 语义等价，但会原样进 SNI 与证书校验，导致 TLS
	// 握手失败。只有这种少见形态才重建 URL（其余情况原样返回，避免
	// url.String() 对路径做不必要的重新编码）。
	if trimmed := strings.TrimSuffix(u.Hostname(), "."); trimmed != u.Hostname() {
		// 端口必须在改写 u.Host 之前取出：u.Port() 读的是 u.Host 自身。
		port := u.Port()
		u.Host = trimmed
		if port != "" {
			u.Host = trimmed + ":" + port
		}
		return u.String()
	}
	return loc
}
