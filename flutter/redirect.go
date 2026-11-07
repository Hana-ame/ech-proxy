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

// resolveSameHost 解析重定向 Location：仅当目标是 [targetHost] 的 http(s)
// URL（或相对路径）时返回完整 URL，否则返回空串（表示不跟随）。
func resolveSameHost(loc, targetHost string) string {
	if loc == "" {
		return ""
	}
	if strings.HasPrefix(loc, "/") {
		return "https://" + targetHost + loc
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if (u.Scheme == "http" || u.Scheme == "https") && strings.TrimSuffix(u.Hostname(), ".") == targetHost {
		return loc
	}
	return ""
}
