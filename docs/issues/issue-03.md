# Issue #3：本地 443 模式下 `rewrites` 域名改写与 `hosts` 直连的冲突

* **定位**：`echproxy/rewriter.go` (`buildEntryRewriter` / `buildRewriter`)、`echproxy/proxy.go` (`ProxyHandler`)
* **问题描述**：
  1. 在 `ProxyHandler` 中，响应体改写器通过 `net.SplitHostPort(c.Request.Host)` 提取端口 `port`。当运行在 443 端口时，浏览器的 `Host` 请求头不带 `:443`，`SplitHostPort` 返回错误，`port` 为空字符串 `""`。
  2. 如果 `pixiv.net` 条目配置了 `"rewrites": {"i.pximg.net": "pximg.l.moonchan.xyz"}`（或继承自远端配置），则 `www.pixiv.net` 返回的 HTML/JS/JSON 中的 `i.pximg.net` 会被改写为 `https://pximg.l.moonchan.xyz/...`（默认 443 端口）。
  3. 此时如果用户的 `hosts` 没有把 `pximg.l.moonchan.xyz` 指向 `127.0.0.1`，浏览器会向公网 `pximg.l.moonchan.xyz:443` 发起请求并失败；而由前端 JS 动态拼接、未被静态 `rewrites` 命中的图片请求则会请求 `https://i.pximg.net/...`。
* **修复方案**：
  1. 在本地 443 模式下，对于原域名直连条目（key 不含 `.l.moonchan.xyz`，如 `pixiv.net`），不应将子资源域名改写到 `*.l.moonchan.xyz`，或者应在本地模式下自动同时支持 `pximg.l.moonchan.xyz` 与原域名 `i.pximg.net`。
  2. 若 `pixiv.net` 在本地模式下开启 `sw_inject` 或 `rewrites`，需确保改写目标域名本身也在本地 `hosts` 覆盖范围内，或保持原域名 `i.pximg.net` 不改写、直接由 `127.0.0.1:443` 的 `i.pximg.net` 规则接管。
