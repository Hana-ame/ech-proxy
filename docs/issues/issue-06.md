# Issue #6：`wildcardMode` 的 10 分钟错误负缓存与 `sni` 模式的硬编码限制

* **定位**：`echproxy/wildcard.go` (`wildcardMode` @ `0xbab820`)、`echproxy/sni.go` (`newSNIFrontTransport` @ `0xba9520`)
* **问题描述**：
  1. **DoH 失败负缓存 10 分钟**：在 `wildcardMode` 中，当通配规则未显式指定 `mode` 时，会调用 `resolveIPFn` (DoH) 解析目标主机 IP 并检查是否属于 `cloudflareNets`。但如果启动初期或网络抖动导致 `resolveIPFn` 返回错误（`err != nil`），代码并未提前返回，而是将空模式 `""`（默认走 `ech`）写入 `wildcardModeCache` 并缓存 **10 分钟**（600s）。
  2. **`sni` 模式硬编码 `ServerName: "cloudflare-ech.com"` 与强制 `h2`**：当 `i.pximg.net` 或其他通配子域被判定为非 Cloudflare IP 而进入 `sni` 模式时，`newSNIFrontTransport` 直连目标 IP 的 443 端口，但将 TLS `ServerName` 硬编码为 `"cloudflare-ech.com"`，且在握手后强制检查 `NegotiatedProtocol == "h2"`（否则报错 `upstream did not negotiate h2`）。若目标 CDN 节点（如 Fastly/Akamai）不接受 `cloudflare-ech.com` 作为 SNI 或仅协商 `http/1.1`，则所有请求全部失败。
* **修复方案**：
  1. 在 `wildcardMode` 中，若 `resolveIPFn` 返回 `err != nil`，**不要写入 `wildcardModeCache`**（或仅做极短如 5s 的退避），避免单次 DoH 抖动锁死 10 分钟。
  2. 为 `UpstreamConfig` / `WildcardRule` 的 `sni` 模式增加可配置的 `sni_server_name`（或允许置空以发送无 SNI 的 ClientHello），并移除对非 Cloudflare 源站不必要的强制 `h2` 限制（允许回退到 `http/1.1`）。
