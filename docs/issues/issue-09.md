# Issue #9：项目内存在三套割裂的 DNS 解析实现，`sni` 模式不支持 IPv6 且 `ech` 本地解析易受 UDP 53 污染

* **定位**：`echproxy/ech/client.go` (`resolvePreferredIP` / `CheckDualStack`)、`echproxy/sni.go` (`resolveHostIPs`)、`echproxy/netdial/netdial.go` (`getResolver`)
* **问题描述**：
  1. `ech/client.go` 的 `resolvePreferredIP` 和 `CheckDualStack` 使用 `netdial.getResolver().lookupIPAddr`，底层走的是对 `8.8.8.8:53` / `1.1.1.1:53` 的明文 UDP DNS 查询。在国内网络环境下，对 `8.8.8.8:53` 的 UDP 查询极易被抢答污染或丢包，一旦未设置 `-local-ip` 且触发了 `resolvePreferredIP`，就会拿到被污染的 IP 或超时。
  2. `sni.go` 的 `resolveHostIPs` 走的是 `ech.QueryDoH(ctx, host, 1)`，硬编码只查询 `Type=1`（IPv4 A 记录），若无 A 记录直接报错 `no A record for %s`，完全不支持 IPv6 (`AAAA`)。
* **修复方案**：
  收拢三处地址解析逻辑（对应 `exp/exp04-dedup-address-resolution`）：统一通过受 bootstrap IP 保护的 DoH 客户端解析 A/AAAA 记录，并根据条目的 `ip_mode` (`v4` / `v6` / `auto`) 过滤和缓存结果。
