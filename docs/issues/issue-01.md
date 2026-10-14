# Issue #1：`upstream.json` 缺少本地 443 模式的 `i.pximg.net` / `s.pximg.net` 原域名路由规则

* **定位**：`certs/l.moonchan.xyz/upstream.json`、`echproxy/proxy.go` (`ProxyHandler`)、`README.md`（第 96–98 行、第 179 行）
* **问题描述**：
  1. 在 8443 门户模式下，`upstream.json` 通过 `"pximg.l.moonchan.xyz": {"host": "i.pximg.net", "referer": "https://www.pixiv.net/"}` 和 `"pximg-s.l.moonchan.xyz": {"host": "s.pximg.net", ...}` 路由图片与静态脚本。
  2. 但在本地 443 反代模式（`-local` / `ech-proxy.443.exe`）下，浏览器直接请求原域名 `https://i.pximg.net/...` 与 `https://s.pximg.net/...`。`ProxyHandler` 依次查找 `cfg.Upstreams[host]` 与 `matchWildcard(cfg, host)`，因线上配置只添加了 `pixiv.net`（含 `*.pixiv.net` 通配）而未添加 `i.pximg.net`、`s.pximg.net` 或 `*.pximg.net` 的原域名规则，所有图片请求全部落入 `未找到上游配置: i.pximg.net` 分支并返回 502。
* **修复方案**：
  在 `certs/l.moonchan.xyz/upstream.json` 中内置本地 443 模式的 `pximg.net` 规则（或直接补齐 `i.pximg.net` 与 `s.pximg.net` 条目），并强制绑定防盗链 `referer` 与 `ip_mode: "v4"`：
  ```json
  "i.pximg.net": {
      "host": "i.pximg.net",
      "mode": "ech",
      "ip_mode": "v4",
      "referer": "https://www.pixiv.net/",
      "wildcard": {
          "entry": "*.pximg.net",
          "upstream": "*.pximg.net",
          "mode": "ech",
          "ip_mode": "v4",
          "referer": "https://www.pixiv.net/"
      }
  }
  ```
