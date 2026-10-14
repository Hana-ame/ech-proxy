# Issue #2：`README.md` 对 `hosts` 文件机制描述错误，且排障指引写错域名（`pximg.net` vs `i.pximg.net`）

* **定位**：`README.md` Step 2（第 76–98 行）与 Troubleshooting（第 179 行）
* **问题描述**：
  1. **错误声称 `hosts` 单条记录可覆盖所有子域名**：`README.md` 第 84–94 行写道 *“so all subdomains are covered by the single `pixiv.net` entry in your hosts file... you can safely drop the subdomain lines and keep only `127.0.0.1 pixiv.net`”*。实际上，TLS 证书的 `*.pixiv.net` SAN 通配仅在连接已到达 `127.0.0.1:443` 后生效；操作系统的 `hosts` 文件**完全不支持通配符**，若删掉子域名行，`www.pixiv.net`、`accounts.pixiv.net` 等将不再解析到 `127.0.0.1`。
  2. **排障表域名缺失子域前缀**：第 179 行建议 *“Add `127.0.0.1 pximg.net` to hosts”*。Pixiv 实际请求的是 `i.pximg.net` 和 `s.pximg.net`，在 `hosts` 中只写 `pximg.net` 无法劫持 `i.pximg.net` 的流量。
* **修复方案**：
  修正 `README.md` Step 2 与 Troubleshooting，明确说明 OS `hosts` 必须显式列出所有需要代理的具体子域名：
  ```text
  127.0.0.1 pixiv.net
  127.0.0.1 www.pixiv.net
  127.0.0.1 accounts.pixiv.net
  127.0.0.1 account.pixiv.net
  127.0.0.1 api.sec.pixiv.net
  127.0.0.1 manga.pixiv.net
  127.0.0.1 comic.pixiv.net
  127.0.0.1 dic.pixiv.net
  127.0.0.1 i.pximg.net
  127.0.0.1 s.pximg.net
  ```
