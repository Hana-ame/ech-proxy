# Issue #5：本地 443 模式 TLS 证书信任链（`ca/ca.pem`）与客户端握手报错处理

* **定位**：`README.md` Step 4、`echproxy/server.go`
* **问题描述**：
  1. 在 `-local`（443）模式下，`ech-proxy` 对非 `l.moonchan.xyz` 域名使用本地自签 CA 动态签发证书。若用户未将 `<data-dir>/ca/ca.pem` 导入系统“受信任的根证书颁发机构”，或使用 Firefox（默认使用内置 NSS 根证书库而非系统证书库），浏览器对每个 `i.pximg.net` 请求都会立即中断握手，443 控制台会刷出成串的 `http: TLS handshake error ... remote error: tls: unknown certificate`。
  2. 当前 `http.Server` 默认 `ErrorLog` 会将每一次浏览器预连接（preconnect）或未信任 CA 导致的 TLS Alert 原样刷屏，缺乏去重或明确提示（例如提示用户“检测到客户端拒绝本地 CA 证书，请确认已安装 `<data-dir>/ca/ca.pem`”）。
* **修复方案**：
  1. 在本地 443 模式的 `http.Server.ErrorLog` 或自定义 `ConnState` / TLS 包装层中，识别 `tls: unknown certificate` / `tls: bad certificate`，聚合打印友好的排障提示（包含当前 `ca.pem` 的绝对路径及 Firefox `security.enterprise_roots.enabled` 设置说明）。
