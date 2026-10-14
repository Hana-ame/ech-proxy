# ech-proxy 443 模式故障诊断与全量 Issue 审查报告

## 一、 核心结论：为什么 443 报一串错误且 `i.pximg.net` 无法访问？

`i.pximg.net` 无法访问且 443 端口回报一串错误，**既包含 `upstream.json` 与 `hosts` 的配置断层，也包含 `ech-proxy` 在本地 443 模式下的路由、重写、证书及传输层代码缺陷**。

在 Pixiv 页面加载时，浏览器会并发发起 30～100+ 个针对 `i.pximg.net`（图片 CDN）和 `s.pximg.net`（静态资源）的 HTTPS 请求。当前仓库状态下，以下 **5 个直接根因** 叠加导致了 443 端口集中刷屏报错：

| 故障表现（443 报错类型） | 触发条件 | 对应根因 Issue |
| :--- | :--- | :--- |
| `[<IP>] 未找到上游配置: i.pximg.net`（返回 HTTP 502 `no upstream for host: i.pximg.net`） | `hosts` 已将 `i.pximg.net` 指向 `127.0.0.1`，但使用默认 `upstream.json` | **Issue #1**：`upstream.json` 仅配置了远端模式入口 `pximg.l.moonchan.xyz`，缺少本地 443 模式的 `i.pximg.net` / `*.pximg.net` 原域名规则。 |
| 浏览器侧 `ERR_CONNECTION_RESET` / `ERR_TIMED_OUT`，或改完 `hosts` 后仍不走本地 443 | 按 `README.md` 只在 `hosts` 写了 `127.0.0.1 pixiv.net` 或 `127.0.0.1 pximg.net` | **Issue #2**：`README.md` 误将 TLS 通配符证书（SAN `*.pixiv.net`）当成了系统 `hosts` 通配能力；OS `hosts` 不支持子域通配，写 `pximg.net` 不会匹配 `i.pximg.net`。 |
| 443 代理转发成功但全部返回 **HTTP 403 Forbidden** | 手动加了 `i.pximg.net` 上游规则，但未配 `referer` 或 Referer 丢失 | **Issue #3**：`i.pximg.net` 强校验防盗链头 `Referer: https://www.pixiv.net/`，缺失或为其他域时源站直接拒访。 |
| `http: TLS handshake error from 127.0.0.1:... remote error: tls: unknown certificate / bad certificate` | 未安装本地 `ca/ca.pem`、使用 Firefox 独立证书库、或误运行了仓库根目录旧版二进制 | **Issue #4 & #5**：仓库根目录残留 `2026-09-16` 编译的旧版 `./ech-proxy` 二进制（无 `-local` 与动态签发 CA 能力，只返回 `*.l.moonchan.xyz` 证书）；或浏览器未信任本地自签 CA。 |
| `[<IP>] 上游请求失败: TLS handshake <ip>: ...` 或 `upstream did not negotiate h2` / `all IPs failed` | `i.pximg.net` 命中通配规则自动探测模式（`wildcardMode`）或 `sni` 模式 | **Issue #6**：`wildcardMode` 将非 Cloudflare IP 自动切为 `sni` 模式，而 `newSNIFrontTransport` 硬编码发送 `ServerName: "cloudflare-ech.com"` 且强制要求 `h2`；同时 `wildcardMode` 在 DoH 瞬时失败时会把错误模式负缓存 10 分钟。 |

## 二、 P0 级 Issue 清单（直接导致 443 报错与 `i.pximg.net` 无法访问，需优先修复）

### Issue #1：`upstream.json` 缺少本地 443 模式的 `i.pximg.net` / `s.pximg.net` 原域名路由规则

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

### Issue #2：`README.md` 对 `hosts` 文件机制描述错误，且排障指引写错域名（`pximg.net` vs `i.pximg.net`）

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

### Issue #3：本地 443 模式下 `rewrites` 域名改写与 `hosts` 直连的冲突

* **定位**：`echproxy/rewriter.go` (`buildEntryRewriter` / `buildRewriter`)、`echproxy/proxy.go` (`ProxyHandler`)
* **问题描述**：
  1. 在 `ProxyHandler` 中，响应体改写器通过 `net.SplitHostPort(c.Request.Host)` 提取端口 `port`。当运行在 443 端口时，浏览器的 `Host` 请求头不带 `:443`，`SplitHostPort` 返回错误，`port` 为空字符串 `""`。
  2. 如果 `pixiv.net` 条目配置了 `"rewrites": {"i.pximg.net": "pximg.l.moonchan.xyz"}`（或继承自远端配置），则 `www.pixiv.net` 返回的 HTML/JS/JSON 中的 `i.pximg.net` 会被改写为 `https://pximg.l.moonchan.xyz/...`（默认 443 端口）。
  3. 此时如果用户的 `hosts` 没有把 `pximg.l.moonchan.xyz` 指向 `127.0.0.1`，浏览器会向公网 `pximg.l.moonchan.xyz:443` 发起请求并失败；而由前端 JS 动态拼接、未被静态 `rewrites` 命中的图片请求则会请求 `https://i.pximg.net/...`。
* **修复方案**：
  1. 在本地 443 模式下，对于原域名直连条目（key 不含 `.l.moonchan.xyz`，如 `pixiv.net`），不应将子资源域名改写到 `*.l.moonchan.xyz`，或者应在本地模式下自动同时支持 `pximg.l.moonchan.xyz` 与原域名 `i.pximg.net`。
  2. 若 `pixiv.net` 在本地模式下开启 `sw_inject` 或 `rewrites`，需确保改写目标域名本身也在本地 `hosts` 覆盖范围内，或保持原域名 `i.pximg.net` 不改写、直接由 `127.0.0.1:443` 的 `i.pximg.net` 规则接管。

### Issue #4：仓库根目录残留旧版编译产物 `./ech-proxy`（2026-09-16 版本）导致严重行为错配

* **定位**：仓库根目录 `/ech-proxy` 二进制文件、`.gitignore`（第 2 行 `/ech-proxy`）
* **问题描述**：
  对当前工作区中的 `./ech-proxy` 可执行文件进行符号表与 DWARF 调试信息检查发现：
  * 其内嵌构建信息为 `vcs.revision=36fb9952d2c6e21424f36055f81be714067e6b5e`（构建时间 `2026-09-16T09:56:45Z`，`vcs.modified=true`）。
  * 该二进制仅支持 `-addr`、`-config`、`-http`、`-v` 四个旧参数，**完全不包含 `-local`、`.443.exe` 自动检测、本地 CA 签发 (`localca`)、按上游 `ip_mode` 隔离连接池、以及 `utls` ECH 握手（该二进制中 `ech/client.go` 仍调用标准库 `crypto/tls.Client`）**。
  * 由于 `.gitignore` 忽略了 `/ech-proxy`，`git pull` 或切换分支后该旧二进制一直静默留在根目录。一旦在测试时直接执行了 `./ech-proxy -addr 127.0.0.1:443`，它会使用 `*.l.moonchan.xyz` 证书响应 `pixiv.net` / `i.pximg.net`，导致所有 443 请求在 TLS 握手阶段直接报错。
* **修复方案**：
  立即删除或重新编译根目录下的 `./ech-proxy`（`go build -o ech-proxy ./win/`），并在启动 banner 中打印编译进来的 `vcs.revision` 与 `vcs.time`，防止运行过期二进制而不自知。

### Issue #5：本地 443 模式 TLS 证书信任链（`ca/ca.pem`）与客户端握手报错处理

* **定位**：`README.md` Step 4、`echproxy/server.go`
* **问题描述**：
  1. 在 `-local`（443）模式下，`ech-proxy` 对非 `l.moonchan.xyz` 域名使用本地自签 CA 动态签发证书。若用户未将 `<data-dir>/ca/ca.pem` 导入系统“受信任的根证书颁发机构”，或使用 Firefox（默认使用内置 NSS 根证书库而非系统证书库），浏览器对每个 `i.pximg.net` 请求都会立即中断握手，443 控制台会刷出成串的 `http: TLS handshake error ... remote error: tls: unknown certificate`。
  2. 当前 `http.Server` 默认 `ErrorLog` 会将每一次浏览器预连接（preconnect）或未信任 CA 导致的 TLS Alert 原样刷屏，缺乏去重或明确提示（例如提示用户“检测到客户端拒绝本地 CA 证书，请确认已安装 `<data-dir>/ca/ca.pem`”）。
* **修复方案**：
  1. 在本地 443 模式的 `http.Server.ErrorLog` 或自定义 `ConnState` / TLS 包装层中，识别 `tls: unknown certificate` / `tls: bad certificate`，聚合打印友好的排障提示（包含当前 `ca.pem` 的绝对路径及 Firefox `security.enterprise_roots.enabled` 设置说明）。

### Issue #6：`wildcardMode` 的 10 分钟错误负缓存与 `sni` 模式的硬编码限制

* **定位**：`echproxy/wildcard.go` (`wildcardMode` @ `0xbab820`)、`echproxy/sni.go` (`newSNIFrontTransport` @ `0xba9520`)
* **问题描述**：
  1. **DoH 失败负缓存 10 分钟**：在 `wildcardMode` 中，当通配规则未显式指定 `mode` 时，会调用 `resolveIPFn` (DoH) 解析目标主机 IP 并检查是否属于 `cloudflareNets`。但如果启动初期或网络抖动导致 `resolveIPFn` 返回错误（`err != nil`），代码并未提前返回，而是将空模式 `""`（默认走 `ech`）写入 `wildcardModeCache` 并缓存 **10 分钟**（600s）。
  2. **`sni` 模式硬编码 `ServerName: "cloudflare-ech.com"` 与强制 `h2`**：当 `i.pximg.net` 或其他通配子域被判定为非 Cloudflare IP 而进入 `sni` 模式时，`newSNIFrontTransport` 直连目标 IP 的 443 端口，但将 TLS `ServerName` 硬编码为 `"cloudflare-ech.com"`，且在握手后强制检查 `NegotiatedProtocol == "h2"`（否则报错 `upstream did not negotiate h2`）。若目标 CDN 节点（如 Fastly/Akamai）不接受 `cloudflare-ech.com` 作为 SNI 或仅协商 `http/1.1`，则所有请求全部失败。
* **修复方案**：
  1. 在 `wildcardMode` 中，若 `resolveIPFn` 返回 `err != nil`，**不要写入 `wildcardModeCache`**（或仅做极短如 5s 的退避），避免单次 DoH 抖动锁死 10 分钟。
  2. 为 `UpstreamConfig` / `WildcardRule` 的 `sni` 模式增加可配置的 `sni_server_name`（或允许置空以发送无 SNI 的 ClientHello），并移除对非 Cloudflare 源站不必要的强制 `h2` 限制（允许回退到 `http/1.1`）。

## 三、 P1 级 Issue 清单（架构一致性、配置静默失败与传输层隐患）

### Issue #7：`NewServer` 在 TLS 证书加载失败时静默降级为明文 HTTP

* **定位**：`echproxy/server.go` (`NewServer` @ `0xba7cd4`)
* **问题描述**：
  在非 `-http` 模式下，当 `LoadTLSCert` 失败（如网络无法拉取远端证书或本地证书文件损坏）时，`NewServer` 仅打印一行 `"加载证书失败，将降级运行: %v"`，随后将 `IsTLS` 置为 `false`，在 `8443` 或 `443` 端口上**以明文 HTTP 启动服务**。客户端用 `https://` 访问 443/8443 时会收到大量 TLS 记录层错误，极难排查。
* **修复方案**：
  除非用户显式传入 `-http`，否则 TLS 证书（或本地 CA）初始化失败时应直接返回 `error` 终止启动，绝不静默在 HTTPS 端口上降级为明文 HTTP。

### Issue #8：`upstream.json` 的 6 类“静默失败”（Silent Failures S1–S6）未在主干拦截

* **定位**：`echproxy/config.go`、`echproxy/ech/client.go`、`echproxy/cookie.go`、`NOTES-experiments.md`
* **问题描述**：
  如 `NOTES-experiments.md` 实战暴露，以下配置错误在运行时均不报错、直接静默失效：
  1. **S1**：在 `upstream.json` 顶层写 `ip_mode` 被 `json.Unmarshal` 静默丢弃（`Config` 结构体无此字段）。
  2. **S2**：`ip_mode: "V4"` 因大小写敏感在 `ech/client.go` 中静默退化为 `auto`。
  3. **S3**：在 `mode: "direct"` 或 `mode: "sni"`（以及 CONNECT 隧道）条目上配置 `ip_mode` 完全无效且无警告（仅 `ech` 分支读取了 `ipMode`）。
  4. **S4**：`ip_mode: "v4"` 但目标域名无 A 记录时硬报错 `no v4 address for <host>`，无清晰排障上下文。
  5. **S5**：JSON 键名拼写错误（如 `ipmode`、`rewirtes`）被静默忽略。
  6. **S6**：`cookie_priority` 拼写错误静默落入默认分支。
* **修复方案**：
  1. 尽快将 `exp/exp01-config-validate` 分支的配置校验器（`Validate` + `-check-config`）合入 `main`，在服务启动加载配置时默认输出 warning/error 日志。
  2. 推进 `exp/arch04-unify-egress`：将 `ip_mode` 下沉到统一的拨号/地址解析层，使 `ech`、`sni`、`direct` 与 `connect` 四条路径统一遵守 `ip_mode`。

### Issue #9：项目内存在三套割裂的 DNS 解析实现，`sni` 模式不支持 IPv6 且 `ech` 本地解析易受 UDP 53 污染

* **定位**：`echproxy/ech/client.go` (`resolvePreferredIP` / `CheckDualStack`)、`echproxy/sni.go` (`resolveHostIPs`)、`echproxy/netdial/netdial.go` (`getResolver`)
* **问题描述**：
  1. `ech/client.go` 的 `resolvePreferredIP` 和 `CheckDualStack` 使用 `netdial.getResolver().lookupIPAddr`，底层走的是对 `8.8.8.8:53` / `1.1.1.1:53` 的明文 UDP DNS 查询。在国内网络环境下，对 `8.8.8.8:53` 的 UDP 查询极易被抢答污染或丢包，一旦未设置 `-local-ip` 且触发了 `resolvePreferredIP`，就会拿到被污染的 IP 或超时。
  2. `sni.go` 的 `resolveHostIPs` 走的是 `ech.QueryDoH(ctx, host, 1)`，硬编码只查询 `Type=1`（IPv4 A 记录），若无 A 记录直接报错 `no A record for %s`，完全不支持 IPv6 (`AAAA`)。
* **修复方案**：
  收拢三处地址解析逻辑（对应 `exp/exp04-dedup-address-resolution`）：统一通过受 bootstrap IP 保护的 DoH 客户端解析 A/AAAA 记录，并根据条目的 `ip_mode` (`v4` / `v6` / `auto`) 过滤和缓存结果。

### Issue #10：反代控制平面接口（`/control/cookie`、`/_ech/cookie`）与 CONNECT 隧道的安全边界缺口

* **定位**：`CONNECT-boundaries.md`、`DESIGN-tunnel-limits-and-android.md`、`echproxy/router.go`
* **问题描述**：
  1. 控制接口 `/control/cookie` 与 `/_ech/cookie` 允许直接切换上游的公用/本地 Cookie 模式（甚至通过 URL 参数 `?_cookie_mode=seed|browser` 触发），且全局 `CORSMiddleware` 无条件反射 `Origin` 并设置 `Access-Control-Allow-Credentials: true`。任意网页可通过跨站请求静默切换用户本地代理的 Cookie 优先级模式。
  2. `exp/exp02-connect-tunnel` 分支的 CONNECT 隧道若未合入认证、SSRF 目标黑名单（拦截 `127.0.0.1`、内网段、`169.254.169.254`）以及 per-peer/global 并发连接数上限（`DESIGN-tunnel-limits-and-android.md`），在绑定 `0.0.0.0` 时会直接暴露为无限制开放代理。
* **修复方案**：
  1. 为 `/control/cookie` 等状态修改接口增加 CSRF 防护（校验 `Origin`/`Referer` 必须为 `l.moonchan.xyz` 门户页）及可选 Token 认证。
  2. 按 `DESIGN-tunnel-limits-and-android.md` 落实验证守卫顺序（认证 → 目标黑名单校验 → per-peer 128 / global 1024 限流 → 空闲超时 `deadlineConn` → dial）。

## 四、 P2 级 Issue 清单（Android 端对齐与 CI/Release 工程化）

### Issue #11：CI 工作流忽略 `**.json` 导致线上 `upstream.json` 改动处于无测试盲区

* **定位**：`.github/workflows/go.yml`、`certs/l.moonchan.xyz/upstream.json`、`NOTES-experiments.md`
* **问题描述**：
  由于运行中的客户端会在启动时直接从 GitHub `main` 分支拉取 `certs/l.moonchan.xyz/upstream.json`，`main` 分支上的 JSON 改动是**即时全网生效的生产变更**。但 `go.yml` 配置了 `paths-ignore: ['**.json']`，导致单独修改 `upstream.json` 的提交完全不触发 CI，一旦出现语法错误、重复键或非法 `ip_mode`，会导致全量客户端拉取配置失败。
* **修复方案**：
  在 `.github/workflows/go.yml` 中移除对 `certs/l.moonchan.xyz/upstream.json` 的忽略（或新增轻量级 `validate-config` CI Job），在每次 PR / push 时自动运行 `go run ./win -check-config -config certs/l.moonchan.xyz/upstream.json`。

### Issue #12：Android 端与桌面端能力边界及环境变量未对齐

* **定位**：`android/main.go`、`CONNECT-boundaries.md`、`DESIGN-tunnel-limits-and-android.md`
* **问题描述**：
  1. `android/main.go` 仅读取了 `IP_MODE` 与 `LOCALIP`，未对齐桌面端新增的鉴权环境变量（`ECH_PROXY_TOKEN` / `ECH_PROXY_USER` / `ECH_PROXY_PASS`）。
  2. Android 端是否支持本地 `pximg.net` 规则及不开 CONNECT 隧道的设计边界未在 `README.md` 中说明。
* **修复方案**：
  按 `DESIGN-tunnel-limits-and-android.md` 第一步与第二步对齐 `android/main.go` 的配置项读取，并在 `README.md` 中补充桌面端与 Android 端的功能对照表。

## 五、 针对当前 `i.pximg.net` 443 问题的立即可执行排查与修复步骤

1. **确认运行的二进制版本**：
   不要运行仓库根目录下 `2026-09-16` 的旧版 `./ech-proxy`；使用最新源码重新编译 `ech-proxy.443.exe`（或带 `-local -addr 127.0.0.1:443` 参数运行新编译产物）。
2. **补齐 `hosts` 中的 `i.pximg.net` 与 `s.pximg.net`**：
   确保系统 `hosts` 中显式包含：
   ```text
   127.0.0.1 pixiv.net
   127.0.0.1 www.pixiv.net
   127.0.0.1 accounts.pixiv.net
   127.0.0.1 i.pximg.net
   127.0.0.1 s.pximg.net
   ```
3. **在 `upstream.json` 中补齐 `i.pximg.net` 本地规则**：
   添加 `"i.pximg.net"` 条目（含 `"wildcard": {"entry": "*.pximg.net", "upstream": "*.pximg.net"}`、`"referer": "https://www.pixiv.net/"`、`"mode": "ech"`、`"ip_mode": "v4"`），并通过 `-config` 指定本地修改后的 `upstream.json` 验证。
4. **确认系统与浏览器已信任本地 CA**：
   将启动日志 `Data dir:` 下的 `ca/ca.pem` 导入系统“受信任的根证书颁发机构”并重启浏览器（若使用 Firefox，在 `about:config` 中开启 `security.enterprise_roots.enabled` 或在设置中手动导入 `ca.pem`）。
