# Changelog — 2026-11-28: 双代理共存方案（新增 `bypass.txt`）与引导 DoH 日志刷屏修复

> **变更日期**：2026-11-28
>
> **关联需求**：
>
> 1. 提供并落地两种与主力代理（Clash / Mihomo / v2rayN 等）共存的架构方案：
>
>    * 方案一：`系统 -> ech-proxy -> bypass.txt（本地/在线） -> 全局代理`
>
>    * 方案二：`系统 -> Clash(全局代理) -> ech-proxy`
>
> 2. 排查并修复 `netdial.go:572: [netdial] bootstrap DoH primary endpoints (1.1.1.1/1.0.0.1) unreachable for "4545810.xyz", trying domestic endpoints as last resort` 大量刷屏问题。

## 一、 两种代理共存方案

### 方案一：`系统 -> ech-proxy -> bypass.txt（本地/在线） -> 全局代理`

适合希望以 `ech-proxy` 作为系统入口（自动用 ECH/SNI/Fragment 免费直连大多数站点），同时将特定域名（如 Google、YouTube、OpenAI 等 IP 级封锁站点）通过 `bypass.txt` **直接转交给上游全局代理**，且其余站点直连失败时自动兜底逃逸到全局代理的场景。

1. **前置准备**：

   * 启动主力代理软件（如 Clash Verge Rev / Mihomo / v2rayN），**关闭其「系统代理」与「TUN 模式」**，仅保留本地混合/HTTP 监听端口（例如 `127.0.0.1:7897` 或 `127.0.0.1:10809`）。

2. **准备 `bypass.txt`（本地优先 / 支持在线）**：

   * **本地方式（推荐，离线可用，30 秒内热加载）**：在 `ech-proxy.exe` 同目录（或 `<dataDir>` / 当前工作目录）放置 `bypass.txt`，每行一个域名，支持 `#` / `//` 注释和 `*.example.com`：

     ▶ 代码块已折叠（约 18 行）点击展开

     ▶ 代码块已折叠（约 18 行）点击展开

     ▶ 代码块已折叠（约 18 行）点击展开

     ▶ 代码块已折叠（约 18 行）点击展开

     ▶ 代码块已折叠（约 18 行）点击展开

     ▶ 代码块已折叠（约 18 行）点击展开

     ```
     # 命中此名单的域名直接绕过 ech-proxy，转交上游全局代理（自动匹配所有子域名）
     # Google / YouTube
     google.com
     youtube.com
     googlevideo.com
     
     # OpenAI / ChatGPT
     openai.com
     chatgpt.com
     
     # Claude / Anthropic 全家桶
     claude.ai
     claude.com
     anthropic.com
     claudeusercontent.com
     
     
     
     ```

   * **在线方式**：通过 `-bypass-url https://your-host/bypass.txt`（或环境变量 `ECH_PROXY_BYPASS_URL`）指定在线列表；若未提供本地文件也未指定 `-bypass-url`，默认自动拉取 `https://4545810.xyz/bypass.txt`（远端不可用时静默保持空表，不影响主线 PAC）。

   * **其他开关**：`-bypass-file <路径>` 显式指定本地路径；`-no-local-bypass`（或 `ECH_PROXY_NO_LOCAL_BYPASS=1`）忽略本地文件强制走在线。

3. **启动 `ech-proxy` 并接入上游全局代理**：

   ```
   # 示例：上游 Clash 混合端口为 127.0.0.1:7897
   .\ech-proxy.exe -fallback 127.0.0.1:7897
   
   
   
   
   
   
   ```

   * 若启动 `ech-proxy` 前系统代理已指向主力代理（如 `127.0.0.1:7897`），`ech-proxy` 也会自动捕获旧系统代理作为 `fallback`，退出时自动恢复。

4. **分流优先级（PAC 层 + 服务端双保险）**：

   * 本地环回/内网（`localhost` / `127.*` / `10.*` / `192.168.*` / `*.local`）→ `DIRECT`

   * **命中 `bypass.txt`** → 直接返回/转发至上游全局代理（`-fallback`），**优先级高于 `-all` 全局模式和 `pac.txt`**，不经 ECH/MITM 直连探测

   * 未命中 `bypass.txt` 且处于 `-all` 模式或命中 `pac.txt` → 走 `ech-proxy`（ECH/SNI/Fragment 直连）；若直连因 IP 封锁失败，自动无感逃逸到 `-fallback` 全局代理

   * 非 `-all` 模式且未命中 `pac.txt` → 直接走 `FALLBACK_STR`（全局代理，未配时 `DIRECT`）

### 方案二：`系统 -> Clash(全局代理) -> ech-proxy`

适合完全由 Clash / Mihomo 统一接管系统代理或 TUN 虚拟网卡，将 `ech-proxy` 降级为纯本地 HTTP 出口节点（`127.0.0.1:8443`）的场景。

1. **关闭 `ech-proxy` 的系统代理接管**：

   * 推荐直接命令行启动，避免接管系统代理：

     ```
     .\ech-proxy.exe -sys-proxy off
     
     
     
     
     
     
     ```

   * 或启动后右键托盘图标点击 **「系统代理：清除 / 禁用系统代理 (直连)」**。

   * *说明*：v3.6.1 起 `-all` 全代理模式**默认开启**，无需额外传 `-all` 即可处理主力代理转发过来的所有域名（若曾手动取消托盘中的「全代理模式」，重新勾选即可）。

2. **在 Clash / Mihomo 中添加本地 HTTP 出口节点**：

   ```
   proxies:
     - name: "ECH-Local"
       type: http
       server: 127.0.0.1
       port: 8443
   
   
   
   
   
   
   ```

3. **配置规则与防回环（关键）**：

   * 若 Clash 开启 **TUN 模式**，**必须**将 `ech-proxy.exe` 设为 `DIRECT` 并置于规则最顶部，否则 `ech-proxy` 发出的外网流量会被 TUN 再次拦截形成死循环。

   * 注意：Clash 的纯 `mode: global` 会跳过 `rules:`，在 TUN 模式下容易引发回环；建议在 Clash 中使用 `mode: rule`，并在底部用 `MATCH` 兜底实现等价全局分流：

   ```
   rules:
     # 1. 防止 TUN 模式下流量回环（必须置顶）
     - PROCESS-NAME,ech-proxy.exe,DIRECT
   
     # 2. 指定走 ech-proxy 的域名或规则集
     - DOMAIN-SUFFIX,pixiv.net,ECH-Local
     - DOMAIN-SUFFIX,pximg.net,ECH-Local
   
     # 3. 其余流量走你的主力全局代理策略组
     - MATCH,PROXY
   
   
   
   
   
   
   ```

   * 如不使用 TUN（仅 Clash 接管系统 HTTP 代理），`ech-proxy` 默认不读取系统代理环境变量，不会发生回环。

## 二、 引导 DoH 日志刷屏问题排查与修复

### 现象

控制台和日志文件中高频刷出：

```
2026/11/28 03:53:38.874925 netdial.go:572: [netdial] bootstrap DoH primary endpoints (1.1.1.1/1.0.0.1) unreachable for "4545810.xyz", trying domestic endpoints as last resort






```

### 根因分析

1. **冷却期内无条件重复打印日志（直接主因）**：

   * 在 `echproxy/netdial/netdial.go` 的 `doResolveViaBootstrapDoH` 中，当 `1.1.1.1` / `1.0.0.1` 首次在 800ms 优先窗口内不可达时，会调用 `markPrimaryBootstrapUnreachable` 进入 **10 分钟冷却期**（`bootstrapPrimaryCooldown`）。

   * 然而，在 10 分钟冷却期内，`if primaryBootstrapUsable(time.Now())` 为 `false` 跳过了主端点探测，此时 `won` 仍为 `nil`（`len(won) == 0`），程序随即进入 `if len(won) == 0 && domesticBootstrapAllowed()`，**无条件执行第 572 行的 `log.Printf`**。在 `dual` 模式下，单次调用甚至会因 A/AAAA 两次循环连打 2 条日志。

2. **缺少解析失败负缓存（Negative Cache）引发高频重试风暴**：

   * `4545810.xyz` 是项目首选 DoH 服务域名，每次拨号建立 DoH 连接时都会通过 `ResolveIPs`（携带 `IsInsideDoH` 标记）直接进入 `resolveViaBootstrapDoH`。

   * 当网络异常、代理冲突或特定协议族无记录导致主端点与国内兜底端点均未返回可用 IP（`len(filtered) == 0`）时，原代码直接返回错误而**不写入缓存**；后续每一个并发或新到达的代理请求都会重新触发解析与日志输出，造成秒级刷屏。

3. **缓存 TTL 与冷却期错配**：

   * `bootstrapCacheTTL` 为 5 分钟，小于 10 分钟的冷却期，即便国内兜底成功，冷却期内每过 5 分钟缓存过期后仍会再次触发告警打印。

### 修复内容

* **`echproxy/netdial/netdial.go` & `echproxy/ech/sni.go`（`4545810.xyz` 改用系统 DNS + 一次性 Cloudflare Anycast 广播 IP 回退）**：

  1. **不再使用 DoH 查询 `4545810.xyz`**：新增 `ResolveDefaultSiteHost(ctx, mode)`，在 `netdial.ResolveIPs`、`netdial.resolveViaBootstrapDoH` 以及 `ech.ResolveHostIPsByMode` 入口处统一拦截 `DefaultSiteHost`（`4545810.xyz`），彻底不再向 `1.1.1.1`/`1.0.0.1` 或国内 DoH 发起引导查询。

  2. **优先使用系统 DNS 并缓存**：通过 `net.DefaultResolver.LookupIPAddr`（3s 超时，过滤保留/回环 IP 后按当前 `-4`/`-6`/`-dual` 模式筛选）解析 `4545810.xyz`，成功结果缓存 5 分钟。

  3. **失败后置位一次性标志，回退内置 Cloudflare 广播 IP**：一旦系统 DNS 解析失败或无有效公网记录，原子置位一次性标志 `defaultSiteUseBuiltinCF`（仅首次打印一条提示日志），此后在本次进程生命周期内直接返回内置 Cloudflare Anycast 广播 IP（`104.16.132.229`、`104.16.133.229`、`2606:4700::6810:84e5`、`2606:4700::6810:85e5`，即 `nslookup cloudflare.com` 对应 IP）作为 `4545810.xyz` 的接入 IP，不再反复重试系统 DNS。

  4. **其余引导 DoH 路径防刷屏加固**：`markPrimaryBootstrapUnreachable(now)` 仅在刚切入 10 分钟冷却期时返回 `entered=true` 打印一次提示日志；新增 15 秒失败负缓存（`bootstrapNegCacheTTL`）。

* **`echproxy/netdial/netdial_test.go`**：

  * 新增 `TestResolveDefaultSiteHostSystemDNSAndOneTimeCFFallback` 与 `TestMarkPrimaryBootstrapUnreachableCooldownTransition` 回归测试。

## 三、 本次代码变更文件清单

| 文件路径 | 变更说明 | 
| ----- | ----- | 
| `echproxy/netdial/netdial.go` | `4545810.xyz` 改走系统 DNS，失败后置位一次性标志永久回退内置 Cloudflare Anycast 广播 IP；加固冷却期日志去重与 15s 负缓存 | 
| `echproxy/ech/sni.go` | `ResolveHostIPsByMode` 对 `4545810.xyz` 直接转交 `netdial.ResolveDefaultSiteHost`，不再走 DoH | 
| `echproxy/netdial/netdial_test.go` | 新增冷却期状态转换与日志去重单元测试 | 
| `echproxy/rewrite/paclocal.go` | 新增 `LocalBypassFileName`（`bypass.txt`）、`DefaultLocalBypassCandidates`、`ResolveBypassSource`（支持本地自动探测与在线地址） | 
| `echproxy/rewrite/adscript.go` | 新增 `DefaultBypassURL`、`BypassList`、`IsBypassed`、`RefreshBypassOnce` 及 30s 本地热加载与缓存隔离 | 
| `echproxy/rewrite/bypass_test.go` | 新增 `bypass.txt` 来源优先级与域名匹配单元测试 | 
| `echproxy/config/generators.go` | 新增 `GeneratePACWithRules`，在 PAC 中优先判定 `BYPASS_EXACT_HOSTS` / `BYPASS_SUFFIX_RULES` 直接转交 `FALLBACK_STR` | 
| `echproxy/portal.go` | `/proxy.pac` 接入 `bypass.txt` 与服务端 `-fallback`；`/statusz` 暴露 `bypass_count` / `bypass_source` / `bypass_kind` / `bypass_path` | 
| `echproxy/proxy.go` | `ProxyHandlerWithConfig` 命中 `bypass.txt` 且已配置 `-fallback` 时跳过 ECH/Fragment，直接走上游全局代理 | 
| `echproxy/server.go` | `ServerOptions` 与导出符号接入 `BypassURL` / `BypassFile` / `NoLocalBypass` | 
| `win/sysproxy.go` | 新增 `SetFallbackProxy`，使显式 `-fallback` 同步注入系统 PAC URL（`?fallback=...`） | 
| `win/main.go` | 新增 `-bypass-url` / `-bypass-file` / `-no-local-bypass` 命令行参数、环境变量、启动日志与热刷新回调 | 
| `README.md` | 补充双代理共存方案与 `bypass.txt` 配置说明 | 
| `changelog/2026-11-28-coexistence-bypass-and-doh-log-fix.md` | 本次变更记录文档 | 

## 四、 晚高峰连接优化（Happy Eyeballs 并发竞速 + 故障 IP 轮换 + 多路 HTTP/2）

* **`echproxy/netdial/netdial.go`**：

  * 新增故障 IP 冷却表（`MarkBadIP` / `ClearBadIP` / `IsBadIP` / `OrderIPsHealthyFirst`，默认 3 分钟冷却），将近期超时/失败的节点自动排到候选末尾。

  * 新增 `DialContextHappyEyeballs`（最多并发 3 路、100ms 阶梯发起，首个握手成功连接立即返回并关闭迟到连接防止泄漏），`DialContextIPMode` 统一切换至此实现。

* **`echproxy/ech/client.go`**：

  * ECH 通道不再死磕 `dohIPs[0]`，改为将 `cloudflare-ech.com` 全部解析 IP 交由 `DialContextHappyEyeballs` 并发竞速；握手超时/丢包时拉黑对应远端 IP 并允许重试轮换（仅证书错误永久中止）。

  * `Client` 升级为 **4 分片 HTTP/2 连接池（`echH2PoolShards = 4` 轮询）**，缓解高丢包环境下单一 TCP 连接的 HTTP/2 队头阻塞（Head-of-Line Blocking）。

* **`echproxy/ech/sni.go`**：

  * `roundTripUTLS`（供 `SNIFrontDo` 与 `FragmentDo` 共用）接入 `OrderIPsHealthyFirst` 与 `MarkBadIP`/`ClearBadIP` 自动轮换，并将 H2 连接池扩展为 2 分片并行。

* **`echproxy/netdial/netdial_test.go`**：

  * 新增 `TestBadIPCooldownAndOrderHealthyFirst` 与 `TestDialContextHappyEyeballsRacesAndReturnsFastest` 回归测试。

## 五、 ECH 通道新增 HTTP/3 备选回退与托盘开关（默认关闭）

* **`echproxy/ech/h3.go` & `echproxy/ech/client.go`**：

  * 新增 `SetECHHTTP3` / `GetECHHTTP3`（默认 `false`），仅在 `ech.Do` 的 HTTP/2 ECH 通道发生非证书错误失败时回退尝试 **HTTP/3 + ECH**（基于 `quic-go v0.59.0` + Go 1.26 标准库 `EncryptedClientHelloConfigList` + `validateUpstreamCert`）；**SNI 伪装与 Fragment 通道绝不使用 HTTP/3**。

  * 复用 `OrderIPsHealthyFirst` / `MarkBadIP` 进行 QUIC 候选 IP 轮换，不设 `KeepAlivePeriod`（配置 `MaxIdleTimeout: 30s`），并在关闭开关、切换 IP 模式或刷新 ECH 配置时主动关闭 H3 连接防 UDP 端口泄漏。

* **`win/tray.go` & `win/main.go` & `echproxy/portal.go`**：

  * 托盘菜单新增 **「ECH 备选 HTTP/3 (仅 ECH 通道, 实验)」**（`TrayCmdECHHTTP3`，默认不勾选，热切换无需重启）；命令行新增 `-ech-h3`（环境变量 `ECH_PROXY_ECH_H3`）；`/statusz` 暴露 `ech_h3_enabled`。

* **`go.mod` & `win/main_test.go`**：

  * 将已有间接依赖 `github.com/quic-go/quic-go v0.59.0` 提升为直接依赖；新增 `TestTrayECHHTTP3ToggleDefaultOff` 单元测试。

> **配套技术深度报告**：本次涉及的双代理拓扑、DNS 引导解耦、TLS/ECH 对抗边界、多路 HTTP/2 与 HTTP/3 备选、同类代理源码对比等完整知识点已沉淀至 [`docs/ech-proxy-technical-notes-2026-11.html`](../docs/ech-proxy-technical-notes-2026-11.html)。

## 6. CI 自动化验证补齐（v3.6.5）

- **单测自动覆盖**：`go test ./... -race`（`go.yml`）与 `go test ./...`（`ech-proxy.yml`）已自动执行全部 8 个新增单测（含新增的 `echproxy/ech/h3_test.go` 验证 `GetECHHTTP3()` 默认关闭与热切换行为）。
- **`.github/workflows/go.yml` 新增门禁与冒烟检查**：
  - 远端资产校验补充 `DefaultBypassURL`（`/bypass.txt"`）与 `certs/l.moonchan.xyz/bypass.txt` 禁入仓检查。
  - 新增 `Validate v3.6.5 invariants` 步骤：静态守护 `4545810.xyz` 经由 `ResolveDefaultSiteHost` 解析（不走 DoH）、`sni.go` 绝不引用 `doECHHTTP3`/`quic-go`/`http3`、以及 `go.mod` 中 `github.com/quic-go/quic-go` 为直接依赖。
  - 扩展 CLI 冒烟测试：校验 `help` 输出包含 `-bypass-url`、`-bypass-file`、`-no-local-bypass`、`-ech-h3`、`-fallback`；同时补齐 `win/main.go` 中 `pac` 子命令对 `bypass.txt` 与 `-fallback` 的支持，在 CI 中实测生成 PAC 并断言 `BYPASS_EXACT_HOSTS`、`BYPASS_SUFFIX_RULES`、测试域名与 `PROXY 127.0.0.1:7890` 均正确注入。
- **`.github/workflows/ech-proxy.yml` 同步门禁**：在打包前同步校验 `/bypass.txt"` 默认配置与 `sni.go` 零 HTTP/3 引用约束。
