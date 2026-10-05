# CONNECT 隧道 · 边界清单

分支 `exp/exp02-connect-tunnel`。**这份清单比代码更有价值**——代码只覆盖了能跑通的主路径，
下面这些是「跑不到 / 跑不好 / 故意不支持」的地方。

每条标注：**现状**是什么、**为什么**、**将来要支持时**该怎么处理。

---

## A. 故意不支持（架构决定的，不是没做）

### A1. 隧道内不做响应体处理

**现状**：`rewriteAndSendBody` / `stripBlockedURLs` / SW 注入 / Cookie 播种全部不生效。

**为什么**：CONNECT 之后字节是不透明的。要处理响应体就必须终结 TLS，而终结 TLS 意味着
浏览器看到一个它不信任的证书——这是**功能正确性问题，不是取舍**。

**影响面**：走隧道的站点拿不到 blocked_hosts 保护、拿不到 service worker、拿不到
`rewriteSetCookieDomains`。这两个路径是互斥的。

### A2. 隧道走明文 TCP，不走 ECH / SNI

**现状**：`dialConnectTarget` 是裸 `net.Dial`。

**为什么**：ECH 和 SNI 两个 dialer **自己终结 TLS**。在这里套上它们，客户端完成的是
「与代理内层 TLS」的握手，不是与源站的握手——直接坏掉。

**代价**：隧道出去的连接**没有 ECH，也没有 SNI 伪装**，且**不经过 Cloudflare**。
对「被墙但没有被 SNI 封锁」的站点，隧道救不了；它只解决「本地网络能连、但需要绕过
中间设备」的场景。

### A3. `ip_mode` 对隧道目标无效

**现状**：和 `mode: "direct"` 一样，`ip_mode` 不被读取。

**为什么**：`dialConnectTarget` 签名里没有 family 参数。这正是我在架构分析里点名的
「分支之间不对称」——**同一个坑，现在有了第三个实例**（原本是 sni 分支）。

**状态**：已知缺口，代码注释里写明了。修法在设计文档 L2（把 `Family` 放进 `Target`）。

### A4. HTTP/2 的 CONNECT 不支持

**现状**：`Hijack()` 不可用时返回 **505 HTTP Version Not Supported**。

**为什么**：`http.Hijacker` 只在 HTTP/1.1 下可用。HTTP/2 没有 hijack 概念。

**补法**：RFC 8441 Extended CONNECT，或直接用 HTTP/2 代理协议（RFC 9113 §8）。
本项目 **只协商 h2 用于上游**（`newTransport` 里强制 `NegotiatedProtocol != "h2"` 就报错），
但**客户端侧目前是 HTTP/1.1**，所以短期不是问题。

---

## B. 已处理但容易踩

### B1. 客户端在 CONNECT 后**不响应**（哑客户端）

**现状**：`relay` 等两个方向，先完成的返回并关闭双方。

**为什么**：如果等两个方向都完成，源站响应完关闭后，`client->upstream` 那个 copy 会
永远卡在 `Read` 上——**连接泄漏**。

**代价**：**半关闭语义不支持**。客户端发完请求就 `CloseWrite` 想复用连接，隧道会被关掉。
正确做法是双向都等到 EOF 才关，但那样又回到泄漏问题。

**判据**：`TestRelayClosesBothSidesWhenOneEndDies`（变异「relay 等两侧」会红）。

### B2. 客户端把 TLS ClientHello **和 CONNECT 同一段发出**（pipeline）

**现状**：hijack 后先把 `clientBuf` 里已缓冲的字节转发给上游，再开始 relay。

**为什么**：不转发就**静默吃掉 ClientHello 的开头**，客户端侧表现为莫名其妙的握手失败，
而没有任何线索指向代理。

**判据**：`TestConnectForwardsPipelinedBytes`。这个测试**第一版是错的**（读 11 字节但
payload 是 10 字节），`io.ReadFull` 一直阻塞到超时，看起来像实现 bug。

### B3. 目标拒绝 / 连不上

**现状**：上游拨号失败 → **502** + 关闭连接。

**注意**：此时连接**已经被 hijack**，gin 的 writer 失效，所以错误响应由
`writeConnectError` 手写并带 `Connection: close`。状态码语义与普通路径一致。

**判据**：`TestConnectUnreachableUpstreamReturns502`（变异「返回 200」会红）。

### B4. 隧道中途断开

**现状**：`isExpectedConnError` 过滤 `connection reset by peer` / `broken pipe` /
`use of closed network connection` / `unexpected EOF` / 超时，**不刷错误日志**。

**为什么**：隧道关闭时这些是常态，刷屏会把真错误埋掉。

**残留问题**：这个判断是**字符串匹配**。`net.ErrClosed` 有 `errors.Is`，但
`"connection reset by peer"` 这类来自 syscall 的错误只有字符串可靠。
**判据**：`TestIsExpectedConnError`（含一条负向断言：TLS 证书错误**不能**被吞掉）。

### B5. CONNECT 目标格式非法

**现状**：`parseConnectTarget` 拒绝缺端口、空 host、端口越界、非数字端口 → **400**。
RequestURI 里的 authority **优先于** Host 头（兼容把 authority 写请求行的客户端）。

**判据**：`TestParseConnectTargetRejectsMalformed` / `AcceptsValid` / `PrefersRequestURI`。
变异「去掉端口范围检查」会红。

### B6. CONNECT 被禁用时

**现状**：**405**，报文里写明怎么开（`-allow-connect`）。

**为什么不让它落到反向代理**：那会把一个 CONNECT 请求**悄悄转发到某个配置的上游**，
正是这类改动要消灭的静默行为。

---

## C. 明确没做（安全相关）

### C1. **没有**认证

开启 `-allow-connect` 后，**任何能连到监听地址的进程都能用它访问任意目标**。
项目默认绑 `127.0.0.1`，Android 端也是 `127.0.0.1:8443`，所以暴露面是本机。

**如果改成绑 `0.0.0.0`，立刻就是一个开放代理。** 这是启用前必须知道的代价。

### C2. **没有**目标黑名单 / 端口限制

`blocked_hosts` 只作用于反向代理路径的响应体，**对隧道目标无效**。
不能 CONNECT 到 `127.0.0.1`、内网地址、云元数据地址（`169.254.169.254`）——
**目前没有任何拦截**。

这是 SSRF 面。绑本机时风险有限，绑公网时是严重问题。

### C3. **没有**审计日志以外的留痕

只有 `debugLogf`（需 `-v`）。开隧道后应该记谁连了谁，目前没有。

### C4. **没有**连接数 / 带宽上限

一个客户端可以开无数条长连接。

---

## D. 待验证（本环境无法测）

| 项 | 为什么测不了 |
|---|---|
| 真实浏览器的 PAC / `curl -x` 全量兼容性 | 本机浏览器未配置为走该代理 |
| WebSocket over CONNECT | 未测；理论上字节透传应当可用 |
| HTTP/2 Extended CONNECT（RFC 8441） | 客户端侧目前是 HTTP/1.1 |
| 半关闭（`CloseWrite` 后复用） | 见 B1，明确不支持 |
| 大文件 / 长连接稳定性 | 未做压力测试 |
| Android 端 | 该分支只改 `win/main.go`，**Android 未接 `-allow-connect`**（见下） |

**Android 缺口**：`android/main.go` 构造 `ServerOptions` 时没设 `AllowConnect`，
所以 Android 上永远关闭。这是刻意的——但**必须在文档里写明**，否则会有人以为两端一致。

---

## E. 下一步的判据

要让下一轮有据可依，按这个顺序验：

1. `curl -x` 挂真实站点（已验证：`example.com` / `www.iana.org` / `httpbin.org` 均 200）
2. 浏览器设代理后人工过一遍（未做）
3. 决定要不要加目标黑名单（C2 是 SSRF 面，建议优先）
4. 决定 `ip_mode` 是否要覆盖隧道目标（A3，需先做设计文档 L2）
