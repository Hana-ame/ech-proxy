# 架构分析：把 ech-proxy 做成通用 http/https 正向代理

分支 `design/general-proxy-architecture`（**纯文档，无代码改动**）。
基线 `origin/main` @ `5f3784a`，代码规模 6065 行（含 1755 行测试）。

本文件是**设计提案**，等 review 通过后再按层动手。

---

## 一、现状：哪些是「为写死的域名写死的」

### 1.1 请求路径全貌

```
客户端 → gin (router.go)
  ├─ /healthz, /control/cookie, /_ech/cookie     控制面，固定路径
  ├─ GET "/"  → serveIndex（门户页）
  │            host == "l.moonchan.xyz"          ← 硬编码
  │            其它 host 查 upstream 表
  └─ NoRoute → ProxyHandler (proxy.go)
                ↓
                host := strip(c.Request.Host)
                uc, ok := cfg.Upstreams[host]      ← 精确匹配
                if !ok { uc, ok = matchWildcard }  ← 通配匹配
                if !ok { 502 "no upstream for host" }   ★★ 通用化的拦路虎
                ↓
                urlStr := "https://" + uc.Host + reqURI   ← 目标写死在 uc.Host
                outReq.Host = uc.Host
                ↓
                roundTripFn(outReq, uc.Mode, uc.IPMode)   ← 三分支分发
```

### 1.2 「写死」的准确清单

| 位置 | 写死了什么 | 通用化影响 |
|---|---|---|
| `router.go:21` | `const indexHost = "l.moonchan.xyz"` | 门户页专属 host，需保留但要与代理解耦 |
| `proxy.go:240` | `cfg.Upstreams[host]` 查不到就 502 | **核心改造点**：要有 fallback 规则 |
| `proxy.go:288` | `urlStr := "https://" + uc.Host + reqURI` | 端口写死 443、协议写死 https |
| `proxy.go:293` | `outReq.Host = uc.Host` | 目标 host 来自配置 |
| `router.go:126` | `badge := entry[:1]` | 门户渲染细节，通用化后条目语义变了 |

### 1.3 已经通用的部分（可直接复用）

- **ECH 传输层** `ech/client.go:392 newTransport`：`DialTLSContext` 里对**任意 host** 都成立
  - `ServerName: host`（真目标做 inner SNI）
  - `EncryptedClientHelloConfigList: echConfig`（同一份 ECH 密钥用于所有站）
  - `dialTCP(ctx, shellDomain, "443", ipMode, ...)` 外壳固定为 `cloudflare-ech.com`
  - **换 host 只需换 `addr`**，无需改逻辑 → 这层已经通用
- **SNI 传输层** `sni.go:172 newSNIFrontTransport(ip)`：按 IP 缓存 h2 transport，对任意 host 成立
- **netdial** `netdial/netdial.go`：公共 DNS + 自带 CA 池，已处理 Termux 无 `resolv.conf` 的场景
- **`ip_mode` 机制本身**：v4/v6/auto 已实现在 egress 层

### 1.4 一句话结论

**传输层（ECH / SNI）已经是通用的，卡点全在「目标从哪来」和「怎么决定走哪条路」。**
所以通用化的主要工作量在**路由与出口策略**，不在 TLS。

---

## 二、三个必须处理的层：现状与雷区

### 2.1 DNS 解析

**现状：三条路径，三套解析，互不共享**

| 分支 | 解析方式 | 代码位置 |
|---|---|---|
| ech | `dialTCP(shellDomain, ...)` —— 解析的是**外壳域**，不是目标域 | `ech/client.go:410` |
| sni | `resolveHostIPs` → DoH，查目标域全部 A/AAAA，**逐个试** | `sni.go:39` + `sni.go:218` |
| direct | `netdial.Client` → netdial 的公共 DNS 解析器 | `proxy.go:47` |

**雷区**：
- ech 分支**不解析目标域**，直接连外壳 IP。这意味着**本地 DNS 完全不参与 ech 路径**——出口端（Cloudflare）做真实解析。这本身符合「远程解析」语义。
- sni 分支**解析目标域**，且**逐个 IP 试**（`sni.go:218` 的循环），天然多族。
- direct 分支走 netdial 解析器。
- 三条路径的 DNS 结果**互不缓存共享**：`ipCache`（sni 用）和 ech 的 `dialTCP` 完全是两套。

**结论**：现状没有「本地 DNS 污染出口策略」的问题，因为 ech 路径压根不在本地解析目标域。但**通用化后如果允许 direct 模式做任意站点，本地/公共 DNS 就会真的参与**，那时才需要引入 SOCKS5H 式的「交出口端解析」选项。

### 2.2 TLS 与 SNI

**现状：三条路径的 ClientHello 完全不同**

| 分支 | outer SNI | inner SNI | 证书校验 | ALPN |
|---|---|---|---|---|
| ech | `cloudflare-ech.com`（外壳） | 真目标（ECH 加密） | Cloudflare 证书，正常校验 | 强制 h2 |
| sni | `cloudflare-ech.com`（**假的**，`fakeSNI`） | — | `InsecureSkipVerify: true` | 强制 h2 |
| direct | 真目标 | — | 系统 CA 池 | 正常协商 |

**两个必须注意的点**：

1. **`fakeSNI = "cloudflare-ech.com"` 被 sni 和 ech 共用**（`sni.go:19` + `ech/client.go:241`）。通用化后如果换外壳域，这两处必须同步——**这正是「分支之间不对称」的典型雷区**。
2. **没有 CONNECT 支持**。我全仓库搜过 `CONNECT`/`Hijack`/`Upgrade`，只命中 `cors.go:21` 的一个 header 名。**要做真正的正向代理，CONNECT 隧道是必须新写的**，这是最大的新增工作量。

**关于证书**：ech 与 sni 都不需要目标站证书（前者由 Cloudflare 终止，后者 `InsecureSkipVerify`）。只有 direct 需要。所以 CONNECT 隧道内层要透传 ClientHello 的话，**不能让代理自己终结 TLS**，否则浏览器会报证书错。

### 2.3 路由与出口策略

**现状：路由 = map 精确查 + 通配查，两级，写死在配置里**

```go
uc, ok := cfg.Upstreams[host]
if !ok { uc, ok = matchWildcard(cfg, host) }
if !ok { 502 }
```

**必须改的东西**：

1. **查不到要能 fallback**，否则「任意站点」无从谈起。
2. **热更新**：现在 `LoadConfig` 只在 `NewServer` 调一次（`server.go:130`），`Server.Config` 是普通字段，**没有任何 reload 路径**。ECH 密钥有 5 分钟刷新循环（`client.go:559 refreshLoop`），但配置没有。
3. **规则要能匹配端口和协议**，现在只匹配 host。

---

## 三、分层设计

### 层 1 · DNS（`Resolver`）

**职责**：给「一个 host + 一个地址族偏好」返回一组候选地址。

**接口**：
```go
type Resolver interface {
    // 返回按 family 过滤后的候选地址；family="" 表示不限
    Lookup(ctx context.Context, host string, family string) ([]netip.Addr, error)
}
```

**实现**：
- `dohResolver` —— 复用 `netdial` 的公共 DNS（现状 sni/direct 已在用）
- `passthroughResolver` —— 返回域名本身，交给 egress 连（远程解析语义，类 SOCKS5H）

**关键设计点**：`family` 就是 `ip_mode` 的值。把它做进接口签名，而不是让每个调用点自己处理——**这就从结构上消灭了「sni 分支不收 ipMode」那类不对称**。

**消除的重复**：现状 ech/sni/direct 三套解析，收敛成这一个接口。

### 层 2 · TLS（`Dialer`）

**职责**：建立一条到目标的 TLS 连接，负责 SNI / ECH / ALPN / 证书策略。

**接口**：
```go
type Dialer interface {
    Dial(ctx context.Context, target Target) (net.Conn, error)
}

type Target struct {
    Host   string      // 真目标，做 inner SNI / 证书校验
    Port   int
    Family string      // v4 / v6 / auto —— 所有分支都必须处理
    Mode   string      // ech / sni / direct
}
```

**三个实现**（都从现状搬过来，行为不变）：
- `echDialer` ← `ech/client.go:392 newTransport`
- `sniDialer` ← `sni.go:172 newSNIFrontTransport`
- `directDialer` ← `proxy.go:47 netdial.Client`

**关键设计点**：`Target.Family` 在**接口签名里**，`sniDialer` 想忽略它都不行——要么用，要么**显式声明忽略**并在验证期报出来。这直接治了 S3。

### 层 3 · 路由（`Router`）

**职责**：给一个请求决定「走哪个出口策略」。

**接口**：
```go
type Decision struct {
    Mode   string   // ech / sni / direct
    Family string   // v4 / v6 / auto
    RuleID string   // 命中的规则 id，用于日志与排障
}

type Router interface {
    Route(host string, port int, scheme string) Decision
}
```

**实现**：
- `explicitRouter` —— 保留现有 `UpstreamMap` 精确+通配查，行为完全不变
- `ruleRouter` —— 新增，支持域名后缀 / 端口 / 协议匹配，带优先级

**规则形态**（示意）：
```json
{
  "rules": [
    { "id": "cf-default", "domain_suffix": [], "mode": "ech", "ip_mode": "v4" },
    { "id": "non-cf",     "not_cloudflare": true, "mode": "sni" }
  ],
  "default": { "mode": "ech" }
}
```

**关键设计点**：`Decision` 里带 `RuleID`。现在 502 只能告诉你「no upstream for host: X」，**不知道是没人配还是配错了**。带上规则 id 后，半夜排障能直接查。

### 层 4 · 出口（`Egress`）

**职责**：执行一次请求。

现状 `proxyRoundTrip(req, mode, ipMode)` 三分支。通用化后：
```go
func Egress(decision Decision, req *http.Request) (*http.Response, error)
```

**这一层几乎不用改**——三个实现都已经在层 2 里了。这层只是编排。

---

## 四、热更新设计

现状 `Server.Config` 是普通字段，`NewServer` 加载一次就没了。通用化后规则会频繁变，必须能热更新。

**方案**：`atomic.Pointer[Config]` + 后台定时器。
- 每 N 秒（建议 60s）重新 `LoadConfig`
- 解析成功**且**校验无 error 才替换指针；否则保留旧配置并打日志
- 参照已有的 `ech/client.go:559 refreshLoop` 写法，保持风格一致

**为什么不用文件监听**：现有配置是远程 URL（CDN 缓存 300 秒），文件监听对远程源无意义。轮询与 `refreshLoop` 一致。

**风险**：这是**行为变更**（配置会热更新）。当前 `upstream.json` 的改法是「push 即部署」，热更新会让这个隐式语义变得更快更明显。要谨慎。

---

## 五、静默失败面的放大与对策

**通用化后危险的地方**（规则写错 = 默默走错出口）：

| 风险 | 现状 | 通用化后 | 对策 |
|---|---|---|---|
| 规则没命中 | 502，**会报错** | fallback 到 default，**不报错** | 命中 default 时打 debug 日志说明走了兜底 |
| 规则 `ip_mode` 值错 | 校验器已能抓（exp01） | 同 | 复用 exp01 的 `Validate` |
| `mode` 拼错 | 落到 default 分支 | 同 | 同上 |
| 分支不对称 | sni 不收 ipMode | **更多分支会不对称** | 把 `Family` 放进 `Target` 结构体，编译期强制 |
| 端口/协议规则写错 | 不存在 | 静默不命中 | 校验器 + 启动时打印规则表摘要 |

**核心对策**：把 exp01 的 `Validate` 扩展到新规则格式。**规则写错必须报错，这是硬要求。**

---

## 六、分歧：我的假设（需要 review 确认）

1. **不删现有 `upstream.json` 模型**——`explicitRouter` 原样保留，新模型并行。通用化是加法不是替换，这样 PR #2 的 14 条 pin 配置不受影响。
2. **CONNECT 隧道需要新写**，且**不能让代理终结内层 TLS**（浏览器会报证书错）。这意味着 CONNECT 路径只能走「字节透传」，无法做响应体重写。这是功能上的实质取舍。
3. **门户页（`l.moonchan.xyz`）保留**为特例，但与代理解耦。
4. **热更新默认关闭**，用 flag 开启——避免改变现有「改配置需重启」的语义。

---

## 七、分阶段实施计划（每阶段独立分支 + PR）

| 阶段 | 内容 | 可验证判据 | 风险 |
|---|---|---|---|
| **L1** | 抽出 `Resolver` 接口，把 sni/direct 两套解析收敛 | 现有测试全绿 + 新增接口一致性测试 | 低 |
| **L2** | 抽出 `Target{Family}` 结构体，消除分支不对称 | 新增测试：三个 Dialer 都必须消费 Family | 低 |
| **L3** | 抽出 `Router` 接口，`explicitRouter` 原样搬迁 | 现有路由测试全绿（行为不变） | 低 |
| **L4** | 加 `ruleRouter` + 规则校验（复用 exp01 的 Validate） | 变异测试：规则写错必须被抓 | 中 |
| **L5** | 加 fallback 规则，让未配置站点可代理 | 未配置域名能代理、且日志说明走了 fallback | 中 |
| **L6** | 实现 CONNECT 隧道 | 本地 httptest + 真实 TLS 站点双判据 | **高** |

**L1–L3 是纯重构，行为不变，可用现有测试做回归护栏。** L4 起开始有行为变更。

---

## 八、待 review 的问题

1. CONNECT 隧道不做响应体重写，是否可接受？（浏览器直连 TLS 字节，代理只做字节透传 + 出口选择）
2. 热更新默认开还是默认关？
3. `ruleRouter` 的规则优先级：显式 upstream 优先于规则，还是规则优先？
