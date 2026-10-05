# 设计：连接数上限 与 Android 接入（本轮只出设计）

`exp02` 的 CONNECT 边界清单里有两条安全缺口。本 PR 只实现认证与目标校验，
这两条**只写设计**，代码留给后续。

---

## 一、连接数上限

### 缺口

`-allow-connect` 打开后没有任何并发限制。一个客户端可以开任意多条长连接：
每个 CONNECT 占用一条到上游的 TCP 连接 + 一条到客户端的连接（hijack 后不再受
`http.Server` 的连接管理约束），再加两条 `io.Copy` goroutine。1000 条隧道就是
约 4000 个内核对象和 2000 个 goroutine，而 `go test` 里没有任何东西会拦住它。

**为什么这比看起来严重**：守卫在 dial **之前**（见 PR 描述），所以攻击面是
「能否开隧道」，而不是「能连到哪」。限流因此是第一道 DoS 防线，不是锦上添花。

### 设计

**三层，从便宜到贵**：

**第一层 · 每 peer 隧道数上限**（主要防线）

```
perPeerMaxTunnels = 128   // 默认，可 -tunnel-max-per-peer 覆盖
```

计数点在 `handleConnect` 拿到 200 之后、`relay` 之前 `Add(1)`，
在 relay 返回后 `Done()` 减一。用 `sync.Map[string]*atomic.Int32` 按
`c.ClientIP()` 记账，而不是全局计数——全局计数会让一个客户端耗尽所有人的额度。

**必须注意**：`net/http` 的 `ConnState` 看不到 hijack 后的连接，gRPC 的
`stats.Handler` 也看不到，所以**不能靠 server 层统计**，只能在 handler 里自己数。
这是本设计唯一的硬约束。

**第二层 · 全局上限**

```
globalMaxTunnels = 1024
```

防的是「很多个 peer 各开一点」。peer 维度挡不住分布式来源，全局维度挡不住
单机超量，两者都要。

**第三层 · 空闲超时**

```
idleTimeout = 10 * time.Minute   // 双向都无流量则回收
```

用 `SetDeadline` 实现，但**要定时刷新**：每次成功 `io.Copy` 之后把 deadline 往后推。
这里有个陷阱——`io.Copy` 本身不暴露「发生了多少字节」的事件，所以要么换成
`io.CopyBuffer` 自己写循环，要么用 `Conn` 的包装器在 `Read` 返回时刷新。
推荐后者（包一层 `deadlineConn`，`Read` 成功后 `SetDeadline(now+idle)`），
这样改动最小。

**第四层 · 握手前速率限制**（已在 auth.go 里）

失败认证 10 次 / 5 分钟按 peer 限流，阻止 token 爆破。成功即 `Reset`。

### 与守卫的交互

顺序必须是：**认证 → 目标校验 → 限流 → dial**。

限流放在校验之后，是为了让被 403 的目标**不消耗额度**——否则一次针对
`169.254.169.254` 的扫描会把自己的隧道额度烧光，起到自我 DoS 的效果。

### 判据

| 测试 | 证伪方式 |
|---|---|
| 第 129 条隧道返回 429，且 `dialConnectTarget` 未被调用 | 把上限改成 9999 → 测试红 |
| 额度在 relay 结束后归还（关 128 条后再开应成功） | 去掉 `Done()` → 测试红 |
| A peer 用满不影响 B peer | 把 per-peer 改成全局 → 测试红 |
| 超限返回 429 而非 403（区分「太多」与「不允许」） | 两者互换 → 测试红 |

**注意 relay 的现有实现**：`relay` 第一个方向结束就返回并关闭双方。
`Done()` 必须挂在 `relay` 调用之后（`defer`），否则半关闭会提前释放额度。

---

## 二、Android 接入

### 缺口

`android/main.go` 构造 `ServerOptions` 时**没有设 `AllowConnect`**，所以 Android 上
隧道永远关闭。这本身是安全的默认，但造成了两处不一致：

1. 桌面端与 Android 端能力不同，且**没有任何文档或提示说明这一点**
2. 本 PR 加的认证与守卫参数在 Android 上无法配置（`IP_MODE` 走 env，
   新参数没有对应物）

### 设计

**目标**：让 Android 能在**不开隧道**的前提下获得同样的安全收益——
即认证与守卫对现有反向代理路径同样生效。

**第一步（建议先做）· 不开放隧道，只让 Android 的配置面与桌面端对齐**

`android/main.go` 加三个 env（与桌面端同名）：

```
ECH_PROXY_TOKEN        -> AuthConfig.Token
ECH_PROXY_USER         -> AuthConfig.Username
ECH_PROXY_PASS         -> AuthConfig.Password
```

反代路径目前不走 `handleConnect`，所以这三个在 Android 上**暂时无效**——
除非同时给反代路径加认证。

**第二步 · 给反代路径加认证（这一步才是真正的收益）**

现在认证只挂在 CONNECT 上。反代路径虽然只允许配置内的 upstream，
但**`blocked_hosts` 不阻止访问配置外的目标**，且任何本机进程都能用它。

加法：在 `ProxyHandler` 入口、解析出 `uc` 之后，加同一套 `pol.auth.Check`。
需要注意 **`/healthz` 与门户页应豁免**（否则浏览器打不开配置界面），
而 `/control/cookie` **不应豁免**（它能改 Cookie 模式）。

**第三步 · Android 开放隧道（可选，风险最高）**

如果确实需要，Android 侧需要额外考虑三件桌面端不存在的事：

1. **前台服务**：隧道是长连接，现有 WakeLock + 前台服务逻辑是为「代理常驻」设计的，
   应可复用，但需确认超时策略不会杀掉活跃隧道
2. **电池优化白名单**：同上
3. **JNI 侧凭据传递**：`StartProxy` 的签名需要加 token 参数，
   而 Dart 侧 `lookupFunction` 按名字取符号、**签名变更不会编译报错**，
   只会真机 `ArgumentError`。必须走 PR #6 建立的
   `TestFlutterEntryExportsAllFFISymbols` 那类契约测试

**明确建议**：第三步**不要做**。Android 的威胁模型是移动设备 + 移动网络，
开隧道换来的能力（任意站点）不值这个风险面。除非用户明确要求。

### 判据（第二步）

| 测试 | 证伪方式 |
|---|---|
| 反代请求无凭据返回 401 | 去掉 auth 检查 → 红 |
| `/healthz` 无凭据返回 200（豁免） | 去掉豁免 → 红 |
| `/control/cookie` 无凭据返回 401（不豁免） | 加豁免 → 红 |
| 带正确 token 的反代请求正常 | — |

---

## 三、为什么这两条不与认证/校验合并

它们的风险性质不同：

- **认证 / 目标校验**是**正确性问题**——不修就是「谁能用、连到哪」不受控
- **限流 / Android** 是**可用性与形态问题**——不做只会导致资源耗尽或能力不一致

先做前者，是因为前者有明确的攻击路径和明确的失败判据；
后者需要压测数据支撑上限取值，猜一个数字比不写更危险。
