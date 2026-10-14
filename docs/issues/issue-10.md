# Issue #10：反代控制平面接口（`/control/cookie`、`/_ech/cookie`）与 CONNECT 隧道的安全边界缺口

* **定位**：`CONNECT-boundaries.md`、`DESIGN-tunnel-limits-and-android.md`、`echproxy/router.go`
* **问题描述**：
  1. 控制接口 `/control/cookie` 与 `/_ech/cookie` 允许直接切换上游的公用/本地 Cookie 模式（甚至通过 URL 参数 `?_cookie_mode=seed|browser` 触发），且全局 `CORSMiddleware` 无条件反射 `Origin` 并设置 `Access-Control-Allow-Credentials: true`。任意网页可通过跨站请求静默切换用户本地代理的 Cookie 优先级模式。
  2. `exp/exp02-connect-tunnel` 分支的 CONNECT 隧道若未合入认证、SSRF 目标黑名单（拦截 `127.0.0.1`、内网段、`169.254.169.254`）以及 per-peer/global 并发连接数上限（`DESIGN-tunnel-limits-and-android.md`），在绑定 `0.0.0.0` 时会直接暴露为无限制开放代理。
* **修复方案**：
  1. 为 `/control/cookie` 等状态修改接口增加 CSRF 防护（校验 `Origin`/`Referer` 必须为 `l.moonchan.xyz` 门户页）及可选 Token 认证。
  2. 按 `DESIGN-tunnel-limits-and-android.md` 落实验证守卫顺序（认证 → 目标黑名单校验 → per-peer 128 / global 1024 限流 → 空闲超时 `deadlineConn` → dial）。
