# Issue #8：`upstream.json` 的 6 类“静默失败”（Silent Failures S1–S6）未在主干拦截

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
