# 实验记录 · ech-proxy 可维护性改进

用户 2026-10-04 授权：「请尝试所有的 route。建立好 git 管理，如果不行我会回退。」

**回滚约定**：`main` 保持干净可回退，所有实验只落在 `exp/*` 分支上，不 merge main。
用户自行决定合哪条或全部丢弃。

**基线**：`origin/main` @ `5f3784a`（"feat(upstream): add x.l.moonchan.xyz entry"）

---

## 基线读数（任何实验都要先有这个数，否则没有对比）

在 `origin/main` @ `5f3784a` 上实跑 CI 的两条命令：

| 命令 | 结果 |
|---|---|
| `go test ./... -race` | ok，`echproxy` 包 4.958s |
| `go vet ./...` | clean |

这是后续所有实验的对照组。

---

## 已被实战暴露的静默失败面（问题来源，不是凭空想的）

下面每一条都是 2026-10-04 那次改 `upstream.json` 真正被绊到、或查证时撞见的：

| # | 静默失败 | 表现 | 证据 |
|---|---|---|---|
| S1 | 顶层写 `ip_mode` | 被 `json.Unmarshal` 丢弃，出口族仍由 OS 决定 | `Config` 结构体无该字段 |
| S2 | `ip_mode: "V4"` | 静默退化成 auto，不报错 | `ech/client.go:272-287` switch 只认小写 |
| S3 | `ip_mode` 写在 direct/sni 条目 | 无效但看不出无效 | `proxy.go:44-54` 只有 default 分支传 ipMode |
| S4 | `ip_mode: "v4"` 但目标域无 A 记录 | 硬报错 `no v4 address for <host>`，不回退 | `ech/client.go:312` |
| S5 | 键名拼错（如 `ipmode`） | 静默丢弃 | 同 S1 |
| S6 | `cookie_priority` 拼错值 | 落到默认分支 | `cookie.go:597,605` |

共性：**这些都是「写了但没生效」，而运行时不告诉你**。这正是要治的病。

---

## 路线清单

按「收益 / 风险 / 工作量」排序。每条独立分支，可单独合。

| 分支 | 路线 | 收益 | 风险 | 工作量 | 状态 |
|---|---|---|---|---|---|
| `exp/exp01-config-validate` | 配置校验：把 S1/S2/S3/S5/S6 变成主动报错 | 高（直接治本次踩的坑） | 低（只读不改行为） | 中 | 进行中 |
| `exp/exp02-error-context` | 报错带上下文：哪条配置、为什么无效 | 中高（半夜排障靠它） | 低 | 中 | 未开始 |
| `exp/exp03-mutation-tested-assertions` | 把变异测试推广到现有断言，找方向写反的 | 中 | 低 | 中高 | 未开始 |
| `exp/exp04-dedup-address-resolution` | 收拢三处地址解析（ech/sni/direct 各一套） | 中 | 中（碰核心链路） | 高 | 未开始 |

### 待评估的架构路线（用户说「试所有 route」，这几条我还没验证可行性）

| 分支 | 路线 | 我的初步判断 |
|---|---|---|
| `exp/arch01-strict-config-mode` | 加 `-strict-config`，有问题就拒绝启动 | 风险低，但会打断现有宽松行为，需默认关 |
| `exp/arch02-config-schema` | 出一份 JSON Schema 文件，CI 校验 | 收益明确，但引入新依赖或自写校验器 |
| `exp/arch03-validate-endpoint` | 运行中暴露 `/config/validate` 端点，portal 可见 | 需鉴权考虑，本机服务风险低 |
| `exp/arch04-unify-egress` | 把 ip_mode 从 ech 层提升到统一 egress 抽象，direct/sni 也支持 | 这才是根治 S3 的做法，但改动面最大 |

**说明**：`arch04` 是唯一能真正修掉 S3（direct/sni 不支持钉族）的路线，但它要动三条传输路径，
属于行为变更而非纯校验。列在这里等前面几条跑通后评估。

---

## 实验日志

（按分支追加，每条记录：试了什么 / 判据 / 真实读数 / 结论）

### exp01 · config 校验（`exp/exp01-config-validate`）

**试了什么**：把 S1/S2/S3/S5/S6 这五个「写了但没生效」的静默失败面变成主动报出的 issue，
并给 CLI 加 `-check-config` 做独立校验入口。

**判据**：每条新测试都必须能被证伪 —— 逐个故意改坏 validator，确认对应测试会红。

**真实读数**：

| 变异 | 结果 |
|---|---|
| `Validate` 直接 return nil | 11 个测试红 |
| `containsFold` 改成大小写不敏感 | `TestValidateFlagsInvalidIPMode` 红 |
| `suggestField` 永不建议 | **存活 → 补测试后杀掉** |
| 空 host 从 error 降级为 warning | **存活 → 补测试后杀掉** |
| `HasErrors` 恒返回 false | `TestValidateFlagsEmptyHostBlocksCheckConfig` 红 |
| `FormatIssues` 不再把 error 排前面 | `TestFormatIssuesSortsErrorsFirst` 红 |
| 重复 host 检测删掉 | `TestValidateFlagsDuplicateHost` 红 |
| `Validate` 篡改配置（清 ip_mode） | **存活 → 换 fixture 后杀掉** |

两个「存活」是真发现，不是噪声：
1. hint 断言和 issue 存在性断言挤在一个测试里 → 拆成独立用例，另加「不相关词不得乱建议」的负向用例
2. 不变性测试拿**线上配置**做基准，而线上配置根本没有 `ip_mode`，所以「清空 ip_mode」这个变异改不动它 → 改用真正填充了这些字段的 fixture

另有一处测试自身写错被测试抓住：`upstream_suffix` 是 wildcard 作用域的键，不在 entry 键表里。

**命令级验证**：

```
go test ./... -race   →  ok  echproxy 9.717s
go vet ./...          →  clean
-check-config 线上配置   →  Entries: 18 / OK: no issues found / exit 0
-check-config 构造坏配置 →  4 error(s), 2 warning(s) / exit 1（六个静默失败面全部命中）
-check-config 不存在的文件 →  exit 2
```

**结论**：路线成立，收益高、风险低（纯只读校验，不改任何运行时行为）。保留，建议优先合。
唯一遗留的判断题：`-check-config` 目前不进 CI，因为 `go.yml` 的 `paths-ignore` 排除了 `**.json`
而配置校验只需要 JSON 改动。要在 CI 里跑需要单独加一个 job，那是 exp/arch02 的范围。
