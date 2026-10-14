# Issue #11：CI 工作流忽略 `**.json` 导致线上 `upstream.json` 改动处于无测试盲区

* **定位**：`.github/workflows/go.yml`、`certs/l.moonchan.xyz/upstream.json`、`NOTES-experiments.md`
* **问题描述**：
  由于运行中的客户端会在启动时直接从 GitHub `main` 分支拉取 `certs/l.moonchan.xyz/upstream.json`，`main` 分支上的 JSON 改动是**即时全网生效的生产变更**。但 `go.yml` 配置了 `paths-ignore: ['**.json']`，导致单独修改 `upstream.json` 的提交完全不触发 CI，一旦出现语法错误、重复键或非法 `ip_mode`，会导致全量客户端拉取配置失败。
* **修复方案**：
  在 `.github/workflows/go.yml` 中移除对 `certs/l.moonchan.xyz/upstream.json` 的忽略（或新增轻量级 `validate-config` CI Job），在每次 PR / push 时自动运行 `go run ./win -check-config -config certs/l.moonchan.xyz/upstream.json`。
