# AGENTS.md — ech-proxy 仓库工作约定

本文件是给 AI 代理（以及协作者）的工作约定。**本地不跑构建与 CI，全部依靠 GitHub Actions。**

## 构建与 CI：只用 GitHub Actions

1. **禁止本地 `go build`**（任何 package、任何目标，含 `win/`、`echproxy/`、`android/` 相关）。本地编译结果与本仓库 CI 可能不一致（Go 版本、平台、构建标签、GoReleaser 配置），且会污染工作树与缓存。
2. **禁止本地执行 CI 脚本**（`.github/workflows/` 下的任何步骤、`scripts/` 下的构建/发布脚本的本地等价物）。本地跑 CI 步骤会绕过 workflow 的固定环境与步骤，结果不可复现。
3. **全部依靠 `gh` 触发 GitHub Actions**：
   - 推 `main` 触发 push 型 workflow（`ech-proxy.yml`、`ech-proxy-flutter-ffi.yml` 等）。
   - 需要手动触发时用 `gh workflow run <workflow> --ref main`（`workflow_dispatch`）。
   - 查看结果用 `gh run watch` / `gh run list`，**以 CI 绿为准**，不以本地编译通过为准。

> **除非用户明确指定需要**（口头/指令直接要求"本地 build"或"本地跑 CI"），否则一律按上述禁止执行。用户指定时以用户指令为准。

## 例外（明确允许）

- **用户明确指定需要时**：以用户指令为准（用户要求"本地 build"或"本地跑 CI"则照做），但完成后仍以 `gh action` 作为最终交付验证。
- `go vet`/`go test` 若用于**纯本地逻辑推理**（不改构建产物）可在注释中说明理由；但**结果不作为交付验证**，交付验证一律看 `gh action`。
- 只读命令（`go list`、`grep`、`git`）不在此限。

## 验证标准

- 改动交付 = 推 `main` → 对应 workflow 绿（`gh run list --branch main`）。
- 本地工作树干净（`git status` 无未提交/未跟踪构建产物）。
- 不改 `go.mod`/`go.sum` 除非 workflow 要求。

## 其他

- 本约定与 KB `AGENTS.md` 的"git 动作是你的活"一致：提交、推送、解冲突、开 PR 均由代理完成。
