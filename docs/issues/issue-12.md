# Issue #12：Android 端与桌面端能力边界及环境变量未对齐

* **定位**：`android/main.go`、`CONNECT-boundaries.md`、`DESIGN-tunnel-limits-and-android.md`
* **问题描述**：
  1. `android/main.go` 仅读取了 `IP_MODE` 与 `LOCALIP`，未对齐桌面端新增的鉴权环境变量（`ECH_PROXY_TOKEN` / `ECH_PROXY_USER` / `ECH_PROXY_PASS`）。
  2. Android 端是否支持本地 `pximg.net` 规则及不开 CONNECT 隧道的设计边界未在 `README.md` 中说明。
* **修复方案**：
  按 `DESIGN-tunnel-limits-and-android.md` 第一步与第二步对齐 `android/main.go` 的配置项读取，并在 `README.md` 中补充桌面端与 Android 端的功能对照表。
