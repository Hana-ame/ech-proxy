# Issue #4：仓库根目录残留旧版编译产物 `./ech-proxy`（2026-09-16 版本）导致严重行为错配

* **定位**：仓库根目录 `/ech-proxy` 二进制文件、`.gitignore`（第 2 行 `/ech-proxy`）
* **问题描述**：
  对当前工作区中的 `./ech-proxy` 可执行文件进行符号表与 DWARF 调试信息检查发现：
  * 其内嵌构建信息为 `vcs.revision=36fb9952d2c6e21424f36055f81be714067e6b5e`（构建时间 `2026-09-16T09:56:45Z`，`vcs.modified=true`）。
  * 该二进制仅支持 `-addr`、`-config`、`-http`、`-v` 四个旧参数，**完全不包含 `-local`、`.443.exe` 自动检测、本地 CA 签发 (`localca`)、按上游 `ip_mode` 隔离连接池、以及 `utls` ECH 握手（该二进制中 `ech/client.go` 仍调用标准库 `crypto/tls.Client`）**。
  * 由于 `.gitignore` 忽略了 `/ech-proxy`，`git pull` 或切换分支后该旧二进制一直静默留在根目录。一旦在测试时直接执行了 `./ech-proxy -addr 127.0.0.1:443`，它会使用 `*.l.moonchan.xyz` 证书响应 `pixiv.net` / `i.pximg.net`，导致所有 443 请求在 TLS 握手阶段直接报错。
* **修复方案**：
  立即删除或重新编译根目录下的 `./ech-proxy`（`go build -o ech-proxy ./win/`），并在启动 banner 中打印编译进来的 `vcs.revision` 与 `vcs.time`，防止运行过期二进制而不自知。
