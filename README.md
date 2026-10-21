# ech-proxy

支持 **Windows 7 ~ 11 (32位 `386` / 64位 `amd64` / `arm64`) PAC 方式运行的本地 HTTP/HTTPS 代理（Mainstream）**，提供系统托盘控制、PAC 原子替换与旧值 `pop` 恢复、本地 CA 一键安装与卸载、自动检查并下载 GitHub Releases 更新（退出后再次打开自动替换）、双 DoH 冗余解析、三种上游 GFW 绕过隧道、服务端回传证书核对与强行访问放行。

## 一、 三种运行方案与严格解耦边界

1. **PAC 方案（默认主流 Mainstream，`ech-proxy.exe`）**：
   - 启动后默认将系统代理原子替换为本地 PAC 脚本（`http://127.0.0.1:8443/proxy.pac?t=<ts>`），并将旧系统代理状态压栈（退出或 `Pop` 时自动 `pop` 恢复旧值）。
   - 严格仅依据远程白名单 `https://4545810.xyz/pac.txt`（一行一个 domain，支持原子替换 `SwapWhitelist` 与旧值 `PopWhitelist`）生成 PAC 规则，**与 `upstream.json` 及 `certs/` 路径完全解耦**。
   - 本地自签 CA 与动态签发的域名叶子证书统一存放在 `<dataDir>/ca/`（`ca/ca.pem`、`ca/leaves/`），绝不触碰 `certs/` 目录。
2. **443 方案（仅当文件名匹配 `.*.443.exe` 时开启）**：
   - **只与 `listen 443` 有关**：仅在可执行文件名匹配 `.*.443.exe` 时开启，严格仅监听 `443` 端口（不回退到 `8443`），其余所有功能（PAC、8443 门户、系统代理、托盘、自动更新、CONNECT 隧道）一律不运行。
   - 当文件名不匹配 `.*.443.exe` 时，严禁监听 443 端口且 443 方案绝不运行。
3. **8443 方案（真实公网证书下发的代理，`upstream.json` + `certs/l.moonchan.xyz/`）**：
   - `upstream.json` 与 `certs/` 路径（`certs/l.moonchan.xyz/fullchain.cer`、`privkey.pem`、`upstream.json`、`pixiv_cookie.txt`）**完全只与 8443 方案相关**。
   - 在当前主流版本中，8443 方案单纯在后台协程中**静默非阻塞运行**（仅为了兼容性保留），即使拉取或解析报错也完全静默忽略，绝不影响其他功能，且绝不阻塞主线代码。

## 二、 命令行 Flag 一览

| Flag / 子命令 | 说明 |
| :--- | :--- |
| `-4` | 强制 v4 出口（IPv4 only，默认开启） |
| `-6` | 强制 v6 出口（IPv6 only） |
| `-dual` | 双端出口（IPv4 + IPv6 双栈自动优选） |
| `-all` | 开启全局模式（无视 `pac.txt` 白名单，所有网站均通过 `ech-proxy` 代理；仅命令行 `-all` 可开启，不在托盘中显示） |
| `-whitelist-url` | 自定义 `pac.txt` 地址（默认 `https://4545810.xyz/pac.txt`） |
| `ca install` / `-ca-install` | 一键安装本地 CA 根证书到受信任根证书库 |
| `ca uninstall` / `-ca-uninstall` | 一键从受信任根证书库卸载本地 CA 根证书 |
| `update` / `-update` | 立即检查并下载 GitHub Releases 最新版本 |
| `help` / `-h` | 打印完整命令行 Flag 一览 |
