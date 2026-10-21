# ech-proxy

支持 **Windows 7 ~ 11 (32位 `386` / 64位 `amd64` / `arm64`) PAC 方式运行的本地 HTTP/HTTPS 代理**，提供系统托盘控制、本地 CA 一键安装与卸载、自动检查并下载 GitHub Releases 更新（退出后再次打开自动替换）、双 DoH 冗余解析、三种上游 GFW 绕过隧道、服务端回传证书核对与强行访问放行。

## 一、 核心架构与工作流

1. **PAC 白名单劫持 (`https://4545810.xyz/pac.txt`)**：
   - 启动后默认将系统代理配置为本地 PAC 脚本（`http://127.0.0.1:8443/proxy.pac`），仅劫持远程白名单 `https://4545810.xyz/pac.txt`（一行一个 domain）中的站点并转发到本地代理，其余流量全部 `DIRECT` 直连。
   - 启动后**不自动打开任何门户网页**，门户功能完全独立，绝不影响 PAC HTTPS Proxy 主线。
   - 在可执行文件名不包含 `.443.exe` 时，**严禁监听 443 端口，且 443 相关代码绝对不运行**。
2. **本地 HTTPS CONNECT MITM 与 CA 管理**：
   - 本地代理接收 `CONNECT` 请求后，使用本地自动生成的根证书（`ca/ca.pem`）按需签发目标域名证书。
   - 托盘右键菜单与命令行同时提供 **一键安装本地 CA 根证书** 与 **卸载本地 CA 根证书** 选项。
3. **双 DoH 解析与三种上游请求方式**：
   - **首选 DoH**：`https://4545810.xyz/doh`
   - **次选 DoH（自动故障回退）**：`https://1.1.1.1/dns-query`
   - **三种上游绕过方式**：
     1. **方式 1（SNI 伪装）**：通过 DoH 解析真实 IP + 伪装 SNI 请求 + 核对服务端回传证书是否与伪装前真实域名（`truedomain.com`）一致且未过期。
     2. **方式 2（Cloudflare ECH）**：通过 DoH 解析域名与 ECH 公钥 + 使用加密 ClientHello 请求 + 核对服务端回传证书。
     3. **方式 3（TLS 分片绕过 GFW）**：通过 DoH 解析真实 IP + 将 TLS ClientHello 按字节分片发送绕过 DPI + 核对服务端回传证书。
4. **上游证书严格核对与「强行访问」按钮**：
   - 比较真实访问域名 `truedomain.com` 与上游服务器回传的证书是否一致、是否过期。
   - 若不一致则提示**域名不一致**，若过期则提示**证书已过期**，并提供带一次性防伪令牌的 **「强行访问」** 按钮。
5. **源站广告拦截与广告商 `<script>` 插入**：
   - 默认拦截并删除源站广告（可通过 `--skip-ad-block` 禁用）。
   - 自动从 `https://4545810.xyz/ads.js` 拉取最新广告商代码（若不可达则使用内置 `slimgather.com` 与 `fussyreturn.com` 兜底），将每段广告代码放入独立的 `<script>...</script>` 标签中插入返回（可通过 `--skip-ad-script` 跳过）。
   - 广告相关设置在系统托盘中隐藏，仅通过命令行参数控制。
6. **自动检查更新与退出替换**：
   - 启动后后台自动检查 `https://github.com/Hana-ame/ech-proxy/releases` 最新版的 `checksums.txt`，对比当前平台二进制 SHA-256（支持 `ech-proxy-windows-386.exe`、`ech-proxy-windows-amd64.exe`、`ech-proxy-windows-arm64.exe`、`ech-proxy-linux-386`、`ech-proxy-linux-amd64`、`ech-proxy-linux-arm64`、`ech-proxy-darwin-amd64`）。
   - 发现新版后自动下载并校验 SHA-256，暂存为 `<exe>.new`，在程序退出后再次打开时自动完成替换（托盘菜单也提供手动「检查更新」选项）。

## 二、 命令行 Flag 一览

| Flag / 子命令 | 说明 |
| :--- | :--- |
| `-4` | 强制 v4 出口（IPv4 only，默认开启） |
| `-6` | 强制 v6 出口（IPv6 only） |
| `-dual` | 双端出口（IPv4 + IPv6 双栈自动优选） |
| `-all` | 开启全局模式（无视 `pac.txt` 白名单，所有网站均通过 `ech-proxy` 代理；**仅命令行 `-all` 可开启**，不在托盘中显示） |
| `--skip-ad-script` | 跳过插入广告商 JS（`<script>...</script>`）的步骤 |
| `--skip-ad-block` | 禁止拦截/移除源站原始广告 |
| `ca install` / `-ca-install` | 一键安装本地 CA 根证书到受信任根证书库 |
| `ca uninstall` / `-ca-uninstall` | 一键从受信任根证书库卸载本地 CA 根证书 |
| `update` / `-update` | 立即检查并下载 GitHub Releases 最新版本 |
| `help` / `-h` | 打印完整命令行 Flag 一览 |

## 三、 系统托盘右键菜单

- **显示 / 隐藏控制台 (双击托盘图标)**
- **系统代理：自动配置 PAC 模式 (推荐)**
- **系统代理：清除 / 禁用系统代理 (直连)**
- **强制 v4 出口** / **强制 v6 出口** / **双端出口**
- **一键安装本地 CA 根证书 (Install CA)**
- **卸载本地 CA 根证书 (Uninstall CA)**
- **检查更新 (Check Update)**
- **反馈 (`https://chatto.moonchan.xyz`)**
- **复制 PAC 地址 (Copy PAC URL)**
- **打开本地日志目录 (问题排查/上传日志)**
- **退出程序并清理系统代理 (Exit)**
