# ech-proxy

支持 **Windows 7 ~ 11 (32位 `386` / 64位 `amd64` / `arm64`) PAC 方式运行的本地 HTTP/HTTPS 代理（Mainstream）**，提供系统托盘控制、PAC 原子替换与旧值 `pop` 恢复、本地 CA 一键安装与卸载、自动检查并下载 GitHub Releases 更新（退出后再次打开自动替换）、双 DoH 冗余解析、三种上游 GFW 绕过隧道、服务端回传证书核对与强行访问放行。

## 一、 三种运行方案与严格解耦边界

1. **PAC 方案（默认主流 Mainstream，`ech-proxy.exe`）**：
   - 启动后默认将系统代理原子替换为本地 PAC 脚本（`http://127.0.0.1:8443/proxy.pac?t=<ts>`），并将旧系统代理状态压栈（退出或 `Pop` 时自动 `pop` 恢复旧值）。
   - 严格仅依据远程白名单 `https://4545810.xyz/pac.txt`（一行一个 domain，支持原子替换 `SwapWhitelist` 与旧值 `PopWhitelist`）生成 PAC 规则，**与 `upstream.json` 及 `certs/` 路径完全解耦**。
   - 本地自签 CA 与动态签发的域名叶子证书统一存放在 `<dataDir>/ca/`（`ca/ca.pem`、`ca/leaves/`），绝不触碰 `certs/` 目录。
2. **443 方案（仅当文件名匹配 `.*.443.exe` 时开启）**：
   - **只与 `listen 443` 有关**：仅在可执行文件名匹配 `.*.443.exe` 时开启，严格仅监听 `443` 端口（不回退到 `8443`），其余所有功能（PAC、广告处理、8443 门户、系统代理、托盘、自动更新、CONNECT 隧道）一律不运行。
   - 当文件名不匹配 `.*.443.exe` 时，严禁监听 443 端口且 443 方案绝不运行。
3. **8443 方案（真实公网证书下发的代理，`upstream.json` + `certs/l.moonchan.xyz/`）**：
   - `upstream.json` 与 `certs/` 路径（`certs/l.moonchan.xyz/fullchain.cer`、`privkey.pem`、`upstream.json`、`pixiv_cookie.txt`）**完全只与 8443 方案相关**。
   - 在当前主流版本中，8443 方案单纯在后台协程中**静默非阻塞运行**（仅为了兼容性保留），即使拉取或解析报错也完全静默忽略，绝不影响其他功能，且绝不阻塞主线代码。

## 二、 成人网站清单闸门、EasyList 去广告与广告替换规则（仅 PAC 方案）

- **远程开关 `DefaultOnURL = "https://4545810.xyz/on.txt"`**：
  - 拉取 `on.txt` 失败时自动重试 **2 次**（共尝试 3 次）；若重试 2 次之后仍然失败，**直接置 `on`（开启显示广告，instead of 不显示）**。
- **远程成人网站清单 `DefaultAdultSitesURL = "https://4545810.xyz/adult.txt"`（唯一闸门）**：
  - 与 `pac.txt` 职责完全独立：`pac.txt` 只决定哪些域名走代理，而 `adult.txt` 只决定哪些站点执行去广告与广告脚本注入。
  - **非 `adult.txt` 命中的普通站点**（如 `pixiv.net`，即使在 `pac.txt` 中或开启 `-all` 全局模式），**零规则执行、零 DOM/HTML 改动、零广告注入**。
- **EasyList 标准规则引擎 `DefaultEasyListURL = "https://easylist.to/easylist/easylist.txt"` + 补充屏蔽表 `DefaultBlocklistURL = "https://4545810.xyz/block.json"`**：
  - 完整支持 EasyList 网络层拦截（`||domain^`、`||domain/path`、`|http...`、子串、`@@` 白名单例外、`$domain=` / `$script` / `$subdocument` / `$third-party` 修饰符）与元素隐藏（`##selector`、`domain##selector`、`~negated##selector`、`#@#` 例外），仅在命中 `adult.txt` 的成人站点上生效。
  - 兼容 `block.json` 的 JSON 数组/对象、EasyList 规则与 HOSTS (`0.0.0.0` / `127.0.0.1`) 格式，拉取失败时使用内存内置规则兜底。
- **广告脚本替换插入 `DefaultAdScriptURL = "https://4545810.xyz/ads.js"`**：
  - 对命中 `adult.txt` 的成人站点，在剥离源站广告（及注入元素隐藏 CSS）的同时，插入来自 `ads.js`（或内置兜底）的 `<script>` 标签（可通过 `--skip-ad-script` 或 `--skip-ad-block` 独立控制）。

## 三、 命令行 Flag 一览

| Flag / 子命令 | 说明 |
| :--- | :--- |
| `-4` | 强制 v4 出口（IPv4 only，默认开启） |
| `-6` | 强制 v6 出口（IPv6 only） |
| `-dual` | 双端出口（IPv4 + IPv6 双栈自动优选） |
| `-all` | 开启全局模式（无视 `pac.txt` 白名单，所有网站均通过 `ech-proxy` 代理；仅命令行 `-all` 可开启，不在托盘中显示） |
| `--skip-ad-script` | 跳过插入广告商 JS（`<script>...</script>`）的步骤 |
| `--skip-ad-block` | 禁止拦截/移除源站原始成人广告 |
| `-whitelist-url` | 自定义 `pac.txt` 地址（默认 `https://4545810.xyz/pac.txt`） |
| `-adult-sites-url` | 自定义 `adult.txt` 成人网站清单地址（默认 `https://4545810.xyz/adult.txt`） |
| `-easylist-url` | 自定义 `easylist.txt` 地址（默认 `https://easylist.to/easylist/easylist.txt`，传 `-` 可禁用） |
| `-blocklist-url` | 自定义 `block.json` 地址（默认 `https://4545810.xyz/block.json`） |
| `-on-url` | 自定义 `on.txt` 地址（默认 `https://4545810.xyz/on.txt`） |
| `-ad-script-url` | 自定义 `ads.js` 地址（默认 `https://4545810.xyz/ads.js`） |
| `ca install` / `-ca-install` | 一键安装本地 CA 根证书到受信任根证书库 |
| `ca uninstall` / `-ca-uninstall` | 一键从受信任根证书库卸载本地 CA 根证书 |
| `update` / `-update` | 立即检查并下载 GitHub Releases 最新版本 |
| `help` / `-h` | 打印完整命令行 Flag 一览 |
