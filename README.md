# ech-proxy

支持 **Windows 7 ~ 11 (32位 `386` / 64位 `amd64` / `arm64`) PAC 方式运行的本地 HTTP/HTTPS 代理（Mainstream）**，提供系统托盘控制、PAC 原子替换与旧值 `pop` 恢复、本地 CA 一键安装与卸载、自动检查并下载 GitHub Releases 更新（退出后再次打开自动替换）、双 DoH 冗余解析、三种上游 GFW 绕过隧道、服务端回传证书核对与强行访问放行。

> [!CAUTION]
> **绝对禁止修改 DoH Endpoint**
>
> 本项目的 DNS 核心机制严格依赖既定的端到端纯净 DoH 服务（主端点 `https://4545810.xyz/doh`，备用端点 `https://1.1.1.1/dns-query`，引导 IP 仅限 `1.1.1.1` / `1.0.0.1`）。
> **绝对禁止修改 DoH Endpoint**，严禁引入国内 DNS / DoH 服务器或修改既定端点，以确保零 DNS 污染与严格隐私安全。

---

## 一、 初次使用步骤指南（推荐顺序）

首次运行 `ech-proxy` 时，建议按照以下步骤进行初始化设置：

1. **第一步：启动程序**
   - 双击运行 `ech-proxy.exe`。
   - 程序启动后会自动在后台初始化，并在 Windows 任务栏右下角通知区域生成系统托盘图标。
   - 默认会显示黑色命令行控制台窗口（右上角 `[X]` 按钮已被保护锁定以防意外误关退出）。

2. **第二步：一键安装本地 CA 根证书（初次必须，仅需一次）**
   - 鼠标右键点击右下角系统托盘小图标，在弹出菜单中点击 **「一键安装本地 CA 根证书 (Install CA)」**。
   - 系统会弹出 Windows 安全警告 / UAC 授权确认对话框，点击 **“是”** 或 **“确认”**。
   - 程序会自动将本地生成的自签根证书（存放于 `<dataDir>/ca/ca.pem`）安装导入至 Windows 系统的“受信任的根证书颁发机构”中。
   - *说明：此步骤用于实现 HTTPS 流量解析与 ECH 探测，安装后浏览器访问加速站点时不会出现任何“不安全”或“证书错误”告警。*

3. **第三步：确认启用系统 PAC 代理模式**
   - 鼠标右键点击托盘图标，确认 **「系统代理：自动配置 PAC 模式 (推荐)」** 处于勾选状态（程序默认启动时会自动配置开启）。
   - 此时系统的自动代理配置脚本已指向本地 PAC 服务（`http://127.0.0.1:8443/proxy.pac`），系统仅对特定分流清单中的目标网站走代理通道，国内常规网站（如百度、淘宝、B站等）完全保持本地网络直连，互不影响。

4. **第四步：选择出口协议族（可选）**
   - 默认启用 **「强制 v4 出口」**。
   - 若本地宽带或所处网络环境具备优质的原生 IPv6 连通性，可在右键菜单中根据需要切换为 **「双端出口」**（IPv4 + IPv6 自动优选）或 **「强制 v6 出口」**。

5. **第五步：隐藏控制台，浏览器无感冲洗**
   - 打开任意支持系统代理的浏览器（Microsoft Edge、Google Chrome、Firefox 等），即可直接流畅访问目标网站。
   - 平时可以将黑框控制台隐藏：**双击托盘图标**，或右键选择 **「显示 / 隐藏控制台」**，控制台窗口将直接隐藏并在后台静默常驻运行。

6. **第六步：安全退出**
   - 如需关闭代理，在托盘菜单中点击 **「退出程序并清理系统代理 (Exit)」**。
   - 程序会在退出前自动清除 Windows 系统的 PAC 设置并恢复原始代理状态，绝不在系统中残留任何失效代理配置。

---

## 二、 Windows 系统托盘功能详述

右键点击任务栏托盘小图标，各菜单功能项说明如下：

| 菜单项名称 | 功能说明与操作指南 |
| :--- | :--- |
| **显示 / 隐藏控制台 (双击托盘图标)** | 切换显示或隐藏后台控制台黑框窗口。为防止日常误点击右上角 `[X]` 导致服务意外中断，控制台右上角的关闭按钮已做锁定保护，日常通过双击托盘图标即可轻松在“静默后台”与“控制台前台”之间切换。 |
| **系统代理：自动配置 PAC 模式 (推荐)** | 将 Windows 系统网络代理设为 PAC 自动脚本模式。依据远程规则动态分流，命中规则的站点走加速隧道，其余站点本地直连。 |
| **系统代理：清除 / 禁用系统代理 (直连)** | 临时停用系统代理并恢复直连模式。当需要临时排查本地网络状况或暂停分流加速时点击此项。 |
| **强制 v4 出口** | 强制所有上游请求通过 IPv4 出口发往远程目标服务器（默认启用，适合大多数常规网络）。 |
| **强制 v6 出口** | 强制所有上游请求通过 IPv6 出口发往远程目标服务器（适合教育网或纯 IPv6 优质线路）。 |
| **双端出口** | 启用 IPv4 / IPv6 双协议族并发并就近优选，兼顾连通性与低延迟。 |
| **一键安装本地 CA 根证书 (Install CA)** | 首次使用必须运行。一键调用 Windows CryptoAPI 将本地 CA 导入系统受信任根证书库，消除 HTTPS 访问时的证书安全警告。 |
| **卸载本地 CA 根证书 (Uninstall CA)** | 从系统证书库中彻底卸载并清理本地自签根证书，不留系统垃圾。 |
| **检查更新 (Check Update)** | 手动检查 GitHub Releases 上的最新发布版本。若有新版将自动在后台下载；下载完毕后菜单将提示“新版本已下载，退出重开自动替换”，并在下一次程序退出时自动完成替换。 |
| **反馈 (https://chatto.4545810.xyz)** | 快速调用默认浏览器打开官方反馈讨论区。 |
| **复制 PAC 地址 (Copy PAC URL)** | 将当前正在运行的 PAC 脚本完整地址（如 `http://127.0.0.1:8443/proxy.pac`）复制到剪贴板，方便配置到局域网手机、平板或其他终端设备。 |
| **转储内存诊断 (Dump Memory)** | 实时将当前 Go 运行时与各模块内存占用、连接池/缓存指标、pprof 堆快照及协程栈转储至本地日志目录，方便排查内存占用与定位异常连接。 |
| **打开本地日志目录 (问题排查/上传日志)** | 一键在文件资源管理器中打开日志存储目录，方便在遇到异常、崩溃或连接问题时查看与提取日志文件。 |
| **退出程序并清理系统代理 (Exit)** | 安全退出代理程序，并在退出前自动清理系统 PAC 设置，确保系统网络完全恢复为启动前的初始状态。 |

> **鼠标悬停提示（Tooltip）**：鼠标指针悬停在托盘图标上时，将实时显示当前服务地址与工作状态，例如：  
> `ech-proxy [127.0.0.1:8443] - 系统PAC自动分流 (v4出口)`

---

## 三、 三种运行方案与严格解耦边界

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

---

## 四、 命令行 Flag 一览

| Flag / 子命令 | 说明 |
| :--- | :--- |
| `-4` | 强制 v4 出口（IPv4 only，默认开启） |
| `-6` | 强制 v6 出口（IPv6 only） |
| `-dual` | 双端出口（IPv4 + IPv6 双栈自动优选） |
| `-all` | 开启全局模式（无视 `pac.txt` 白名单，所有网站均通过 `ech-proxy` 代理；仅命令行 `-all` 可开启，不在托盘中显示） |
| `-whitelist-url` | 自定义 `pac.txt` 地址（默认 `https://4545810.xyz/pac.txt`） |
| `-ip` | 出口 IP 协议族兼容别名（支持 `4` / `ipv4` / `6` / `ipv6` / `dual` / `0`，兼容旧版 `-ip 4` 调用习惯） |
| `-mode` | 运行模式选择（`smart` / `443` / `local`；若旧版脚本误传悬空 `-mode -ip 4` 将自动容错忽略） |
| `ca install` / `-ca-install` | 一键安装本地 CA 根证书到受信任根证书库 |
| `ca uninstall` / `-ca-uninstall` | 一键从受信任根证书库卸载本地 CA 根证书 |
| `update` / `-update` | 立即检查并下载 GitHub Releases 最新版本 |
| `help` / `-h` | 打印完整命令行 Flag 一览 |

---

## 五、 Windows 7 (32位 `386` / 64位 `amd64`) 兼容性与构建说明（借鉴 Xray / V2Ray 方案）

### 1. 为什么官方原版 Go 1.21.5+ 编译的程序在 Windows 7 下启动即崩溃？
- 自 **Go 1.21.5** 及 **Go 1.22 ~ 1.26+** 起，Go 官方运行时在启动阶段（`runtime.osinit` -> `runtime.getRandomData`）将随机数接口从 Windows XP/7 原生支持的 `advapi32.dll!SystemFunction036`（`RtlGenRandom`）强制替换为仅 **Windows 8+** 才存在的 `bcryptprimitives.dll!ProcessPrng`。
- 在 Windows 7 系统上，由于系统目录缺失 `bcryptprimitives.dll`，`_ProcessPrng` 函数指针解析为 `0x0`（空指针），程序启动执行第一条 `internal/runtime/syscall/windows.asmstdcall` 时直接 `CALL 0x0`，触发 `Exception 0xc0000005 0x8 0x0 0x0 (PC=0x0)` 崩溃退出。

### 2. 本项目的双轨解决方案（借鉴 `XTLS/Xray-core`）
为了同时满足 **Windows 7 (`386` / `amd64`) 原生运行** 与 **`uTLS v1.8.2` 完整 ECH 加密客户端问候支持**，本项目采用与 `XTLS/Xray-core` 相同的工程方案：

1. **项目源码层降级至 Go 1.20 标准库基线**：
   - 移除项目源码中对 Go 1.23+ 专属标准库 API 的依赖（将 `http.ParseSetCookie` 替换为兼容 Go 1.0+ 的 `parseSetCookie` 辅助函数；移除在 Win7 下存在控制台/句柄克隆兼容隐患的 `debug.SetCrashOutput`）。
   - 对所有 Windows 动态库过程调用（`user32.dll`、`shell32.dll`、`wininet.dll` 等）统一通过 `safeCallProc`（调用前先执行 `proc.Find()` 校验）保护，彻底杜绝缺失导出函数导致的 `PC=0x0` 空指针异常。
2. **CI 与发布流水线采用 `XTLS/go-win7` (`patched-1.26.7`) 补丁版 SDK 编译**：
   - `.github/workflows/ech-proxy.yml`、`.github/workflows/go.yml` 与 `.github/workflows/goreleaser.yml` 在构建 Windows 产物时自动拉取 [`XTLS/go-win7`](https://github.com/XTLS/go-win7/releases)（`patched-1.26.7`）并锁定 `GOTOOLCHAIN=local`。
   - 该补丁版工具链将 `ProcessPrng` 替换为 Windows 7 原生支持的 `bcrypt.dll!BCryptGenRandom`，并修复了 Win7 控制台句柄（`CONIN$`/`CONOUT$`）、PEB 长路径与 `os.RemoveAll` 兼容性问题。
3. **本地构建方式**：
   - **推荐方案（保留完整 ECH 与最新依赖）**：直接运行 `./scripts/build-win7.sh`，自动下载 `XTLS/go-win7` 并交叉编译出兼容 Windows 7 ~ 11 的 `dist/ech-proxy-windows-amd64.exe`、`dist/ech-proxy-windows-386.exe` 及 `dist/ech-proxy.443.exe`。
   - **备选方案（强制降级至官方原版 `Go 1.21.4`）**：若需在无补丁的官方原版 Go 下编译，最高只能使用 **Go 1.21.4** 或 **Go 1.20.14**，可运行 `./scripts/downgrade-go1214.sh` 自动回退 `go.mod` 与第三方依赖版本。
4. **Windows 7 客户端运行环境建议**：
   - 建议使用 **Windows 7 SP1** 并安装基础更新汇总（KB3125574）与 SHA-2 签名支持补丁（KB4474419）。
