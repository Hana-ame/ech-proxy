# ech-proxy

支持 **V2rayN 风格系统托盘（显示/隐藏 Console 控制台）**、**Windows 自动配置 PAC / 系统代理**、**远程唯一白名单（黄网 = 去原有广告 + 加自己广告 + PAC 走代理，其他直连）**、**`-all` 全局模式**、**`-ipmode` 协议族切换（默认 `ipv4`，支持 `dual` / `6`）** 与 **本地持久化报错/闪退崩溃日志** 的轻量级代理工具。

## 一、 核心规则与功能说明

| 核心机制 | 行为说明 |
| :--- | :--- |
| **唯一远程白名单 (`whitelist.json`)** | **白名单 = 黄网 = 去掉原有广告 + 加上自己广告 + 通过 `ech-proxy` 的 PAC 规则代理（其他网站直接 `DIRECT` 直连）**。可通过 `-whitelist-url` 配置远程 JSON 列表地址，留空使用默认远程地址（`certs/l.moonchan.xyz/whitelist.json`），拉取失败严格执行 `fallback = []`（空列表）。此外，若网页 HTML 中出现了成人网站广告（如 ExoClick、JuicyAds、TrafficJunky 等），同样自动识别为黄网并去广告 + 加自有推广横幅。 |
| **`all` 全局代理模式 (`-all`)** | 通过 `-all`、`-mode all` 或子命令 `ech-proxy all` 开启：无视白名单限制，所有网站（除本机与局域网外）均通过 `ech-proxy` 代理。 |
| **`ipmode` 协议族标志 (`-ipmode`)** | 控制上游出口 IP 协议族：**默认 `ipv4`**（即 `4 = ipv4 only`，避免 IPv6 不通导致连接超时或报错），`-ipmode dual` 开启双栈（IPv4 + IPv6），`-ipmode 6` 锁定仅 IPv6（`ipv6 only`）。 |
| **报错与闪退日志落盘 (`logs/`)** | 无论在命令行解析阶段报错、端口/证书初始化失败，还是运行期发生未捕获 Panic 闪退，程序均会自动在 `logs/` 目录下留下完整的 `ech-proxy.log` 与 `crash-latest.log`（含系统环境、脱敏参数、完整堆栈与最近 80 行上下文日志），并绑定 `debug.SetCrashOutput`，方便直接上传排查 debug。 |

## 二、 命令行子命令与参数一览

| 子命令 / 标志 | 等价参数 / 环境变量 | 功能说明 |
| :--- | :--- | :--- |
| `ech-proxy` / `ech-proxy run` | `-mode smart` | 启动默认白名单智能代理（默认开启系统托盘 + 自动配置 Windows PAC + 默认 `ipv4`） |
| `ech-proxy all` | `-all` / `-mode all` / `ECH_PROXY_ALL=1` | 开启 `all` 模式：无视白名单，所有网站均通过 `ech-proxy` 代理 |
| `-ipmode <ipv4\|4\|dual\|6>` | `-ip-mode` / `IP_MODE` | 出口 IP 协议族：**`[default]=ipv4`**（`4 = ipv4 only`），`dual` = 双栈，`6` = `ipv6 only` |
| `-whitelist-url <url>` | `ECH_PROXY_WHITELIST_URL` | 远程唯一白名单（黄网域名 JSON 列表）地址，留空用默认远程地址，失败 `fallback = []` |
| `-ad-script-url <url>` | `ECH_PROXY_AD_SCRIPT_URL` | 远程去广告与推广脚本地址，留空自动拉取最新并每 30 分钟热更新 |
| `-no-ad-script` | `-disable-ad-script` / `ECH_PROXY_NO_AD_SCRIPT=1` | 禁用去广告与自有推广横幅注入功能 |
| `ech-proxy logs [path\|tail\|crash\|clean]` | `-log-dir` / `-log-file` / `-no-log-file` | 查看本地日志路径、输出最近 100 行日志、查看最近一次报错/闪退报告（`crash-latest.log`）或清理日志 |
| `ech-proxy sysproxy [pac\|global\|clear\|status]` | `-sys-proxy <pac\|global\|off>` | 切换或查看 Windows 系统代理状态 |
| `ech-proxy ca [status\|export\|install]` | `-ca-install` / `-ca-export <file>` | 查看、导出或一键安装本地自签 CA 根证书（`certutil -user`） |
| `ech-proxy check` | `-check-config` | 静态校验 `upstream.json` 配置文件 |
| `ech-proxy hosts [print\|apply\|clean]` | `-hosts-print` / `-hosts-apply` / `-hosts-clean` | 预览、一键写入或清理系统 `hosts` 中的 `# BEGIN ECH-PROXY` 受管块 |

## 三、 编译与测试

```bash
# 1. 运行全量单元测试与竞态检测
go test ./... -race -v

# 2. 编译 Windows 桌面端（纯 Go 零 CGo 依赖，原生支持系统托盘与自动设置 PAC）
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ech-proxy.exe ./win/
```
