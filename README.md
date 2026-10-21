# ech-proxy

支持 **V2rayN 风格系统托盘（显示/隐藏 Console 控制台）**、**Windows 自动配置 PAC / 系统代理**、**HTTP CONNECT 正向代理（Smart MITM ECH/SNI）**、**全自动 SNI / ECH 透明反向代理** 与 **Android / Flutter 集成** 的轻量级代理工具。

## 一、 全新使用逻辑设计（参考 V2rayN：托盘控制 + 自动 PAC + 三模式合一）

重构后的桌面端参考了 **V2rayN** 的交互与系统代理管理机制，采用 **纯 Go 原生 Win32 API（零 CGo 依赖，完美兼容 `CGO_ENABLED=0` 交叉编译）** 实现了系统托盘、控制台显隐切换与 Windows 系统 PAC 自动接管：

| 核心特性 | 行为说明（参考 V2rayN 交互逻辑） |
| :--- | :--- |
| **系统托盘与控制台显隐** | 启动后自动常驻 Windows 右下角系统托盘（内置亮青色 `E` 字盾牌图标，无需外部 `.ico` 文件），并自动禁用控制台窗口右上角误关按钮 `[X]`；**单击/双击托盘图标**即可随时隐藏或恢复显示 Console 窗口（也支持 `-hide-console` 启动即隐藏到托盘） |
| **自动给 Windows 设置 PAC** | 默认 `smart` 模式启动时，自动通过 Windows 注册表（`HKCU\...\Internet Settings`）与 WinINet `InternetSetOptionW`（`INTERNET_OPTION_PER_CONNECTION_OPTION` + `SETTINGS_CHANGED` + `REFRESH`）将系统代理设为 `http://127.0.0.1:8443/proxy.pac?t=<timestamp>`，浏览器无需重启立即生效 |
| **托盘右键菜单一键切换** | 右键点击托盘图标可一键切换：**① 自动配置 PAC 模式（推荐）**、**② 全局 HTTP/HTTPS 代理模式**、**③ 清除/禁用系统代理（直连）**，以及 **打开门户导航页**、**复制 PAC 地址到剪贴板**、**一键安装本地 CA 根证书（`certutil -user`）** |
| **退出自动还原防断网** | 无论是从托盘点击“退出程序”还是按下 `Ctrl+C` / 收到终止信号，`ech-proxy` 都会自动清除系统代理配置并移除托盘图标，绝不残留失效代理导致浏览器断网 |

### 三种接入方式对比（同一端口全兼容）

| 接入方式 | 适用场景 | 是否需要改 `hosts` | 是否需要管理员/443 端口 | 核心优势 |
| :--- | :--- | :--- | :--- | :--- |
| **方式 A：自动 PAC / 系统代理模式（默认，强烈推荐）** | Windows 桌面端 Chrome / Edge / Firefox 及全系统应用 | **不需要** | **不需要**（默认 `8443` 普通端口） | 启动即自动设置 Windows PAC，天然支持 `*.pixiv.net`、`*.pximg.net`、`*.dlsite.com` 等任意泛子域名与多级子域名，自动注入防盗链 `Referer` |
| **方式 B：门户导航模式（`l.moonchan.xyz`）** | 移动端浏览器、免装本地 CA 的快速访问 | 仅需 `l.moonchan.xyz` 1 条 | **不需要**（默认 `8443`） | 使用 `l.moonchan.xyz` 公网受信证书，自带站点搜索、CA 下载与状态面板 |
| **方式 C：本地 443 透明反代模式（`hosts` 模式）** | 不读取系统代理的特殊原生客户端 | 需要（支持 `ech-proxy hosts apply` 一键写入） | 需要（若无权限自动回退至 `8443`） | 浏览器直接访问原域名 `https://www.pixiv.net/`，由内置 CLI 自动管理 `hosts` 块 |

### 快速上手（Windows 桌面端零配置体验）

1. **双击运行 `ech-proxy.exe`**：
   * 程序自动监听 `127.0.0.1:8443`，自动在右下角生成系统托盘图标，并自动将 Windows 系统代理配置为 PAC 模式（`http://127.0.0.1:8443/proxy.pac?t=...`）。
2. **一键信任本地 CA 根证书（仅首次需要）**：
   * 右键点击右下角托盘图标 $\rightarrow$ 点击 **“一键安装本地 CA 根证书 (Install CA)”**（或执行 `ech-proxy ca install`），在弹出的系统提示中点击“是”即可导入当前用户受信任根证书库（若使用 Firefox，在 `about:config` 中将 `security.enterprise_roots.enabled` 设为 `true`）。
3. **直接打开原网址畅游**：
   * 直接在浏览器访问 `https://www.pixiv.net`、`https://e-hentai.org`、`https://www.dlsite.com`、`https://www.iwara.tv` 等原域名，所有主站与图片 CDN（`i.pximg.net` / `s.pximg.net`）均自动通过 ECH/SNI 加速转发！
   * 需要隐藏黑框控制台时，**双击右下角托盘图标**即可隐藏到后台运行。

## 二、 命令行子命令与参数一览

`ech-proxy` 同时支持语义化子命令与传统 CLI 标志（100% 向后兼容）：

| 子命令 / 标志 | 等价传统参数 | 跨平台环境变量 | 功能说明 |
| :--- | :--- | :--- | :--- |
| `ech-proxy` / `ech-proxy run` | `-mode smart` | — | 启动统一智能代理（默认开启系统托盘 + 自动配置 Windows PAC） |
| `-sys-proxy <pac\|global\|off>` | — | `ECH_PROXY_SYS_PROXY` | 启动时自动设置的系统代理模式（`smart` 默认 `pac`，`local` 默认 `off`） |
| `-hide-console` | — | — | 启动后自动隐藏控制台窗口到系统托盘（双击托盘图标可恢复） |
| `-no-tray` | — | — | 禁用系统托盘图标（适用于无桌面服务器环境） |
| `ech-proxy sysproxy pac` | — | — | 立即将系统代理设置为本地 PAC 模式并退出 |
| `ech-proxy sysproxy global` | — | — | 立即将系统代理设置为全局 HTTP/HTTPS 模式并退出 |
| `ech-proxy sysproxy clear` | — | — | 立即清除系统代理（恢复直连）并退出 |
| `ech-proxy sysproxy status` | — | — | 查看当前操作系统的系统代理状态 |
| `ech-proxy ca install` | `-ca-install` | — | 一键将本地 CA 证书安装到当前用户受信任根证书库（`certutil -user`） |
| `ech-proxy ca export <file>` | `-ca-export <file>` | `ECH_PROXY_DATA_DIR` | 导出本地 CA 根证书到指定路径 |
| `ech-proxy local` | `-local` / `.443.exe` | — | 启动 443 本地透明反向代理（若 443 端口无权限则自动回退至 `8443`） |
| `ech-proxy check` | `-check-config` | `ECH_PROXY_CONFIG` | 静态校验 `upstream.json`（主动捕获键名拼写错误、非法 `ip_mode`/`mode` 等 S1–S6 问题） |
| `ech-proxy hosts [print\|apply\|clean]` | `-hosts-*` | — | 预览、一键写入或清理系统 `hosts` 中的 `# BEGIN ECH-PROXY` 受管块 |
| `-addr <host:port>` | `-addr` | — | 自定义监听地址与端口 |
| `-ip-mode <v4\|v6>` | `-ip-mode` | `IP_MODE` | 锁定全局上游出口协议族（统一作用于 ECH、SNI、Direct 与 CONNECT） |
| `-local-ip <ip>` | `-local-ip` | `LOCALIP` | 指定 DoH 引导 IP |
| `-connect-mode <mitm\|tunnel>` | `-connect-mode` | — | `CONNECT` 策略：`mitm`（默认，443 走 ECH/SNI 管道）或 `tunnel`（纯 TCP 隧道） |
| `-token <secret>` | `-token` | `ECH_PROXY_TOKEN` | 开启代理 Bearer Token 鉴权（同时支持 `ECH_PROXY_USER` / `ECH_PROXY_PASS` Basic 认证） |

## 三、 模块化架构

```text
echproxy/
├── netdial/      # [基础网络层] 独立连接/DoH/流超时、双栈 IP 过滤、Cloudflare/内网保留 CIDR 识别（0 内部依赖）
├── config/       # [配置与生成层] upstream.json 解析、S1–S6 静态校验器（含编辑距离拼写建议）、PAC 与受管 hosts 生成器
├── certstore/    # [证书管理层] 公网证书 + 本地自签 CA、多级子域与双后缀顶级域（如 co.jp）证书分组、TLS 握手告警聚合去重
├── cookie/       # [Cookie 管理层] 受控 Cookie 加载、过期/deleted 登出主动清理、browser/seed 优先级合并与 Set-Cookie 改写
├── rewrite/      # [内容重写层] 解压/重压缩、门户与原域名重写隔离（防止原域名模式污染为 l.moonchan.xyz）、SW 脚本生成
├── ech/          # [传输隧道层] Cloudflare ECH、SNI 伪装（H2/H1.1 自适应 + 自定义 SNI）、双栈 DoH A/AAAA 解析与无感回退
├── connect.go    # [正向代理层] HTTP CONNECT 处理器（鉴权防爆破 + SSRF 黑名单守卫 + 双层并发限流 + Smart MITM / TCP Relay）
├── portal.go     # [门户与自助端点] 导航面板、/ca.pem、/proxy.pac、/hosts.txt、/statusz 路由注册
├── proxy.go      # [反代流水线] 路由匹配、请求构造、多跳自重定向熔断与超大流式响应无损转发
└── server.go     # [服务生命周期] 双模单端口连接嗅探（同端口承载 HTTP/CONNECT 与 HTTPS）、443 无权限平滑回退
win/
├── main.go             # [桌面端 CLI 与生命周期] 子命令/参数解析、自动 PAC 挂载与优雅退出清理
├── sysproxy.go         # [系统代理状态机] PAC / Global / Off 三态切换、时间戳防缓存 PAC URL 与退出自动还原
├── sysproxy_windows.go # [Windows WinINet 驱动] 注册表 + InternetSetOptionW 实时刷新系统代理与 certutil 证书安装
├── tray.go             # [系统托盘控制器] 控制台显隐切换、托盘右键菜单命令分发与状态同步
└── tray_windows.go     # [Windows 原生托盘] 纯 Go Win32 Shell_NotifyIconW、内置绘制图标、GetConsoleWindow 显隐与剪贴板
```

## 四、 编译与测试

```bash
# 1. 运行全量单元测试与竞态检测（包含系统代理状态机、托盘控制器、upstream.json 校验与 FFI 契约测试）
go test ./... -race -v

# 2. 编译 Windows 桌面端（纯 Go 零 CGo 依赖，原生支持系统托盘与自动设置 PAC）
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ech-proxy.exe ./win/
```
