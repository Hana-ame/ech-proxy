# ech-proxy

支持 **Windows 7 ~ 11（32 位 `386` / 64 位 `amd64`）全系统 PAC 自动代理**、**本地 HTTPS CONNECT MITM 终结（自生成 CA）**、**三种 GFW 绕过请求方式（DoH + SNI 伪装 / DoH + ECH / DoH + TLS 分片绕过）**、**源站证书真伪与过期校验（带“强行访问”按钮）** 以及 **远程去广告与自有广告注入（从 repo 拉取 `.js`）** 的模块化 HTTP/HTTPS 代理工具。

## 一、 核心工作流与架构设计

1. **PAC 方式劫持白名单请求（兼容 Windows 7~11 32/64 位）**：
   * 启动时自动通过 Windows 注册表与 WinINet `InternetSetOptionW`（精确适配 32 位 12 字节 / 64 位 16 字节 `INTERNET_PER_CONN_OPTIONW` 联合体内存布局）设置系统 PAC：`http://127.0.0.1:8443/proxy.pac?t=<timestamp>`。
   * 白名单（`certs/l.moonchan.xyz/whitelist.json`）中的网站请求通过 PAC 转发到本地代理（`PROXY 127.0.0.1:8443; DIRECT`），其余网站直接 `DIRECT` 直连（也可通过 `-all` 开启全量代理）。
2. **CONNECT 本地 HTTPS Server 与自生成 CA**：
   * 浏览器对白名单域名发起 `CONNECT` 请求到本地代理，本地代理启动 HTTPS MITM 服务终结 TLS。
   * 运行后自动在本地生成根证书 `ca/ca.pem`（可通过托盘右键菜单 **“一键安装本地 CA 根证书”**、命令 `ech-proxy ca install` 或访问 `http://127.0.0.1:8443/ca.pem` 手动安装信任，避免浏览器显示 HTTPS 证书错误）。
3. **三种方式请求白名单目标地址 + 广告拦截与注入**：
   * **方式 1（DoH + SNI 伪装，`echproxy/ech/sni.go`）**：通过 DoH 解析域名真实 IP，使用伪装 SNI 绕过检测发起请求；握手后核对服务端回传证书是否覆盖伪装前访问的真实域名（`truedomain.com`）且未过期；拦截并删除源站广告，插入从 repo 拉取的 `ad_script.js` 自有广告后返回。
   * **方式 2（DoH + ECH，`echproxy/ech/client.go`）**：通过 DoH 解析域名与 HTTPS Type 65 配置，使用 Cloudflare ECH 加密请求；核对服务端回传证书；拦截并删除源站广告，插入从 repo 拉取的 `ad_script.js` 自有广告后返回。
   * **方式 3（DoH + TLS ClientHello 分片绕过 GFW，`echproxy/ech/fragment.go`）**：通过 DoH 解析域名真实 IP，将首个 TLS Handshake `ClientHello` 记录拆分为多个微小 TLS Record 分片发送（打碎明文 SNI 特征以绕过 GFW DPI）；核对服务端回传证书；得到响应 body 后删除源站广告，插入从 repo 拉取的 `ad_script.js` 自有广告后返回。
4. **上游证书真伪/过期核对与“强行访问”按钮（`echproxy/ech/certcheck.go`、`echproxy/certwarn.go`、`echproxy/forcecert.go`）**：
   * 比较伪装前访问的真实域名 `truedomain.com` 与服务端回传证书是否一致（`leaf.VerifyHostname`）、是否过期（`NotBefore` / `NotAfter`）、证书链是否可信（`leaf.Verify`）。
   * **如果不一致**：渲染红色警告页明确提示 **“⚠ 上游证书与请求域名不一致”**（展示 `truedomain.com` 与回传证书实际包含的域名 SANs）。
   * **如果已过期**：渲染琥珀色警告页明确提示 **“⚠ 上游证书已过期或尚未生效”**（展示证书有效期起止时间）。
   * **强行访问按钮**：警告页内置一次性防伪 Token 的 **“强行访问（忽略证书警告并继续）”** 按钮，点击后在本会话内放行该域名及其子资源。

## 二、 模块化代码结构

```text
echproxy/
├── netdial/            # [基础网络层] 独立超时、IPv4/IPv6/Dual 协议族绑定（默认 ipv4）、Cloudflare/内网 CIDR 识别
├── logger/             # [持久化日志层] 启动自动清空旧日志、5MB 滚动切分、报错/Panic 闪退自动落盘 ech-proxy.log 与 crash-latest.log
├── config/             # [配置与生成层] upstream.json 解析、S1–S6 静态校验器、PAC 脚本与受管 hosts 生成器
├── certstore/          # [本地 CA 证书层] 自动生成 ca/ca.pem 根证书、按需动态签发目标域名通配符证书（含多级子域与双后缀顶级域）
├── ech/
│   ├── certcheck.go    # [上游证书核对模块] 比较 truedomain.com 与回传证书（域名一致性、是否过期、信任链）及强行访问标记
│   ├── sni.go          # [方式 1：SNI 伪装] DoH 解析 + 伪造 SNI + 回传证书核对 + 三方式智能路由调度（RoundTrip）
│   ├── client.go       # [方式 2：ECH 请求] DoH 解析 + Cloudflare ECH 隧道 + 回传证书核对
│   └── fragment.go     # [方式 3：GFW 绕过] DoH 解析 + TLS ClientHello 记录分片（Record Fragmentation）+ 回传证书核对
├── forcecert.go        # [强行访问状态机] 警告页一次性 Token 签发、并发 /favicon.ico 容错、限速防刷与会话级域名批准
├── certwarn.go         # [证书警告页渲染] 区分“已过期 / 不一致 / 不可信”的 HTML 警告页与“强行访问”按钮生成
├── rewrite/
│   ├── adscript.go     # [广告拦截与注入] 从 repo 拉取 whitelist.json 与 ad_script.js，剥离源站广告并注入自有推广横幅
│   ├── rewrite.go      # [内容解压与重写] Gzip/Brotli/Deflate 解压重压、门户与原域名隔离重写
│   └── headers.go      # [响应头与 CORS] 全量 CORS 覆盖、重定向 HTTPS 升级
├── cookie/             # [Cookie 管理层] 受控 Cookie 加载、过期/登出清理与 Set-Cookie 改写
├── connect.go          # [CONNECT 本地 HTTPS 服务] HTTP CONNECT 鉴权、SSRF 拦截、并发限流与本地 TLS MITM 终结
├── portal.go           # [门户与自助端点] /proxy.pac、/ca.pem、/__ech_proxy__/ad_script.js、/debug/log、/statusz
├── proxy.go            # [核心反代流水线] 路由匹配、证书错误拦截转警告页、去广告与自有广告脚本注入
└── server.go           # [服务生命周期] 同端口 HTTP/CONNECT 与 HTTPS 自动嗅探分流、443 无权限平滑回退
win/
├── main.go             # [桌面端 CLI 入口] 子命令/参数解析、默认 ipmode=ipv4、早退/报错日志落盘与优雅退出清理
├── sysproxy.go         # [系统代理状态机] PAC / Global / Off 三态切换与退出自动还原
├── sysproxy_windows.go # [Windows 7~11 32/64 驱动] 注册表 + WinINet 32/64 位精确对齐刷新系统 PAC 与 certutil 安装 CA
├── tray.go             # [系统托盘控制器] 控制台显隐切换、托盘右键菜单命令分发
└── tray_windows.go     # [Windows 原生托盘] 纯 Go Win32 Shell_NotifyIconW、内置绘制图标与剪贴板
```

## 三、 编译与测试（Windows 7~11 32/64 位）

```bash
# 1. 运行全量单元测试与竞态检测
go test ./... -race -v

# 2. 编译 Windows 64 位 (Windows 7~11 x64)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ech-proxy-windows-amd64.exe ./win/

# 3. 编译 Windows 32 位 (Windows 7~11 x86)
GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ech-proxy-windows-386.exe ./win/
```
