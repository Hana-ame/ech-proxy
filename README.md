# ech-proxy

支持 **全自动无干预 SNI / ECH 透明反向代理**、**门户导航（`l.moonchan.xyz`）** 与 **Android / Flutter 集成** 的轻量级反向代理工具。

## 一、 核心工作原理

`ech-proxy` 采用双轨证书与全自动隧道分流设计：

1. **`l.moonchan.xyz` 相关域名（门户与代理子域）**：
   * 证书：使用 `upstream.json` 中配置的 `l.moonchan.xyz` 公网证书。
   * 行为：访问 `https://l.moonchan.xyz:8443/` 展示门户列表；访问 `*.l.moonchan.xyz`（如 `dlsite.l.moonchan.xyz`）自动映射至对应目标网站并执行响应体域名替换与 Service Worker 注入。
2. **除 `l.moonchan.xyz` 以外的所有域名（本地 `hosts -> 127.0.0.1` 透明反代模式）**：
   * **本地自签名 CA 动态签发证书**：只要通过修改系统 `hosts` 将目标域名（如 `pixiv.net`、`i.pximg.net`、`sukebei.nyaa.si` 或任意其他域名）指向 `127.0.0.1` 并安装一次本机生成的 `ca/ca.pem` 根证书，`ech-proxy` 会在 TLS 握手阶段自动为该域名签发带通配符与完整信任链（`fullchain.pem`）的证书。
   * **SNI / ECH 全自动无干预选择**：代理会自动通过 DoH 解析目标域名的真实 IP 并检测其是否属于 Cloudflare 网段：
     * **Cloudflare 站点（如 `pixiv.net`、`e-hentai.org`、`archiveofourown.org`、`dlsite.com`）**：自动通过 **Cloudflare ECH（Encrypted Client Hello）** 隧道转发。
     * **非 Cloudflare 站点（如 `i.pximg.net`、`s.pximg.net`、`sukebei.nyaa.si`）**：自动通过 **SNI 伪装直连**（同时兼容 HTTP/2 与 HTTP/1.1 源站）转发。
     * **无感故障回退**：若首选隧道连接失败或被边缘拒绝，自动无感切换至备选隧道并缓存成功路由，全程无需手动干预 `mode`。

## 二、 语义化模块架构 (#29)

代码库按职责划分为 6 个正交语义子包与 1 个顶层组装层，模块间无环形依赖：

```text
echproxy/
├── netdial/      # [基础网络模块] 公共 DNS 解析、IPv4/IPv6 协议族优选、Cloudflare CIDR 识别、文件拉取与重试（0 内部依赖）
├── config/       # [配置与路由模块] 解析 upstream.json，支持精确/泛域名匹配及任意非门户域名的自动透传（仅依赖 netdial）
├── certstore/    # [证书管理模块] 公网证书加载 + 本地自签 CA 生成与按需动态签发完整信任链证书（仅依赖 config, netdial）
├── cookie/       # [Cookie 管理模块] 受控 Cookie 加载、按域名的内存 CookieJar 与 Set-Cookie 域名改写（0 内部依赖）
├── rewrite/      # [内容重写模块] 解压/重压缩、域名替换、HTTP->HTTPS 强制升级、SW 脚本生成与 Header/CORS 处理（仅依赖 config）
├── ech/          # [传输隧道模块] Cloudflare ECH 隧道、SNI 伪装（H2/H1.1 双栈）与全自动无干预 RoundTrip 分发（仅依赖 netdial）
├── portal.go     # [顶层门户路由] l.moonchan.xyz 导航页渲染与 Gin 路由注册
├── proxy.go      # [顶层反代流水线] 串联路由解析、请求构造、自动隧道转发、自重定向熔断与响应重写
└── server.go     # [顶层服务管理] 统一管理服务生命周期与双轨 TLS 证书挂载
```

## 三、 本地透明反代使用步骤（以 Pixiv 为例）

### 步骤 1 — 启动 443 模式
将下载的可执行文件重命名为以 `.443.exe` 结尾（如 `ech-proxy.443.exe`），并以**管理员 / `root` 权限**运行（也可以不重命名，直接运行 `ech-proxy -local -addr 127.0.0.1:443`）：
```cmd
ech-proxy.443.exe
```

### 步骤 2 — 编辑系统 `hosts` 文件 (#18)
> **重要说明**：操作系统的 `hosts` 文件（Windows 位于 `C:\Windows\System32\drivers\etc\hosts`，Linux/macOS 位于 `/etc/hosts`）**不支持 `*.pixiv.net` 通配符语法**！必须将实际访问的子域名与图片 CDN 域名（`i.pximg.net` / `s.pximg.net`）逐行写入 `hosts`：

```hosts
# Pixiv 主站与子域名
127.0.0.1 pixiv.net
127.0.0.1 www.pixiv.net
127.0.0.1 accounts.pixiv.net
127.0.0.1 account.pixiv.net
127.0.0.1 api.sec.pixiv.net
127.0.0.1 manga.pixiv.net
127.0.0.1 novel.pixiv.net
127.0.0.1 dic.pixiv.net
127.0.0.1 fanbox.cc
127.0.0.1 www.fanbox.cc

# Pixiv 图片与静态资源 CDN（缺少这两项会导致图片裂开或样式丢失 #17 #18）
127.0.0.1 pximg.net
127.0.0.1 i.pximg.net
127.0.0.1 s.pximg.net
```
*(注：除 Pixiv 外，你也可以将任何其他需要代理的域名按 `127.0.0.1 <域名>` 格式加入 `hosts`，`ech-proxy` 会自动为其签发证书并自动选择 SNI/ECH 转发。)*

### 步骤 3 — 安装本地 CA 根证书与浏览器信任配置 (#21)
首次运行后，`ech-proxy` 会在程序所在目录（若不可写则位于 `%AppData%\ech-proxy\` 或 `~/.config/ech-proxy/`）生成 `ca/ca.pem`：

* **Windows（Chrome / Edge）**：右键点击 `ca\ca.pem` $ightarrow$ **安装证书** $ightarrow$ 选择 **本地计算机** $ightarrow$ 选择 **将所有的证书都放入下列存储** $ightarrow$ 浏览并选择 **受信任的根证书颁发机构** $ightarrow$ 完成并重启浏览器。
* **macOS（Safari / Chrome）**：打开“钥匙串访问”，将 `ca/ca.pem` 拖入 **系统** 钥匙串，双击打开 `"ech-proxy local CA"`，展开“信任”并将“使用此证书时”设为 **始终信任**。
* **Linux**：
  ```bash
  sudo cp ca/ca.pem /usr/local/share/ca-certificates/ech-proxy-ca.crt
  sudo update-ca-certificates
  ```
* **Firefox 浏览器专属配置（必看 #21）**：
  Firefox 默认使用内置的独立证书库，不会自动读取操作系统根证书库。请任选以下一种方式配置：
  1. **方式 A（推荐，自动信任系统根证书）**：在 Firefox 地址栏输入 `about:config` 回车，搜索 `security.enterprise_roots.enabled`，双击将其值切换为 **`true`**。
  2. **方式 B（手动导入 CA）**：打开 Firefox **设置** $ightarrow$ **隐私与安全** $ightarrow$ 滑到底部点击 **查看证书 (View Certificates)** $ightarrow$ 切换到 **证书颁发机构 (Authorities)** 标签页 $ightarrow$ 点击 **导入 (Import)**，选择 `ca/ca.pem`，勾选 **“信任由此证书颁发机构来标识网站”** 并确定。

## 四、 命令行参数与跨平台环境变量对照 (#27)

桌面端（`win/`）与 Android 端（`android/`）对齐了核心环境变量配置：

| 功能说明 | 桌面端 CLI 参数 | 跨平台环境变量（桌面端 + Android） | 默认值 |
| :--- | :--- | :--- | :--- |
| 本地透明反代模式 | `-local` | （通过 `.443.exe` 后缀或 `-local` 开启） | `false`（`.443.exe` 为 `true`） |
| 监听地址与端口 | `-addr` | — | `127.0.0.1:8443` / `127.0.0.1:443` |
| 上游配置文件路径/URL | `-config` | `ECH_PROXY_CONFIG` | 默认远程 GitHub URL |
| 锁定上游出口协议族 | `-ip-mode` | `IP_MODE`（`v4` 或 `v6`） | 自动（`pixiv`/`pximg` 已内置 `v4`） |
| DoH 引导 IP | `-local-ip` | `LOCALIP` | 空 |
| 本地 CA 存储目录 | `-data-dir` | `ECH_PROXY_DATA_DIR` | 程序所在目录（或系统用户配置目录） |
| 纯 HTTP 模式 | `-http` | — | `false` |
| 详细请求日志 | `-v` | — | `false`（Android 默认开启） |

## 五、 编译构建

```bash
# 1. 运行全量测试（包含 upstream.json 校验）
go test ./... -v

# 2. 编译桌面端常规版本
go build -trimpath -ldflags="-s -w" -o ech-proxy ./win/

# 3. 编译 Windows 443 本地透明反代版本
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ech-proxy.443.exe ./win/
```
