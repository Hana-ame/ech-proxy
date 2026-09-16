# ech-proxy

ECH (Encrypted Client Hello) 代理，支持多上游路由和 Android APK 部署。

## 功能

- **多上游支持**：twimg、exhentai、iwara、dlsite、sukebei、ao3 等
- **两种模式**：ECH 域前置、SNI 伪装直连
- **Android APK**：编译为 c-shared 库，集成到 Android App
- **通配符路由**：如 `iwara-xxx.l.moonchan.xyz` → `xxx.iwara.tv`
- **Cookie 注入**：支持固定 Cookie（exhentai 登录态）
- **响应重写**：URL 重写、Service Worker 注入

## 构建

### Go 二进制 (Windows / Linux)

```bash
go build -o ech-proxy ./win/
```

### Android APK

```bash
# 1. 编译 Go 动态库 (需要 Android NDK r27)
cd android
GOOS=android GOARCH=arm64 CC=aarch64-linux-android21-clang \
  go build -buildmode=c-shared -o app/src/main/jniLibs/arm64-v8a/libechproxy.so .

# 2. 打包 APK
./gradlew assembleRelease
```

## 配置

上游配置位于 `certs/l.moonchan.xyz/upstream.json`，运行时从 GitHub `main`
分支远程加载（经 `proxy.moonchan.xyz` 转发到 `raw.githubusercontent.com`）。
不锁定 commit/tag，main 分支变更会直接影响线上代理行为。

### 规则核心机制：`rewrites` vs `body_replace` vs `sw_inject`

为避免配置混淆，响应重写与 Service Worker 的协作职责划分如下：

| 配置项 | 语法格式 | 作用范围 | 核心机制与使用场景 |
| :--- | :--- | :--- | :--- |
| **`rewrites`** | `{"target.com": "local.proxy"}` | **Body + sw.js (双重生效)** | **域名级别映射**。<br>1. **静态 Body 替换**：将 HTML、JS、JSON、XML 及响应头 (`Location`/`Refresh`) 中的 `target.com` 替换为本地代理域名（自动附带当前监听端口）。<br>2. **Service Worker 动态拦截**：在开启 `sw_inject` 时，`rewrites` 的全部映射对会自动注入到浏览器端 `sw.js` 的 `__swMap` 中，用于在浏览器网络层实时拦截前端 JS 运行时动态拼接的请求（静态正则替换顾及不到的动态 URL，如 DLsite 图片 CDN）。 |
| **`body_replace`** | `[["old", "new"]]`<br>`[{"replace": ["old", "new"]}]` | **仅 Body (单向生效)** | **通用文本与正则替换**。<br>专门用于响应正文内容的精准文本替换或正则匹配（如特定脚本地址、版本号、内联代码微调等）。<br>**注意**：`body_replace` 绝对**不会**进入 `sw.js`，避免正则或非域名文本污染 Service Worker 的路由判定。 |
| **`sw_inject`** | `true` / `false` | **HTML 注册 + sw.js** | **Service Worker 注入开关**。<br>用于自身没有 Service Worker 的站点（如 DLsite）。开启后代理会在返回的 HTML 中自动注入 `/sw.js` 注册代码，并在请求 `/sw.js` 时动态输出包含 `rewrites` 映射与 `blocked_hosts` 拦截规则的脚本。<br>（**警告**：对于自带 Workbox 等 Service Worker 的站点如 Iwara 绝不能开启，避免冲突覆盖）。 |

### 示例

```json
{
    "upstreams": {
        "dlsite.l.moonchan.xyz": {
            "host": "www.dlsite.com",
            "referer": "https://www.dlsite.com/",
            "sw_inject": true,
            "rewrites": {
                "www.dlsite.com": "dlsite.l.moonchan.xyz",
                "img.dlsite.jp": "dlsite-img.l.moonchan.xyz"
            },
            "body_replace": [
                ["https://old-cdn.com/lib.js", "https://new-cdn.com/lib.js"],
                {"replace": ["v[0-9]+\\.[0-9]+", "v2.0"]}
            ]
        }
    }
}
```

**SSL 证书完全公开**：`certs/l.moonchan.xyz/fullchain.cer` 与 `privkey.pem`
都提交在仓库内（`wintools` 仓库存有同一份，两仓库均 public），桌面版运行时
直接从公开地址拉取证书 + 私钥。Let's Encrypt 证书浏览器天然信任，任何拿到该
私钥的人都能对 `*.l.moonchan.xyz` 做浏览器可信的 TLS 终止 —— 这是刻意的
（见 `d23da9b`），不是泄漏。

唯一例外是 Android APK 签名密钥（`release.keystore`），仍走 GitHub Secrets。

## GitHub Actions

- `go.yml`：Go 单元测试
- `ech-proxy.yml`：Go 二进制构建
- `ech-proxy-android.yml`：Android APK 构建
- `release.yml`：Release 发布
