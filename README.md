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

### Go 二进制

```bash
go build -o ech-proxy ./cmd/ech-proxy/
```

### Android APK

```bash
# 需要 Android NDK r27
GOOS=android GOARCH=arm64 CC=aarch64-linux-android21-clang \
  go build -buildmode=c-shared -o cmd/ech-proxy-android/libechproxy.so \
  ./cmd/ech-proxy-android/

cd cmd/ech-proxy-android/android
./gradlew assembleRelease
```

## 配置

上游配置位于 `certs/l.moonchan.xyz/upstream.json`，运行时从 GitHub `main`
分支远程加载（经 `proxy.moonchan.xyz` 转发到 `raw.githubusercontent.com`）。
不锁定 commit/tag，main 分支变更会直接影响线上代理行为。

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
