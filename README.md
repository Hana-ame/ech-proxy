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

上游配置位于 `certs/l.moonchan.xyz/upstream.json`，从 GitHub 远程加载。

证书依赖 `wintools` 仓库（私钥不公开）。

## GitHub Actions

- `go.yml`：Go 单元测试
- `ech-proxy.yml`：Go 二进制构建
- `ech-proxy-android.yml`：Android APK 构建
- `release.yml`：Release 发布
