#!/usr/bin/env bash
# scripts/downgrade-go1214.sh
# 备选方案：若不使用 XTLS/go-win7 补丁版 SDK，而是强制使用 Go 官方原版编译器支持 Windows 7，
# 则必须降级至 Go 1.21.4（1.21.5 引入 bcryptprimitives.dll!ProcessPrng 之前的最后一个官方版本）或 Go 1.20.14。
# 注意：官方原版降级需要同步回退 go.mod 中要求高版本 Go 的第三方依赖（如 golang.org/x/*、gin、utls）。

set -euo pipefail

WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORK_DIR"

echo "Switching go.mod to official Go 1.21.4 compatible baseline..."
go mod edit -go=1.21.4
go get \
  github.com/gin-gonic/gin@v1.10.0 \
  github.com/refraction-networking/utls@v1.6.7 \
  github.com/klauspost/compress@v1.17.9 \
  github.com/andybalholm/brotli@v1.1.0 \
  golang.org/x/net@v0.28.0 \
  golang.org/x/sys@v0.24.0 \
  golang.org/x/crypto@v0.26.0 \
  golang.org/x/text@v0.17.0
go mod tidy
echo "go.mod & go.sum updated for stock Go 1.21.4."
