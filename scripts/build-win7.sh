#!/usr/bin/env bash
# scripts/build-win7.sh
# 借鉴 XTLS/Xray-core 的 Windows 7 构建方案：
# 使用 XTLS/go-win7 (patched-1.26.7) 编译同时兼容 Windows 7 ~ 11 (386 / amd64) 的可执行文件，
# 保留完整的 uTLS v1.8.2 ECH 支持，同时避免官方 Go 1.21.5+ 因缺失 bcryptprimitives.dll!ProcessPrng
# 在 Windows 7 启动阶段触发 Exception 0xc0000005 (PC=0x0 in asmstdcall)。

set -euo pipefail

WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_DIR="${GO_WIN7_DIR:-/tmp/go-win7-sdk}"
PATCHED_TAG="${GO_WIN7_TAG:-patched-1.26.7}"

HOST_OS="$(uname -s | tr "[:upper:]" "[:lower:]")"
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_ARCH="amd64" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
esac

if [ ! -x "$TOOLCHAIN_DIR/bin/go" ]; then
  echo "[1/3] Downloading XTLS/go-win7 ($PATCHED_TAG) for ${HOST_OS}-${HOST_ARCH}..."
  mkdir -p "$TOOLCHAIN_DIR"
  ZIP_PATH="/tmp/go-for-win7-${HOST_OS}-${HOST_ARCH}.zip"
  curl -fsSL -o "$ZIP_PATH" "https://github.com/XTLS/go-win7/releases/download/${PATCHED_TAG}/go-for-win7-${HOST_OS}-${HOST_ARCH}.zip" \
    || curl -fsSL -o "$ZIP_PATH" "https://github.com/XTLS/go-win7/releases/latest/download/go-for-win7-${HOST_OS}-${HOST_ARCH}.zip"
  rm -rf "$TOOLCHAIN_DIR"/*
  unzip -q "$ZIP_PATH" -d "$TOOLCHAIN_DIR"
  GO_BIN="$(find "$TOOLCHAIN_DIR" -type f -name go -perm -u+x | head -n1)"
  if [ -z "$GO_BIN" ]; then
    echo "Error: go binary not found in archive" >&2
    exit 1
  fi
  REAL_ROOT="$(dirname "$(dirname "$GO_BIN")")"
  if [ "$REAL_ROOT" != "$TOOLCHAIN_DIR" ]; then
    mv "$REAL_ROOT"/* "$TOOLCHAIN_DIR"/
  fi
fi

export GOROOT="$TOOLCHAIN_DIR"
export PATH="$GOROOT/bin:$PATH"
export GOTOOLCHAIN=local

echo "[2/3] Using toolchain: $(go version)"
cd "$WORK_DIR"
mkdir -p dist

echo "[3/3] Building Windows 7 ~ 11 compatible binaries (386 / amd64 / 443)..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/ech-proxy-windows-amd64.exe ./win/
GOOS=windows GOARCH=386   CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/ech-proxy-windows-386.exe ./win/
cp dist/ech-proxy-windows-amd64.exe dist/ech-proxy.443.exe
cp dist/ech-proxy-windows-386.exe   dist/ech-proxy-386.443.exe

echo "Done! Output binaries in dist/:"
ls -lh dist/
