#!/usr/bin/env bash
# scripts/build-android-lib.sh
#
# 构建 ECH Proxy 嵌入式库的 AAR（echproxy-android-<ver>.aar），供第三方
# Java/Kotlin App 通过 implementation files(...) 直接引用。
#
# 为什么不走 Android Gradle Plugin（com.android.library）：
#   AAR 本质是一个约定结构的 zip。本库的 Java 部分 EchProxy.java 只用
#   java.net.InetAddress（纯 JDK API，零 Android 依赖），用 javac 编进
#   classes.jar 即可；native 部分就是各 ABI 的 libechproxy.so。两者手工
#   组装成 AAR，既绕开 AGP/Gradle 版本地狱，又不需 android.jar。
#   产物结构与 AGP 产出完全一致，下游无感知。
#
# AAR 内部结构（zip）：
#   AndroidManifest.xml          库占位清单（package + <uses-sdk>）
#   classes.jar                  编译后的 EchProxy.class
#   jni/<abi>/libechproxy.so     Go 核心 + JNI 注册层（打包时自动进下游 APK）
#   R.txt                        空（本库无资源）
#
# 环境要求：
#   - Go（go.mod 要求 1.26.7）+ Android NDK（提供 aarch64/armv7/x86_64 clang 与 jni.h）
#   - JDK（javac/jar，任意 17+）
#   - 在仓库根目录执行（需要 android-lib/ 与 go.mod）
#
# 用法：
#   ./scripts/build-android-lib.sh [VERSION]
#   VERSION 缺省时取 git describe（去掉前导 v），失败则用 0.0.0
#   产物：dist/echproxy-android-<VERSION>.aar

set -euo pipefail

cd "$(dirname "$0")/.."   # 仓库根

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    VERSION="$(git describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.0.0)"
fi
[[ -n "$VERSION" ]] || VERSION="0.0.0"

echo "==> Building echproxy-android-${VERSION}.aar"

# ── 环境检查 ─────────────────────────────────────────────────────────────────

command -v go >/dev/null || { echo "ERROR: go not found in PATH" >&2; exit 1; }
command -v javac >/dev/null || { echo "ERROR: javac not found (need JDK)" >&2; exit 1; }
command -v jar >/dev/null || { echo "ERROR: jar not found (need JDK)" >&2; exit 1; }

: "${ANDROID_NDK_HOME:=}"
: "${ANDROID_NDK_ROOT:=}"
: "${ANDROID_HOME:=}"
: "${ANDROID_SDK_ROOT:=}"

NDK_CANDIDATES=(
    "$ANDROID_NDK_HOME"
    "$ANDROID_NDK_ROOT"
    "$ANDROID_HOME/ndk-bundle"
    "$ANDROID_SDK_ROOT/ndk-bundle"
)
NDK_ROOT=""
for c in "${NDK_CANDIDATES[@]}"; do
    if [[ -n "$c" && -d "$c" ]]; then
        NDK_ROOT="$c"
        break
    fi
done

# 自动探测 $ANDROID_HOME/ndk/<ver>
if [[ -z "$NDK_ROOT" && -n "${ANDROID_HOME:-}" && -d "$ANDROID_HOME/ndk" ]]; then
    latest="$(ls -1d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$latest" ]] && NDK_ROOT="$latest"
fi
if [[ -z "$NDK_ROOT" && -n "${ANDROID_SDK_ROOT:-}" && -d "$ANDROID_SDK_ROOT/ndk" ]]; then
    latest="$(ls -1d "$ANDROID_SDK_ROOT"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
    [[ -n "$latest" ]] && NDK_ROOT="$latest"
fi

if [[ -z "$NDK_ROOT" ]]; then
    echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME (or ANDROID_HOME/ndk/<ver>)." >&2
    exit 1
fi
export ANDROID_NDK_HOME="$NDK_ROOT"

TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [[ ! -d "$TOOLCHAIN" ]]; then
    echo "ERROR: NDK toolchain not found at $TOOLCHAIN" >&2
    exit 1
fi

# minSdk 21（与 android/app/build.gradle 一致）
API=21

echo "==> NDK: $NDK_ROOT"
echo "==> Go:  $(go version)"

# ── 输出目录 ─────────────────────────────────────────────────────────────────

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

AAR_STAGING="$WORK/aar"
JNI_DIR="$AAR_STAGING/jni"
mkdir -p "$JNI_DIR"

# ── 1. 各 ABI 编译 libechproxy.so ───────────────────────────────────────────

build_abi() {
    local abi="$1" goarch="$2" cc="$3"
    echo "==> [$abi] go build (GOARCH=$goarch)"
    mkdir -p "$JNI_DIR/$abi"
    CGO_ENABLED=1 \
    GOOS=android \
    GOARCH="$goarch" \
    CC="$TOOLCHAIN/$cc" \
    go build -buildmode=c-shared \
        -ldflags="-s -w" \
        -o "$JNI_DIR/$abi/libechproxy.so" \
        ./android-lib/go/
    ls -lh "$JNI_DIR/$abi/libechproxy.so"
}

# ⚠ 与 android/app/build.gradle 的 abiFilters 对齐。当前仅 arm64（真机主流）。
#    需要模拟器/老设备时按需追加 armeabi-v7a / x86_64 三行。
build_abi arm64-v8a arm64 aarch64-linux-android${API}-clang
# build_abi armeabi-v7a arm   armv7a-linux-androideabi${API}-clang
# build_abi x86_64       amd64 x86_64-linux-android${API}-clang

# ── 2. 编译 Java → classes.jar ─────────────────────────────────────────────

echo "==> javac EchProxy.java"
CLASSES="$WORK/classes"
mkdir -p "$CLASSES"
javac -release 8 \
    -d "$CLASSES" \
    android-lib/src/main/java/xyz/moonchan/echproxy/android/EchProxy.java

echo "==> jar classes.jar"
CLASSES_JAR="$AAR_STAGING/classes.jar"
(cd "$CLASSES" && jar cf "$CLASSES_JAR" .)
ls -lh "$CLASSES_JAR"

# ── 3. AndroidManifest.xml（库占位） ───────────────────────────────────────

cat > "$AAR_STAGING/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="xyz.moonchan.echproxy.android">
    <uses-sdk android:minSdkVersion="21" />
</manifest>
EOF

# ── 4. R.txt（无资源，空文件） ──────────────────────────────────────────────

: > "$AAR_STAGING/R.txt"

# ── 5. 组装 AAR（zip） ─────────────────────────────────────────────────────

OUT_DIR="dist"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/echproxy-android-${VERSION}.aar"

echo "==> packaging $OUT"
rm -f "$OUT"
(cd "$AAR_STAGING" && zip -qr "$OLDPWD/$OUT" \
    AndroidManifest.xml classes.jar R.txt jni)

# ── 6. 校验 + checksum ─────────────────────────────────────────────────────

echo "==> AAR contents:"
unzip -l "$OUT"

sha256sum "$OUT" > "$OUT.sha256"
echo "==> sha256: $(cut -d' ' -f1 "$OUT.sha256")"

echo "==> DONE: $OUT"
