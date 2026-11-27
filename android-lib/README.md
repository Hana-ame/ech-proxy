# echproxy-android（嵌入式 AAR 库）

把 ECH 代理核心打包成 Android AAR，供**第三方 Java/Kotlin App** 通过一行依赖直接引用。
下游无需接触 Go、无需 Android NDK、无需写 JNI。

> 这与 [`android/`](../android/)（自成一体的代理 APK）是两个东西：
> `android/` 产出**能装的 App**；本目录产出**给别的 App 当库用的 `.aar`**。

---

## 下游接入

### 1. 放入 AAR

从 [Releases](https://github.com/Hana-ame/ech-proxy/releases) 下载
`echproxy-android-<ver>.aar`，放进你 App 的 `app/libs/`。

```
your-app/app/libs/echproxy-android-3.6.1.aar
```

### 2. 加依赖

`app/build.gradle`（Groovy）：

```groovy
dependencies {
    implementation files("libs/echproxy-android-3.6.1.aar")
}
```

或 `app/build.gradle.kts`（Kotlin DSL）：

```kotlin
dependencies {
    implementation(files("libs/echproxy-android-3.6.1.aar"))
}
```

### 3. 调用

```kotlin
import xyz.moonchan.echproxy.android.EchProxy

// 启动（ECH 探测约 25~35s，务必在工作线程调，别在主线程）
thread {
    val port = EchProxy.start()          // 内部解析 moonchan.xyz 取引导 IP
    if (port > 0) {
        // 把你的 WebView / OkHttp / ExoPlayer 的代理指到 127.0.0.1:port
    }
}

// 查状态
val ready = EchProxy.isReady()
val port  = EchProxy.getPort()
val logs  = EchProxy.getLogs()

// 停止
EchProxy.stop()
```

**JNI 已动态注册**（`JNI_OnLoad` + `RegisterNatives`），与你的包名无关——任意
App 引入即用，不会 `UnsatisfiedLinkError`。

---

## 公共 API

`xyz.moonchan.echproxy.android.EchProxy`

| 方法 | 返回 | 说明 |
|---|---|---|
| `start(bootstrapIp: String?)` | `int` | 启动代理，返回监听端口；**0 = 失败**。传 `null` 走环境兜底 |
| `start()` | `int` | 便捷重载，内部解析 `moonchan.xyz` 取引导 IP |
| `stop()` | `void` | 停止并释放监听，幂等 |
| `getPort()` | `int` | 当前端口；未运行时 0 |
| `isReady()` | `boolean` | ECH 就绪且端口有人在听 |
| `getLogs()` | `String` | 最近日志（≤500 行），已释放 native 内存 |
| `resolveBootstrapIp()` | `String?` | 解析 `moonchan.xyz` 的首个 IPv4 |

监听形态：本机回环 `127.0.0.1`，端口优先 8443、被占则随机。

---

## AAR 内部结构

```
echproxy-android-<ver>.aar
├── AndroidManifest.xml        库占位（package=xyz.moonchan.echproxy.android, minSdk 21）
├── classes.jar                EchProxy.class
├── jni/arm64-v8a/libechproxy.so   Go 核心 + JNI 注册层
└── R.txt                      空（无资源）
```

下游打包时，`jni/<abi>/libechproxy.so` 会被自动并进最终 APK，调用方零感知。

---

## 本仓库维护

- Go 导出层：[`android-lib/go/main.go`](../android-lib/go/main.go)（包装 `echproxy` 核心）
- JNI 动态注册：[`android-lib/go/jni_onload_android.c`](../android-lib/go/jni_onload_android.c)
- Java API：[`android-lib/src/main/java/.../EchProxy.java`](../android-lib/src/main/java/xyz/moonchan/echproxy/android/EchProxy.java)
- 打包脚本：[`scripts/build-android-lib.sh`](../scripts/build-android-lib.sh)
- CI：`.github/workflows/ech-proxy-lib.yml`（手动或 tag push，产物挂 Release）

**ABI**：当前仅 `arm64-v8a`（与 `android/app` 一致，真机主流）。需要模拟器 /
老设备时，在 `scripts/build-android-lib.sh` 里解开 `armeabi-v7a` / `x86_64` 两行。

**与 `android/` 的同步**：`android-lib/go/main.go` 与 `android/main.go` 包装同一
`echproxy` 核心、导出同一组函数，仅 JNI 绑定方式不同（静态 vs 动态）。改核心
调用逻辑时两处需同步；长期可让 `android/` 也复用本层以消除重复。
