// android-lib/go/jni_onload.c
//
// ECH Proxy 嵌入式库（AAR）的 JNI 动态注册层。
//
// 为什么不用静态 JNI（Java_xyz_moonchan_..._*）：静态 JNI 的函数名把「调用方的
// Java 包名 + 类名」编进了符号名。android/app 内建版可以用它（包名固定为
// xyz.moonchan.echproxy.MainActivity），但库要给**任意包名**的第三方 App 引用，
// 静态名必然对不上 → UnsatisfiedLinkError。
//
// 解法：JNI_OnLoad + RegisterNatives。JVM 加载 libechproxy.so 时回调 JNI_OnLoad，
// 在这里把 Go 导出函数动态绑到固定类 xyz.moonchan.echproxy.android.EchProxy 上，
// 与下游 App 自己的包名无关。下游只需 System.loadLibrary("echproxy")。
//
// Go 用 //export 导出的符号是 C ABI，直接 dlsym 取地址（避开 cgo 的
// _cgo_export.h，后者对 JNI 类型不可用）。
//
// 链接：本文件由 go build -buildmode=c-shared 一并编入 libechproxy.so（同目录
// .c 文件被 cgo 自动编译）。需要 jni.h —— Android NDK sysroot 自带，无需额外 include。

#include <jni.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

// Go //export 出来的 C 符号（见 main.go）
typedef unsigned short go_uint16;
extern go_uint16 StartProxy(const char *bootstrapIP);
extern void StopProxy(void);
extern go_uint16 GetProxyPort(void);
extern int IsEchReady(void);
extern char *GetLogs(void);
extern void FreeCString(char *s);

// ── JNI 方法实现：Java 调用 → Go 导出 ───────────────────────────────────────

static jint JNICALL
startProxyImpl(JNIEnv *env, jclass clazz, jstring bootstrapIP) {
    const char *ipStr = NULL;
    if (bootstrapIP != NULL) {
        ipStr = (*env)->GetStringUTFChars(env, bootstrapIP, NULL);
    }

    go_uint16 port = StartProxy(ipStr);

    if (ipStr != NULL) {
        (*env)->ReleaseStringUTFChars(env, bootstrapIP, ipStr);
    }

    return (jint)port;
}

static void JNICALL
stopProxyImpl(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    StopProxy();
}

static jint JNICALL
getProxyPortImpl(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return (jint)GetProxyPort();
}

static jint JNICALL
isEchReadyImpl(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return (jint)IsEchReady();
}

static jstring JNICALL
getLogsImpl(JNIEnv *env, jclass clazz) {
    (void)clazz;
    char *logs = GetLogs();
    if (logs == NULL) {
        return NULL;
    }

    jstring result = (*env)->NewStringUTF(env, logs);
    FreeCString(logs);

    return result;
}

static void JNICALL
freeCStringImpl(JNIEnv *env, jclass clazz, jstring s) {
    (void)env;
    (void)clazz;
    (void)s;
    // Java 侧拿到的是已拷贝成 jstring 的副本，native 内存已在 getLogsImpl 释放。
    // 保留此方法以匹配 Java 声明，避免签名漂移。
}

// ── 方法表：名字 / 签名 / 实现 ──────────────────────────────────────────────
// 签名要和 EchProxy.java 的 native 声明严格一致，否则 RegisterNatives 失败。

static JNINativeMethod methods[] = {
    {"nativeStartProxy", "(Ljava/lang/String;)I", (void *)&startProxyImpl},
    {"nativeStopProxy", "()V", (void *)&stopProxyImpl},
    {"nativeGetProxyPort", "()I", (void *)&getProxyPortImpl},
    {"nativeIsEchReady", "()I", (void *)&isEchReadyImpl},
    {"nativeGetLogs", "()Ljava/lang/String;", (void *)&getLogsImpl},
    {"nativeFreeCString", "(Ljava/lang/String;)V", (void *)&freeCStringImpl},
};

static const int methodsCount = sizeof(methods) / sizeof(methods[0]);

static const char *kClassPath = "xyz/moonchan/echproxy/android/EchProxy";

// ── 入口：JVM 加载 .so 时回调 ───────────────────────────────────────────────

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;

    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        return JNI_ERR;
    }

    jclass cls = (*env)->FindClass(env, kClassPath);
    if (cls == NULL) {
        // 下游没把 AAR 的 EchProxy.class 打进 APK —— 通常意味着没正确依赖 AAR。
        return JNI_ERR;
    }

    if ((*env)->RegisterNatives(env, cls, methods, methodsCount) != JNI_OK) {
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}
