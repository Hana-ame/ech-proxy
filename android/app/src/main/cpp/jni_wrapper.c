// android/app/src/main/cpp/jni_wrapper.c
// JNI wrapper layer: Java native methods -> Go exported functions

#include <jni.h>
#include <stdlib.h>
#include <string.h>

// Go exported function declarations (in libechproxy.so)
extern uint16_t StartProxy(const char* bootstrapIP);
extern void StopProxy(void);
extern uint16_t GetProxyPort(void);
extern int IsEchReady(void);
extern char* GetLogs(void);
extern void FreeCString(char* s);

#ifdef __cplusplus
extern "C" {
#endif

// --- MainActivity native methods ---

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_MainActivity_StartProxy(
    JNIEnv *env,
    jclass clazz,
    jstring bootstrapIP) {

    const char *ipStr = NULL;
    if (bootstrapIP != NULL) {
        ipStr = (*env)->GetStringUTFChars(env, bootstrapIP, NULL);
    }

    uint16_t port = StartProxy(ipStr);

    if (ipStr != NULL) {
        (*env)->ReleaseStringUTFChars(env, bootstrapIP, ipStr);
    }

    return (jint)port;
}

JNIEXPORT void JNICALL
Java_xyz_moonchan_echproxy_MainActivity_StopProxy(
    JNIEnv *env,
    jclass clazz) {

    StopProxy();
}

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_MainActivity_GetProxyPort(
    JNIEnv *env,
    jclass clazz) {

    uint16_t port = GetProxyPort();
    return (jint)port;
}

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_MainActivity_IsEchReady(
    JNIEnv *env,
    jclass clazz) {

    return (jint)IsEchReady();
}

JNIEXPORT jstring JNICALL
Java_xyz_moonchan_echproxy_MainActivity_GetLogs(
    JNIEnv *env,
    jclass clazz) {

    char *logs = GetLogs();
    if (logs == NULL) {
        return NULL;
    }

    jstring result = (*env)->NewStringUTF(env, logs);
    FreeCString(logs);

    return result;
}

// --- ProxyService native methods (forwarding aliases) ---

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_ProxyService_StartProxy(
    JNIEnv *env,
    jclass clazz,
    jstring bootstrapIP) {

    return Java_xyz_moonchan_echproxy_MainActivity_StartProxy(env, clazz, bootstrapIP);
}

JNIEXPORT void JNICALL
Java_xyz_moonchan_echproxy_ProxyService_StopProxy(
    JNIEnv *env,
    jclass clazz) {

    StopProxy();
}

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_ProxyService_GetProxyPort(
    JNIEnv *env,
    jclass clazz) {

    return (jint)GetProxyPort();
}

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_ProxyService_IsEchReady(
    JNIEnv *env,
    jclass clazz) {

    return (jint)IsEchReady();
}

JNIEXPORT jstring JNICALL
Java_xyz_moonchan_echproxy_ProxyService_GetLogs(
    JNIEnv *env,
    jclass clazz) {

    return Java_xyz_moonchan_echproxy_MainActivity_GetLogs(env, clazz);
}

#ifdef __cplusplus
}
#endif
