// android/app/src/main/cpp/jni_wrapper.c
// JNI wrapper layer: Java native methods -> Go exported functions
//
// Go exported functions (//export):
//   StartProxy(char* bootstrapIP) -> uint16
//   StopProxy() -> void
//   GetProxyPort() -> uint16
//   IsEchReady() -> int
//   GetLogs() -> char*
//
// JNI function naming rule: Java_xyz_moonchan_echproxy_MainActivity_<method>

#include <jni.h>
#include <stdlib.h>
#include <string.h>

// Go exported function declarations (in libechproxy.so)
extern uint16_t StartProxy(const char* bootstrapIP);
extern void StopProxy(void);
extern uint16_t GetProxyPort(void);
extern int IsEchReady(void);
extern char* GetLogs(void);

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_MainActivity_StartProxy(
    JNIEnv *env,
    jobject thiz,
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
    jobject thiz) {

    StopProxy();
}

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_MainActivity_GetProxyPort(
    JNIEnv *env,
    jobject thiz) {

    uint16_t port = GetProxyPort();
    return (jint)port;
}

JNIEXPORT jint JNICALL
Java_xyz_moonchan_echproxy_MainActivity_IsEchReady(
    JNIEnv *env,
    jobject thiz) {

    return (jint)IsEchReady();
}

JNIEXPORT jstring JNICALL
Java_xyz_moonchan_echproxy_MainActivity_GetLogs(
    JNIEnv *env,
    jobject thiz) {

    char *logs = GetLogs();
    if (logs == NULL) {
        return NULL;
    }

    jstring result = (*env)->NewStringUTF(env, logs);
    free(logs);

    return result;
}

#ifdef __cplusplus
}
#endif
