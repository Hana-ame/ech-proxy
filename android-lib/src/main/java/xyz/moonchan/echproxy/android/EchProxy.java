package xyz.moonchan.echproxy.android;

import java.net.InetAddress;

/**
 * ECH Proxy 嵌入式库的公共 API（供第三方 Android App 通过 AAR 引用）。
 *
 * <p>下游只需把 {@code echproxy-android-<ver>.aar} 放进 {@code app/libs/} 并
 * {@code implementation files("libs/echproxy-android-<ver>.aar")}，即可在任意包名的
 * App 里直接调用本类——JNI 通过 {@code JNI_OnLoad} + {@code RegisterNatives} 在运行时
 * 注册，<b>与调用方的 Java 包名无关</b>（这是它与 android/app 内建版
 * {@code MainActivity.StartProxy} 静态绑定的本质区别）。
 *
 * <p>加载：首次调用任意方法时通过 {@link System#loadLibrary} 加载
 * {@code libechproxy.so}（Go 核心 + 本库的 JNI 注册层编译在同一 .so 里，
 * 下游无需单独携带 jni-wrapper）。
 *
 * <p>线程模型：所有方法均可从任意线程调用，内部已加锁；{@link #start} 的 ECH
 * 探测耗时约 25~35s，<b>不要在主线程同步调用</b>，请在工作线程里调（与
 * android/app 的 Lite 模式一致）。
 *
 * <p>监听形态：本库只在本机回环地址 {@code 127.0.0.1} 上开明文 HTTP 代理，
 * 端口优先 8443、被占则随机。调用方拿到端口后自行决定如何使用（例如给
 * WebView / OkHttp / ExoPlayer 配 {@code 127.0.0.1:<port>} 代理）。
 */
public final class EchProxy {

    private static volatile boolean loaded = false;

    private EchProxy() {}

    /** 幂等加载 native 库；重复调用安全。 */
    private static synchronized void ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("echproxy");
            loaded = true;
        }
    }

    // ── native 方法（由 JNI_OnLoad/RegisterNatives 绑定到 libechproxy.so 的 Go 导出） ──

    private static native int nativeStartProxy(String bootstrapIP);

    private static native void nativeStopProxy();

    private static native int nativeGetProxyPort();

    private static native int nativeIsEchReady();

    private static native String nativeGetLogs();

    private static native void nativeFreeCString(String s);

    // ── 公共 API ─────────────────────────────────────────────────────────────

    /**
     * 启动代理。ECH 探测约 25~35s，<b>务必在工作线程调用</b>。
     *
     * @param bootstrapIP 连接 DoH 用的引导 IP；传 {@code null} 时由库内部按环境兜底。
     *                    想让库自己解析 moonchan.xyz 拿 IP，用 {@link #start()}。
     * @return 监听端口；0 表示启动失败（探测失败 / 端口无法绑定 / 期间被 stop）。
     */
    public static int start(String bootstrapIP) {
        ensureLoaded();
        return nativeStartProxy(bootstrapIP);
    }

    /** 便捷重载：库内部解析 moonchan.xyz 取 IPv4 作为引导 IP。 */
    public static int start() {
        return start(resolveBootstrapIp());
    }

    /** 停止代理并释放监听。幂等。 */
    public static void stop() {
        ensureLoaded();
        nativeStopProxy();
    }

    /**
     * @return 当前监听端口；代理未运行时为 0。
     */
    public static int getPort() {
        ensureLoaded();
        return nativeGetProxyPort();
    }

    /**
     * @return true 表示 ECH 隧道已就绪且端口有人在听。
     */
    public static boolean isReady() {
        ensureLoaded();
        return nativeIsEchReady() == 1;
    }

    /**
     * @return 最近日志的拼接文本（最多 500 行）；无日志时为空串。返回的是 Java
     *         String，native 侧内存已由库内部释放，调用方无需再 free。
     */
    public static String getLogs() {
        ensureLoaded();
        String s = nativeGetLogs();
        return s == null ? "" : s;
    }

    /**
     * 解析 moonchan.xyz 的首个 IPv4 地址，作为 ECH 引导 IP。
     *
     * @return IPv4 字符串；解析失败返回 {@code null}（此时应改用带显式 IP 的 {@link #start(String)}）。
     */
    public static String resolveBootstrapIp() {
        try {
            InetAddress[] addresses = InetAddress.getAllByName("moonchan.xyz");
            for (InetAddress addr : addresses) {
                String host = addr.getHostAddress();
                if (host != null && !host.contains(":")) {
                    return host;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }
}
