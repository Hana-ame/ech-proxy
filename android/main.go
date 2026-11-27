package main

// #include <stdlib.h>
import "C"

import (
	"context"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

var (
	proxyMu     sync.Mutex
	proxyServer *echproxy.Server
	echReady    bool
	proxyGen    uint64

	logMu       sync.RWMutex
	logBuffer   []string
	maxLogLines = 500
)

type logWriter struct{}

func (w *logWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\n")
	logMu.Lock()
	logBuffer = append(logBuffer, line)
	if len(logBuffer) > maxLogLines {
		logBuffer = logBuffer[len(logBuffer)-maxLogLines:]
	}
	logMu.Unlock()
	return len(p), nil
}

func init() {
	log.SetOutput(&logWriter{})
	log.SetFlags(log.Ltime | log.Lmicroseconds)
}

//export StartProxy
func StartProxy(bootstrapIP *C.char) uint16 {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in StartProxy: %v\n%s", r, debug.Stack())
		}
	}()

	proxyMu.Lock()
	proxyGen++
	myGen := proxyGen

	logMu.Lock()
	logBuffer = nil
	logMu.Unlock()
	log.Println("=== Starting full ech-proxy (8443 Portal Scheme) ===")

	if proxyServer != nil {
		_ = proxyServer.Close()
		proxyServer = nil
	}
	echReady = false
	echproxy.Debug = true
	proxyMu.Unlock()

	bootstrap := strings.TrimSpace(C.GoString(bootstrapIP))
	if bootstrap == "" {
		bootstrap = os.Getenv("LOCALIP")
	}
	allowConnect := os.Getenv("ECH_PROXY_ALLOW_CONNECT") == "1"

	// 手机 App 只与 8443 方案有关（PortalMode: true，加载 upstream.json 与真实公网证书）
	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:            "127.0.0.1:8443",
		AllowRandomPort: true,
		PortalMode:      true,
		ConfigURL:       os.Getenv("ECH_PROXY_CONFIG"),
		BootstrapIP:     bootstrap,
		IPMode:          os.Getenv("IP_MODE"),
		DataDir:         os.Getenv("ECH_PROXY_DATA_DIR"),
		AllowConnect:    allowConnect,
		DisableConnect:  !allowConnect,
		Auth:            echproxy.AuthConfigFromEnv(),
	})
	if err != nil {
		log.Printf("Server init failed: %v", err)
		return 0
	}

	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxyGen != myGen {
		_ = srv.Close()
		log.Printf("StartProxy aborted: stopped during initialization")
		return 0
	}

	if err := srv.ServeAsync(); err != nil {
		_ = srv.Close()
		log.Printf("Serve failed: %v", err)
		return 0
	}

	proxyServer = srv
	echReady = true
	log.Printf("Proxy started on port %d", srv.Port)
	return srv.Port
}

//export StopProxy
func StopProxy() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in StopProxy: %v\n%s", r, debug.Stack())
		}
	}()

	// 锁内只做「摘引用 + 清状态」，Shutdown 必须放到锁外。
	// Shutdown 会等活跃连接收尾，最长 5 秒。原先持着 proxyMu 调用它，这 5 秒里
	// GetProxyPort / IsEchReady（MainActivity.java:104/190 在 **UI 线程**上同步
	// 调用，jni_wrapper.c 只是直接转发）全部卡在 Lock 上 → 主线程阻塞 → ANR。
	// 反过来，StopProxy 的调用点（MainActivity.stopProxy / ProxyService.
	// stopProxyInternal）本身都在 new Thread 里，慢的是锁、不是调用线程。
	proxyMu.Lock()
	proxyGen++
	srv := proxyServer
	proxyServer = nil
	echReady = false
	proxyMu.Unlock()

	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Proxy shutdown: %v", err)
	} else {
		log.Printf("Proxy stopped")
	}
}

//export GetProxyPort
func GetProxyPort() uint16 {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in GetProxyPort: %v", r)
		}
	}()

	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxyServer != nil {
		return proxyServer.Port
	}
	return 0
}

//export IsEchReady
func IsEchReady() C.int {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in IsEchReady: %v", r)
		}
	}()

	proxyMu.Lock()
	defer proxyMu.Unlock()
	if echReady {
		return 1
	}
	return 0
}

//export GetLogs
func GetLogs() *C.char {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in GetLogs: %v", r)
		}
	}()

	logMu.RLock()
	joined := strings.Join(logBuffer, "\n")
	logMu.RUnlock()

	return C.CString(sanitizeForJNI(joined))
}

//export FreeCString
func FreeCString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// appendModifiedUTF8 按 JNI 的 Modified UTF-8（JVM 规范 §4.4.7，即 CESU-8）
// 追加一个 UTF-16 码元：1 字节（<0x80）、2 字节（<0x800）、3 字节（其余，
// 含 0xD800–0xDFFF 的代理码元，它们是合法的三字节序列）。
func appendModifiedUTF8(b *strings.Builder, u rune) {
	switch {
	case u < 0x80:
		b.WriteByte(byte(u))
	case u < 0x800:
		b.WriteByte(byte(0xC0 | u>>6))
		b.WriteByte(byte(0x80 | u&0x3F))
	default:
		b.WriteByte(byte(0xE0 | u>>12))
		b.WriteByte(byte(0x80 | (u>>6)&0x3F))
		b.WriteByte(byte(0x80 | u&0x3F))
	}
}

// sanitizeForJNI 把 Go 字符串转成 JNI 的 Modified UTF-8。
//
// 为什么要转换而不是原样返回：这些字节最终交给 jni_wrapper.c 的
// `NewStringUTF`（jni_wrapper.c:77），它要求的不是标准 UTF-8，而是
// Modified UTF-8 —— 增补平面字符必须拆成**代理对、每个代理各三字节**
// （CESU-8），4 字节序列在那边是非法输入。
//
// 原实现写的是 `r1, r2 := utf16.EncodeRune(r); b.WriteRune(r1); b.WriteRune(r2)`：
// strings.Builder.WriteRune 走 utf8.EncodeRune，而代理码点 0xD800–0xDFFF 在
// UTF-8 里非法，会被替换成 U+FFFD —— 于是日志里每个 emoji 都变成 "��"。
// 这里改成手工写三字节，代理码元不再经过 utf8 编码器。
func sanitizeForJNI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0 {
			// Modified UTF-8 用 0xC0 0x80 表示 U+0000（0x00 会截断 C 串）。
			// 日志里出现 NUL 本就反常，丢弃比塞进去更安全。
			continue
		}
		if r <= 0xFFFF {
			appendModifiedUTF8(&b, r)
			continue
		}
		r1, r2 := utf16.EncodeRune(r)
		appendModifiedUTF8(&b, r1)
		appendModifiedUTF8(&b, r2)
	}
	return b.String()
}

func main() {}
