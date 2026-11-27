// android-lib/go/main.go
//
// ECH Proxy 嵌入式库（AAR）的 Go c-shared 导出层。
//
// 与 android/main.go 的关系：两者都包装同一个 echproxy 核心（echproxy.Server，
// 8443 Portal 方案），导出同一组函数。差别只在 JNI 绑定方式：
//
//   - android/main.go（App 内建）：靠 android/app/src/main/cpp/jni_wrapper.c
//     的静态 JNI 名（Java_xyz_moonchan_echproxy_MainActivity_*），写死了 App
//     自己的包名 —— 只能给自己用。
//   - android-lib/go/main.go（本文件，库）：靠 jni_onload.c 的 JNI_OnLoad +
//     RegisterNatives 在运行时把函数绑到 xyz/moonchan/echproxy/android/EchProxy，
//     与下游 App 的包名无关 —— 任意第三方 App 引 AAR 即可用。
//
// ⚠ 同步约定：本文件的 StartProxy/StopProxy/GetProxyPort/IsEchReady/GetLogs/
//   FreeCString 实现与 android/main.go 一一对应（仅 JNI 注册方式不同）。改核心
//   调用逻辑时两处需同步；长期可让 android/ 也改为复用本层以彻底消除重复。
//
// 构建（见 .github/workflows/ech-proxy-lib.yml，arm64 示例）：
//   CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
//     CC=aarch64-linux-android21-clang \
//     go build -buildmode=c-shared -ldflags="-s -w" \
//       -o libechproxy.so ./android-lib/go/
//
// 产物：libechproxy.so（Go 核心 + jni_onload.c 的 JNI 注册层，单文件，无外部依赖）。

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
	log.Println("=== Starting ech-proxy embedded library (8443 Portal) ===")

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

	proxyMu.Lock()
	defer proxyMu.Unlock()
	proxyGen++
	if proxyServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = proxyServer.Shutdown(ctx)
		proxyServer = nil
		echReady = false
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

// sanitizeForJNI 清掉 embedded NUL（JNI 修改型 UTF-8 不接受）并把超 BMP 码点
// 转成 surrogate pair，避免 NewStringUTF 抛 IllegalArgumentException。
func sanitizeForJNI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0 {
			continue
		}
		if r <= 0xFFFF {
			b.WriteRune(r)
		} else {
			r1, r2 := utf16.EncodeRune(r)
			b.WriteRune(r1)
			b.WriteRune(r2)
		}
	}
	return b.String()
}

func main() {}
