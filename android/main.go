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
	log.Println("=== Starting full ech-proxy ===")

	if proxyServer != nil {
		_ = proxyServer.Close()
		proxyServer = nil
	}
	echReady = false
	echproxy.Debug = true
	proxyMu.Unlock()

	// 对齐桌面端全部环境变量：LOCALIP, IP_MODE, ECH_PROXY_CONFIG, ECH_PROXY_DATA_DIR,
	// ECH_PROXY_TOKEN, ECH_PROXY_USER, ECH_PROXY_PASS (#12, #27)
	bootstrap := strings.TrimSpace(C.GoString(bootstrapIP))
	if bootstrap == "" {
		bootstrap = os.Getenv("LOCALIP")
	}
	allowConnect := os.Getenv("ECH_PROXY_ALLOW_CONNECT") == "1"

	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:            "127.0.0.1:8443",
		AllowRandomPort: true,
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
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if echReady {
		return 1
	}
	return 0
}

func sanitizeForJNI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0 {
			continue
		}
		if r > 0xFFFF {
			r1, r2 := utf16.EncodeRune(r)
			b.WriteRune(r1)
			b.WriteRune(r2)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

//export GetLogs
func GetLogs() *C.char {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in GetLogs: %v", r)
		}
	}()

	logMu.RLock()
	defer logMu.RUnlock()
	raw := strings.Join(logBuffer, "\n")
	clean := sanitizeForJNI(strings.ToValidUTF8(raw, ""))
	return C.CString(clean)
}

//export FreeCString
func FreeCString(s *C.char) {
	if s == nil {
		return
	}
	C.free(unsafe.Pointer(s))
}

func main() {}
