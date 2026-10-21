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
