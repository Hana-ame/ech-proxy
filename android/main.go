package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"C"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

var (
	proxyMu     sync.Mutex
	proxyServer *echproxy.Server
	echReady    bool

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
	proxyMu.Lock()
	defer proxyMu.Unlock()

	logBuffer = nil
	log.Println("=== Starting full ech-proxy ===")

	if proxyServer != nil {
		_ = proxyServer.Close()
		proxyServer = nil
	}
	echReady = false

	bootstrap := C.GoString(bootstrapIP)
	srv, err := echproxy.NewServer(echproxy.ServerOptions{
		Addr:            "127.0.0.1:8443",
		AllowRandomPort: true,
		BootstrapIP:     bootstrap,
	})
	if err != nil {
		log.Printf("Server init failed: %v", err)
		return 0
	}

	if err := srv.ServeAsync(); err != nil {
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
	proxyMu.Lock()
	defer proxyMu.Unlock()
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
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxyServer != nil {
		return proxyServer.Port
	}
	return 0
}

//export IsEchReady
func IsEchReady() C.int {
	if echReady {
		return 1
	}
	return 0
}

//export GetLogs
func GetLogs() *C.char {
	logMu.RLock()
	defer logMu.RUnlock()
	return C.CString(strings.Join(logBuffer, "\n"))
}

func main() {}
