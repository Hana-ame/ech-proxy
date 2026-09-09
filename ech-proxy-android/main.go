// cmd/ech-proxy-android/main.go
// Android 版完整 ECH 代理（移植自 cmd/ech-proxy），编译为 c-shared 库。

package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"C"

	"github.com/gin-gonic/gin"

	"github.com/Hana-ame/ech-proxy/apifwd"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy"
)

//go:embed web/index.html
var indexHTML string

var (
	proxyMu     sync.Mutex
	proxyServer *http.Server
	proxyPort   uint16
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
	gin.SetMode(gin.ReleaseMode)
}

//export StartProxy
func StartProxy(bootstrapIP *C.char) uint16 {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	logBuffer = nil
	logBuffer = append(logBuffer, "=== Starting full ech-proxy ===")

	if proxyServer != nil {
		proxyServer.Close()
		proxyServer = nil
	}

	bootstrap := C.GoString(bootstrapIP)
	if bootstrap != "" {
		log.Printf("ECH: DoH=moonchan.xyz, bootstrapIP=%s", bootstrap)
		cloudflare_ech.SetDoHConfig("moonchan.xyz", bootstrap)
	} else {
		log.Printf("ECH: DoH=https://moonchan.xyz/doh")
		cloudflare_ech.SetDohURL("https://moonchan.xyz/doh")
	}

	log.Printf("Initializing ECH client...")
	if err := cloudflare_ech.InitDefault(); err != nil {
		log.Printf("ECH init failed: %v", err)
		return 0
	}
	echReady = true
	log.Printf("ECH ready")

	proxyBase := "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/%s?proxy_host=raw.githubusercontent.com"
	upstreamConfigURL := fmt.Sprintf(proxyBase, "certs/l.moonchan.xyz/upstream.json")

	log.Printf("Loading upstream config: %s", upstreamConfigURL)
	cfg, err := echproxy.LoadConfig(upstreamConfigURL)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		return 0
	}
	log.Printf("Upstream config loaded: %d entries", len(cfg.Upstreams))

	var tlsCert *tls.Certificate
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		log.Printf("Fetching certificate: %s", cfg.CertPath)
		certPEM, err := echproxy.FetchBytes(cfg.CertPath)
		if err != nil {
			log.Printf("Failed to fetch cert: %v", err)
			return 0
		}
		log.Printf("Fetching key: %s", cfg.KeyPath)
		keyPEM, err := echproxy.FetchBytes(cfg.KeyPath)
		if err != nil {
			log.Printf("Failed to fetch key: %v", err)
			return 0
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Printf("Failed to parse cert: %v", err)
			return 0
		}
		tlsCert = &cert
		log.Printf("Certificate loaded (*.l.moonchan.xyz)")
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(apifwd.CORSMiddleware())

	r.GET("/healthz", func(c *gin.Context) {
		c.String(200, "ok")
	})

	// 根路径：渲染 upstream 入口列表页（跳过通配符条目，带 describe）
	r.GET("/", func(c *gin.Context) {
		var sb strings.Builder
		var entries []string
		for entry := range cfg.Upstreams {
			entries = append(entries, entry)
		}
		sort.Strings(entries)
		colors := []string{"#5ce1e6", "#f0a35e", "#7c9cff", "#5ecb8e", "#e68ab8", "#9b8cff", "#5ec9e6", "#e6c45e"}
		ci := 0
		for _, entry := range entries {
			uc := cfg.Upstreams[entry]
			// 通配符条目跳过
			if uc.Wildcard != nil {
				continue
			}
			color := colors[ci%len(colors)]
			ci++
			mode := uc.Mode
			if mode == "" {
				mode = "ech"
			}
			desc := uc.Describe
			if desc == "" {
				desc = "通过 ECH 代理访问 " + uc.Host
			}
			badge := strings.ToUpper(entry[:1])
			sb.WriteString(`<div class="item">`)
			sb.WriteString(`<div class="badge" style="background:` + color + `">` + badge + `</div>`)
			sb.WriteString(`<div class="info"><div class="entry">` + entry + `</div>`)
			sb.WriteString(`<div class="desc">` + desc + `</div>`)
			sb.WriteString(`<div class="target">→ ` + uc.Host + `</div></div>`)
			sb.WriteString(`<div class="mode">` + mode + `</div>`)
			sb.WriteString(`</div>`)
		}
		page := strings.Replace(indexHTML, "{{UPSTREAMS}}", sb.String(), 1)
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(200, page)
	})

	upstreamHandler := echproxy.ProxyHandler(cfg.Upstreams, cfg.BlockedHosts)

	hostOf := func(c *gin.Context) string {
		h := c.Request.Host
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		return h
	}

	r.NoRoute(func(c *gin.Context) {
		h := hostOf(c)
		if _, ok := cfg.Upstreams[h]; ok {
			upstreamHandler(c)
			return
		}
		if _, ok := echproxy.MatchWildcardForTest(cfg.Upstreams, h); ok {
			upstreamHandler(c)
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(200, indexHTML)
	})

	ln, err := net.Listen("tcp4", "127.0.0.1:8443")
	if err != nil {
		log.Printf("Port 8443 in use, trying random port...")
		ln, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			log.Printf("listen failed: %v", err)
			return 0
		}
	}
	proxyPort = uint16(ln.Addr().(*net.TCPAddr).Port)

	if tlsCert != nil {
		log.Printf("Listening HTTPS on 127.0.0.1:%d", proxyPort)
		log.Printf("Access: https://twimg.l.moonchan.xyz:%d/", proxyPort)
		proxyServer = &http.Server{
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		proxyServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS12,
		}
		tlsLn := tls.NewListener(ln, proxyServer.TLSConfig)
		go func() {
			if err := proxyServer.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
				log.Printf("server error: %v", err)
			}
		}()
	} else {
		log.Printf("Listening HTTP on 127.0.0.1:%d", proxyPort)
		proxyServer = &http.Server{
			Handler:           r,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := proxyServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("server error: %v", err)
			}
		}()
	}

	log.Printf("Proxy started on port %d", proxyPort)
	return proxyPort
}

//export StopProxy
func StopProxy() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxyServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := proxyServer.Shutdown(ctx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
		proxyServer = nil
		proxyPort = 0
		echReady = false
		log.Printf("Proxy stopped")
	}
}

//export GetProxyPort
func GetProxyPort() uint16 {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	return proxyPort
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
