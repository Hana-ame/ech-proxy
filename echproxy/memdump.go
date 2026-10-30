package echproxy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/cookie"
	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

var (
	memDumpMu sync.Mutex
)

func formatBytes(b uint64) string {
	return fmt.Sprintf("%.2f MB (%d bytes)", float64(b)/1024/1024, b)
}

// DumpMemory 收集当前运行时内存指标、各业务模块资源缓存、pprof 堆快照及协程栈，
// 并将人类可读文本报告与二进制 heap.pprof 写入日志目录，同时输出至控制台与日志文件。
// 返回简要摘要信息（供日志与通知使用）。
func DumpMemory(reason string, srv *Server, logMgr *logger.Manager) string {
	memDumpMu.Lock()
	defer memDumpMu.Unlock()

	now := time.Now()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	numGoroutines := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()

	// 1. 确定写入的日志目录
	logDir := ""
	if logMgr != nil {
		logDir = logMgr.LogDir()
	}
	if logDir == "" {
		if srv != nil && srv.Logger != nil {
			logDir = srv.Logger.LogDir()
		}
	}
	if logDir == "" {
		dataDir := ""
		if srv != nil {
			dataDir = srv.Options.DataDir
		}
		logDir = logger.DefaultLogDir(dataDir)
	}
	_ = os.MkdirAll(logDir, 0o755)

	ts := now.Format("20060102-150405")
	txtPath := filepath.Join(logDir, fmt.Sprintf("mem_dump_%s.txt", ts))
	pprofPath := filepath.Join(logDir, fmt.Sprintf("heap_%s.pprof", ts))
	goroutinePath := filepath.Join(logDir, fmt.Sprintf("goroutines_%s.txt", ts))

	// 2. 构造人类可读诊断文本
	var sb strings.Builder
	sb.WriteString("==================== ECH-PROXY MEMORY & MODULE DIAGNOSTICS ====================\n")
	sb.WriteString(fmt.Sprintf("Trigger Reason:      %s\n", reason))
	sb.WriteString(fmt.Sprintf("Timestamp:           %s\n", now.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("OS / Arch / Go:      %s / %s / %s\n", runtime.GOOS, runtime.GOARCH, runtime.Version()))
	sb.WriteString(fmt.Sprintf("PID:                 %d\n", os.Getpid()))
	sb.WriteString(fmt.Sprintf("CPU Cores:           %d\n", numCPU))
	sb.WriteString(fmt.Sprintf("Active Goroutines:   %d\n\n", numGoroutines))

	sb.WriteString("--- Go Runtime Memory Stats ---\n")
	sb.WriteString(fmt.Sprintf("  Alloc (HeapAlloc): %s\n", formatBytes(m.Alloc)))
	sb.WriteString(fmt.Sprintf("  TotalAlloc:        %s\n", formatBytes(m.TotalAlloc)))
	sb.WriteString(fmt.Sprintf("  Sys (OS Reserved): %s\n", formatBytes(m.Sys)))
	sb.WriteString(fmt.Sprintf("  HeapInuse:         %s\n", formatBytes(m.HeapInuse)))
	sb.WriteString(fmt.Sprintf("  HeapIdle:          %s\n", formatBytes(m.HeapIdle)))
	sb.WriteString(fmt.Sprintf("  HeapReleased:      %s\n", formatBytes(m.HeapReleased)))
	sb.WriteString(fmt.Sprintf("  HeapSys:           %s\n", formatBytes(m.HeapSys)))
	sb.WriteString(fmt.Sprintf("  StackInuse:        %s\n", formatBytes(m.StackInuse)))
	sb.WriteString(fmt.Sprintf("  StackSys:          %s\n", formatBytes(m.StackSys)))
	sb.WriteString(fmt.Sprintf("  MSpanInuse:        %s\n", formatBytes(m.MSpanInuse)))
	sb.WriteString(fmt.Sprintf("  MCacheInuse:       %s\n", formatBytes(m.MCacheInuse)))
	sb.WriteString(fmt.Sprintf("  GCSys:             %s\n", formatBytes(m.GCSys)))
	sb.WriteString(fmt.Sprintf("  NextGC:            %s\n", formatBytes(m.NextGC)))
	sb.WriteString(fmt.Sprintf("  NumGC:             %d\n", m.NumGC))
	sb.WriteString(fmt.Sprintf("  PauseTotal:        %.2f ms\n", float64(m.PauseTotalNs)/1e6))
	sb.WriteString(fmt.Sprintf("  Live Objects:      %d (Mallocs: %d, Frees: %d)\n\n", m.Mallocs-m.Frees, m.Mallocs, m.Frees))

	sb.WriteString("--- Module Breakdown ---\n")

	// Module 1: cloudflare_ech / sni
	echStats := cloudflare_ech.CollectStats()
	sb.WriteString("[cloudflare_ech / sni]\n")
	sb.WriteString(fmt.Sprintf("  Route Cache Entries: %d\n", echStats.RouteCacheCount))
	if len(echStats.Routes) > 0 {
		count := 0
		for h, m := range echStats.Routes {
			sb.WriteString(fmt.Sprintf("    - %s: %s\n", h, m))
			count++
			if count >= 30 {
				sb.WriteString(fmt.Sprintf("    ... and %d more routes\n", len(echStats.Routes)-30))
				break
			}
		}
	}
	sb.WriteString(fmt.Sprintf("  IP Cache Entries:    %d\n", echStats.IPCacheCount))
	sb.WriteString(fmt.Sprintf("  uTLS H2 Transports:  %d\n", echStats.UTLSH2Count))
	for _, k := range echStats.UTLSH2Keys {
		sb.WriteString(fmt.Sprintf("    - %s\n", k))
	}
	sb.WriteString(fmt.Sprintf("  uTLS H1 Clients:     %d\n", echStats.UTLSH1Count))
	for _, k := range echStats.UTLSH1Keys {
		sb.WriteString(fmt.Sprintf("    - %s\n", k))
	}
	sb.WriteString(fmt.Sprintf("  Direct Clients:      %d\n", echStats.DirectClients))
	sb.WriteString(fmt.Sprintf("  ECH Clients:         %d\n", echStats.ECHClients))
	sb.WriteString(fmt.Sprintf("  ECH Cached Configs:  %d\n\n", echStats.ECHConfigs))

	// Module 2: certstore
	sb.WriteString("[certstore]\n")
	if srv != nil && srv.CertStore != nil {
		hasCA, caPath, leafCount := srv.CertStore.Stats()
		sb.WriteString(fmt.Sprintf("  Root CA Loaded:      %v (Path: %s)\n", hasCA, caPath))
		sb.WriteString(fmt.Sprintf("  In-Memory Leaf Certs:%d\n\n", leafCount))
	} else {
		sb.WriteString("  Store: nil / not initialized\n\n")
	}

	// Module 3: connect / limiter
	sb.WriteString("[connect / limiter]\n")
	if srv != nil && srv.Limiter != nil {
		active, perPeer, global := srv.Limiter.Stats()
		sb.WriteString(fmt.Sprintf("  Active Tunnels:      %d\n", active))
		sb.WriteString(fmt.Sprintf("  Per-Peer Max Limit:  %d\n", perPeer))
		sb.WriteString(fmt.Sprintf("  Global Max Limit:    %d\n\n", global))
	} else {
		sb.WriteString("  Limiter: nil / not initialized\n\n")
	}

	// Module 4: netdial
	transCount, transModes := netdial.TransportPoolStats()
	sb.WriteString("[netdial]\n")
	sb.WriteString(fmt.Sprintf("  Transport Pool Count:%d\n", transCount))
	for _, tm := range transModes {
		sb.WriteString(fmt.Sprintf("    - %s\n", tm))
	}
	sb.WriteString("\n")

	// Module 5: cookie
	cookieDomains, totalCookies := cookie.DefaultJar.Stats()
	sb.WriteString("[cookie]\n")
	sb.WriteString(fmt.Sprintf("  Cached Host Domains: %d\n", cookieDomains))
	sb.WriteString(fmt.Sprintf("  Total Cookies:       %d\n\n", totalCookies))

	// Module 6: rewrite / adscript
	sb.WriteString("[rewrite / adscript]\n")
	if srv != nil && srv.AdScript != nil {
		wlCount, blCount, scriptLen := srv.AdScript.Stats()
		sb.WriteString(fmt.Sprintf("  Whitelist Domains:   %d\n", wlCount))
		sb.WriteString(fmt.Sprintf("  Blocklist Rules:     %d\n", blCount))
		sb.WriteString(fmt.Sprintf("  Script Cache Size:   %d bytes\n\n", scriptLen))
	} else {
		sb.WriteString("  AdScript: nil / disabled\n\n")
	}

	// 3. 收集 pprof 堆内存分布摘要
	sb.WriteString("--- Top Heap Allocations (pprof heap summary) ---\n")
	if hp := pprof.Lookup("heap"); hp != nil {
		_ = hp.WriteTo(&sb, 1)
	}
	sb.WriteString("\n")

	// 4. 收集协程状态摘要
	sb.WriteString("--- Goroutine Summary ---\n")
	if gp := pprof.Lookup("goroutine"); gp != nil {
		_ = gp.WriteTo(&sb, 1)
	}
	sb.WriteString("================================================================================\n")

	reportText := sb.String()

	// 5. 写入文本报告文件
	if err := os.WriteFile(txtPath, []byte(reportText), 0o644); err != nil {
		log.Printf("[MemDump] Failed to write text dump %s: %v", txtPath, err)
	}

	// 6. 写入二进制 pprof 堆文件（方便 go tool pprof 分析）
	if pf, err := os.Create(pprofPath); err == nil {
		_ = pprof.WriteHeapProfile(pf)
		_ = pf.Close()
	} else {
		log.Printf("[MemDump] Failed to write heap profile %s: %v", pprofPath, err)
	}

	// 7. 写入完整协程调用栈文件
	if gf, err := os.Create(goroutinePath); err == nil {
		if gp := pprof.Lookup("goroutine"); gp != nil {
			_ = gp.WriteTo(gf, 2)
		}
		_ = gf.Close()
	} else {
		log.Printf("[MemDump] Failed to write goroutines %s: %v", goroutinePath, err)
	}

	// 8. 输出至日志文件与控制台
	if logMgr != nil {
		_, _ = logMgr.Write([]byte(reportText))
		logMgr.Sync()
	} else {
		log.Print(reportText)
	}

	summary := fmt.Sprintf("已转储内存诊断报告至: %s (HeapAlloc: %.2f MB, Goroutines: %d)",
		filepath.Base(txtPath), float64(m.Alloc)/1024/1024, numGoroutines)
	log.Printf("[MemDump] %s", summary)

	// 9. 轮转：只保留最近 maxMemDumpFiles 份，避免 mem_dump/heap/goroutines 无限累积（issue #44）。
	pruneMemDumps(logDir, maxMemDumpFiles)
	return summary
}

// maxMemDumpFiles 是每类内存转储产物（mem_dump_*.txt / heap_*.pprof / goroutines_*.txt）
// 最多保留的份数，超出后删除最旧的。
const maxMemDumpFiles = 5

// memDumpFilePrefixes 列出 DumpMemory 产生的三类文件名前缀，用于轮转与清理。
var memDumpFilePrefixes = []struct {
	prefix string
	suffix string
}{
	{"mem_dump_", ".txt"},
	{"heap_", ".pprof"},
	{"goroutines_", ".txt"},
}

// pruneMemDumps 保留 logDir 下每类内存转储文件最新的 keep 份，删除其余。
func pruneMemDumps(logDir string, keep int) {
	if strings.TrimSpace(logDir) == "" || keep <= 0 {
		return
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return
	}
	for _, cat := range memDumpFilePrefixes {
		var matched []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, cat.prefix) && strings.HasSuffix(name, cat.suffix) {
				matched = append(matched, name)
			}
		}
		if len(matched) <= keep {
			continue
		}
		// 文件名内嵌 20060102-150405 时间戳，字典序即时间序，升序后删除最旧的。
		sort.Strings(matched)
		for _, name := range matched[:len(matched)-keep] {
			_ = os.Remove(filepath.Join(logDir, name))
		}
	}
}

// StartMemoryWatchDog 启动轻量级后台内存看门狗，当堆内存超过警戒阈值时自动转储诊断报告。
func StartMemoryWatchDog(srv *Server, logMgr *logger.Manager, thresholdBytes uint64) {
	if thresholdBytes <= 0 {
		thresholdBytes = 300 * 1024 * 1024 // 默认 300MB 警戒线
	}
	SafeGo("MemoryWatchDog", func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		var lastDump time.Time
		for range ticker.C {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.Alloc >= thresholdBytes && time.Since(lastDump) > 3*time.Minute {
				lastDump = time.Now()
				log.Printf("[MemoryWatchDog] High heap memory detected (%s >= %s), triggering auto dump...",
					formatBytes(m.Alloc), formatBytes(thresholdBytes))
				DumpMemory("WatchDog-HighMemory", srv, logMgr)
			}
		}
	})
}
