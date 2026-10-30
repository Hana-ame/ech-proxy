package echproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDumpMemoryExecutionAndFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ech-proxy-memdump-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr, err := InitLogger(LoggerOptions{
		LogDir:      tmpDir,
		DisableFile: false,
	})
	if err != nil {
		t.Fatalf("InitLogger failed: %v", err)
	}
	defer mgr.Close()

	summary := DumpMemory("UnitTest", nil, mgr)
	if !strings.Contains(summary, "已转储内存诊断报告至") {
		t.Errorf("DumpMemory summary unexpected: %s", summary)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	var hasTxt, hasPprof, hasGoroutine bool
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "mem_dump_") && strings.HasSuffix(name, ".txt") {
			hasTxt = true
			content, rerr := os.ReadFile(filepath.Join(tmpDir, name))
			if rerr != nil {
				t.Errorf("read mem_dump txt error: %v", rerr)
			}
			if !strings.Contains(string(content), "ECH-PROXY MEMORY & MODULE DIAGNOSTICS") {
				t.Errorf("mem_dump txt missing header")
			}
			if !strings.Contains(string(content), "cloudflare_ech / sni") {
				t.Errorf("mem_dump txt missing cloudflare_ech module section")
			}
		}
		if strings.HasPrefix(name, "heap_") && strings.HasSuffix(name, ".pprof") {
			hasPprof = true
		}
		if strings.HasPrefix(name, "goroutines_") && strings.HasSuffix(name, ".txt") {
			hasGoroutine = true
		}
	}

	if !hasTxt {
		t.Errorf("expected mem_dump_*.txt file to be generated")
	}
	if !hasPprof {
		t.Errorf("expected heap_*.pprof file to be generated")
	}
	if !hasGoroutine {
		t.Errorf("expected goroutines_*.txt file to be generated")
	}
}

// TestPruneMemDumpsKeepsLatest 验证 issue #44：内存转储产物按数量轮转，只保留最新 keep 份。
func TestPruneMemDumpsKeepsLatest(t *testing.T) {
	dir := t.TempDir()
	stamp := func(i int) string {
		return time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC).Format("20060102-150405")
	}
	for i := 0; i < 8; i++ {
		ts := stamp(i)
		for _, name := range []string{
			"mem_dump_" + ts + ".txt",
			"heap_" + ts + ".pprof",
			"goroutines_" + ts + ".txt",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	pruneMemDumps(dir, 3)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, "mem_dump_"):
			counts["txt"]++
		case strings.HasPrefix(name, "heap_"):
			counts["pprof"]++
		case strings.HasPrefix(name, "goroutines_"):
			counts["goroutine"]++
		}
	}
	if counts["txt"] != 3 || counts["pprof"] != 3 || counts["goroutine"] != 3 {
		t.Errorf("prune kept %v, want 3 of each", counts)
	}
	// 保留的必须是最新的（时间戳最大的 3 个）
	if _, err := os.Stat(filepath.Join(dir, "mem_dump_"+stamp(7)+".txt")); err != nil {
		t.Errorf("newest mem_dump removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mem_dump_"+stamp(0)+".txt")); err == nil {
		t.Error("oldest mem_dump should have been pruned")
	}
}
