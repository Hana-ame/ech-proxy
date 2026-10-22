package echproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
