package logger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingLoggerAndRedaction(t *testing.T) {
	dir := t.TempDir()
	var console bytes.Buffer

	mgr, err := NewManager(Options{
		LogDir:       dir,
		MaxSizeBytes: 512,
		MaxBackups:   2,
		ConsoleOut:   &console,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	mgr.WriteStartupHeader("v1.5.0-test", []string{"ech-proxy", "-token", "super-secret-123", "-pass=my-password"}, map[string]string{
		"Mode":   "smart",
		"IPMode": "ipv4 (4 = ipv4 only)",
	})

	if strings.Contains(console.String(), "super-secret-123") || strings.Contains(console.String(), "my-password") {
		t.Fatalf("sensitive credentials were not redacted: %s", console.String())
	}
	if !strings.Contains(console.String(), "***REDACTED***") {
		t.Errorf("expected ***REDACTED*** in startup header: %s", console.String())
	}

	for i := 0; i < 30; i++ {
		_, _ = mgr.Write([]byte("2026/10/20 12:00:00 [INFO] test log rotation line with enough padding bytes\n"))
	}
	mgr.Sync()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var backups int
	var hasMain bool
	for _, e := range entries {
		if e.Name() == "ech-proxy.log" {
			hasMain = true
		} else if strings.HasPrefix(e.Name(), "ech-proxy-") && strings.HasSuffix(e.Name(), ".log") {
			backups++
		}
	}
	if !hasMain {
		t.Error("expected active ech-proxy.log to exist")
	}
	if backups == 0 || backups > 2 {
		t.Errorf("expected 1..2 rotated backup files (MaxBackups=2), got %d", backups)
	}
}

func TestCrashAndFatalErrorWriteLogFiles(t *testing.T) {
	dir := t.TempDir()
	var console bytes.Buffer

	mgr, err := Init(Options{
		LogDir:     dir,
		ConsoleOut: &console,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer mgr.Close()

	_, _ = mgr.Write([]byte("breadcrumb before crash\n"))

	// 1. Test panic crash recovery writes to both ech-proxy.log and crash-latest.log
	caught := false
	func() {
		defer RecoverAndLog("unit-test-worker", func(r any, stack []byte) {
			caught = true
		})
		panic("simulated fatal nil pointer dereference")
	}()

	if !caught {
		t.Fatal("RecoverAndLog did not catch panic")
	}

	crashBytes, err := os.ReadFile(filepath.Join(dir, "crash-latest.log"))
	if err != nil {
		t.Fatalf("expected crash-latest.log to be written: %v", err)
	}
	crashText := string(crashBytes)
	if !strings.Contains(crashText, "simulated fatal nil pointer dereference") ||
		!strings.Contains(crashText, "unit-test-worker") ||
		!strings.Contains(crashText, "breadcrumb before crash") {
		t.Errorf("crash-latest.log missing expected diagnostic details:\n%s", crashText)
	}

	// 2. Test RecordFatalError writes structured FATAL ERROR report to both ech-proxy.log and crash-latest.log
	RecordFatalError("NewServer", errors.New("bind 127.0.0.1:443 permission denied"))
	mainLogBytes, err := os.ReadFile(filepath.Join(dir, "ech-proxy.log"))
	if err != nil {
		t.Fatalf("expected ech-proxy.log to exist: %v", err)
	}
	if !strings.Contains(string(mainLogBytes), "FATAL ERROR REPORT") ||
		!strings.Contains(string(mainLogBytes), "bind 127.0.0.1:443 permission denied") {
		t.Errorf("ech-proxy.log missing fatal error report:\n%s", string(mainLogBytes))
	}
}

// TestStartupClearsExistingLogFile verifies that initializing a new Manager on
// a directory already holding a previous session's ech-proxy.log truncates the
// file on open instead of appending to it.
// 用户要求：每次启动时不再 append，而是直接清空文件。
func TestStartupClearsExistingLogFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, logFileName)

	// Seed a previous session's log file with stale content that must not survive restart.
	stale := []byte("OLD SESSION LOG LINE THAT MUST NOT SURVIVE RESTART\n")
	if err := os.WriteFile(logPath, stale, 0o644); err != nil {
		t.Fatalf("seed previous log: %v", err)
	}

	mgr, err := NewManager(Options{LogDir: dir})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	marker := []byte("FRESH STARTUP MARKER\n")
	if _, err := mgr.Write(marker); err != nil {
		t.Fatalf("write: %v", err)
	}
	mgr.Sync()

	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(got), "OLD SESSION LOG LINE THAT MUST NOT SURVIVE RESTART") {
		t.Errorf("startup should have cleared the previous log, but stale content remains: %s", got)
	}
	if !strings.Contains(string(got), "FRESH STARTUP MARKER") {
		t.Errorf("fresh startup marker missing from cleared log: %s", got)
	}
}
