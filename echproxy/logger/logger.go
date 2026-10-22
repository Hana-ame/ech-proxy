package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxLogSize = 5 * 1024 * 1024
	DefaultMaxBackups = 5
	DefaultRingLines  = 1000

	logFileName     = "ech-proxy.log"
	crashLatestName = "crash-latest.log"
	backupPrefix    = "ech-proxy-"
	backupSuffix    = ".log"
)

type Options struct {
	LogDir       string
	LogFile      string
	MaxSizeBytes int64
	MaxBackups   int
	DisableFile  bool
	ConsoleOut   io.Writer
}

type Manager struct {
	mu           sync.Mutex
	logDir       string
	logFilePath  string
	maxSizeBytes int64
	maxBackups   int
	disableFile  bool
	consoleOut   io.Writer

	file        *os.File
	currentSize int64

	ring    []string
	maxRing int
	closed  bool
}

var (
	globalMu      sync.RWMutex
	globalManager *Manager
)

func Default() *Manager {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalManager
}

func EnsureDefault() *Manager {
	if m := Default(); m != nil {
		return m
	}
	if m, err := Init(Options{}); err == nil {
		return m
	}
	return Default()
}

func Init(opts Options) (*Manager, error) {
	mgr, err := NewManager(opts)
	if err != nil {
		return nil, err
	}
	globalMu.Lock()
	old := globalManager
	globalManager = mgr
	globalMu.Unlock()

	log.SetOutput(mgr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	if old != nil && old != mgr {
		_ = old.Close()
	}
	return mgr, nil
}

func NewManager(opts Options) (*Manager, error) {
	if opts.MaxSizeBytes <= 0 {
		opts.MaxSizeBytes = DefaultMaxLogSize
	}
	if opts.MaxBackups <= 0 {
		opts.MaxBackups = DefaultMaxBackups
	}
	if opts.ConsoleOut == nil {
		opts.ConsoleOut = os.Stderr
	}

	m := &Manager{
		maxSizeBytes: opts.MaxSizeBytes,
		maxBackups:   opts.MaxBackups,
		disableFile:  opts.DisableFile,
		consoleOut:   opts.ConsoleOut,
		maxRing:      DefaultRingLines,
	}

	if !opts.DisableFile {
		logFile := strings.TrimSpace(opts.LogFile)
		logDir := strings.TrimSpace(opts.LogDir)
		if logFile != "" {
			logDir = filepath.Dir(logFile)
		} else {
			if logDir == "" {
				logDir = DefaultLogDir("")
			}
			logFile = filepath.Join(logDir, logFileName)
		}
		if err := os.MkdirAll(logDir, 0o755); err != nil {
			fallbackDir := filepath.Join(os.TempDir(), "ech-proxy-logs")
			if err2 := os.MkdirAll(fallbackDir, 0o755); err2 != nil {
				return nil, fmt.Errorf("create log dir %s: %w", logDir, err)
			}
			logDir = fallbackDir
			logFile = filepath.Join(logDir, logFileName)
		}
		m.logDir = logDir
		m.logFilePath = logFile
		if err := m.openFileLocked(true); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func DefaultLogDir(dataDir string) string {
	if strings.TrimSpace(dataDir) != "" {
		return filepath.Join(dataDir, "logs")
	}
	if exe, err := os.Executable(); err == nil {
		if exeDir := filepath.Dir(exe); canWriteDir(exeDir) {
			return filepath.Join(exeDir, "logs")
		}
	}
	if wd, err := os.Getwd(); err == nil && canWriteDir(wd) {
		return filepath.Join(wd, "logs")
	}
	if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
		return filepath.Join(cfgDir, "ech-proxy", "logs")
	}
	return filepath.Join(os.TempDir(), "ech-proxy-logs")
}

func canWriteDir(dir string) bool {
	if dir == "" {
		return false
	}
	f, err := os.CreateTemp(dir, ".ech-log-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name) == nil
}

func (m *Manager) openFileLocked(truncate bool) error {
	if m.disableFile || m.logFilePath == "" {
		return nil
	}
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if truncate {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(m.logFilePath, flags, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", m.logFilePath, err)
	}
	if info, err := f.Stat(); err == nil {
		m.currentSize = info.Size()
	} else {
		m.currentSize = 0
	}
	m.file = f
	// 注意：移除 Go 1.23+ 的 debug.SetCrashOutput 调用，兼顾 Go 1.20/1.21.4 降级编译兼容性，
	// 并避免 Windows 7 (386/amd64) 下因运行时崩溃监控复制控制台/文件句柄引发异常。
	// 崩溃转储统一由 RecoverAndLog 与 RecordFatalError 直接写入 crash-latest.log 与日志文件。
	return nil
}

func (m *Manager) Write(p []byte) (int, error) {
	return m.writeInternal(p, true)
}

func (m *Manager) writeInternal(p []byte, addToRing bool) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.consoleOut != nil {
		_, _ = m.consoleOut.Write(p)
	}
	if addToRing {
		for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
			m.ring = append(m.ring, line)
		}
		if len(m.ring) > m.maxRing {
			m.ring = append([]string(nil), m.ring[len(m.ring)-m.maxRing:]...)
		}
	}
	if !m.disableFile && !m.closed && m.file != nil {
		if m.currentSize+int64(len(p)) > m.maxSizeBytes && m.currentSize > 0 {
			_ = m.rotateLocked()
		}
		if m.file != nil {
			n, err := m.file.Write(p)
			m.currentSize += int64(n)
			return len(p), err
		}
	}
	return len(p), nil
}

func (m *Manager) appendRingLine(line string) {
	if m == nil || line == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ring = append(m.ring, line)
	if len(m.ring) > m.maxRing {
		m.ring = append([]string(nil), m.ring[len(m.ring)-m.maxRing:]...)
	}
}

func (m *Manager) rotateLocked() error {
	if m.file != nil {
		_ = m.file.Sync()
		_ = m.file.Close()
		m.file = nil
	}
	ts := strings.ReplaceAll(time.Now().Format("20060102-150405.000"), ".", "-")
	backupPath := filepath.Join(m.logDir, fmt.Sprintf("%s%s%s", backupPrefix, ts, backupSuffix))
	_ = os.Rename(m.logFilePath, backupPath)
	m.pruneOldBackupsLocked()
	return m.openFileLocked(false)
}

func (m *Manager) pruneOldBackupsLocked() {
	if m.logDir == "" || m.maxBackups <= 0 {
		return
	}
	entries, err := os.ReadDir(m.logDir)
	if err != nil {
		return
	}
	var backups []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, backupPrefix) && strings.HasSuffix(name, backupSuffix) && name != logFileName {
			backups = append(backups, filepath.Join(m.logDir, name))
		}
	}
	sort.Strings(backups)
	if len(backups) > m.maxBackups {
		for _, old := range backups[:len(backups)-m.maxBackups] {
			_ = os.Remove(old)
		}
	}
}

func (m *Manager) LogDir() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logDir
}

func (m *Manager) LogFilePath() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logFilePath
}

func (m *Manager) CrashLogPath() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logDir == "" {
		return ""
	}
	return filepath.Join(m.logDir, crashLatestName)
}

func (m *Manager) RecentLines(n int) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if n <= 0 || n > len(m.ring) {
		n = len(m.ring)
	}
	return strings.Join(m.ring[len(m.ring)-n:], "\n")
}

func (m *Manager) Sync() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.file != nil {
		_ = m.file.Sync()
	}
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.file != nil {
		_ = m.file.Sync()
		err := m.file.Close()
		m.file = nil
		return err
	}
	return nil
}

func RedactArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	sensitiveFlags := map[string]bool{"-token": true, "--token": true, "-pass": true, "--pass": true, "-password": true, "--password": true}
	for i := 0; i < len(out); i++ {
		arg := out[i]
		lower := strings.ToLower(arg)
		if sensitiveFlags[lower] && i+1 < len(out) {
			out[i+1] = "***REDACTED***"
			i++
			continue
		}
		for prefix := range sensitiveFlags {
			if strings.HasPrefix(lower, prefix+"=") {
				out[i] = arg[:len(prefix)+1] + "***REDACTED***"
				break
			}
		}
	}
	return out
}

func (m *Manager) WriteStartupHeader(version string, args []string, extra map[string]string) {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("[DIAG] ech-proxy session started at %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("[DIAG] Version: %s | Go: %s | OS/Arch: %s/%s | CPUs: %d | PID: %d\n",
		version, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), os.Getpid()))
	sb.WriteString(fmt.Sprintf("[DIAG] Args: %v\n", RedactArgs(args)))
	if m != nil && m.LogFilePath() != "" {
		sb.WriteString(fmt.Sprintf("[DIAG] LogFile: %s\n", m.LogFilePath()))
	}
	if len(extra) > 0 {
		keys := make([]string, 0, len(extra))
		for k := range extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("[DIAG] %s: %s\n", k, extra[k]))
		}
	}
	sb.WriteString("================================================================================\n")
	if m != nil {
		_, _ = m.Write([]byte(sb.String()))
		m.Sync()
	} else {
		log.Print(sb.String())
	}
}

func (m *Manager) RecordCrash(component string, recovered any, stack []byte) string {
	return m.recordDiagnosticReport("CRASH / PANIC", component, recovered, stack)
}

func (m *Manager) RecordFatal(component string, err error) string {
	if err == nil {
		return ""
	}
	return m.recordDiagnosticReport("FATAL ERROR", component, err, debug.Stack())
}

func (m *Manager) recordDiagnosticReport(kind, component string, reason any, stack []byte) string {
	now := time.Now()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n==================== ECH-PROXY %s REPORT ====================\n", kind))
	sb.WriteString(fmt.Sprintf("Time:      %s\nComponent: %s\nOS/Arch:   %s/%s (%s)\nPID:       %d\nArgs:      %v\nDetail:    %v\n\n",
		now.Format(time.RFC3339), component, runtime.GOOS, runtime.GOARCH, runtime.Version(), os.Getpid(), RedactArgs(os.Args), reason))
	if len(stack) > 0 {
		sb.WriteString("--- Stack Trace ---\n")
		sb.Write(stack)
		if !strings.HasSuffix(string(stack), "\n") {
			sb.WriteByte('\n')
		}
	}
	if m != nil {
		if recent := m.RecentLines(80); recent != "" {
			sb.WriteString("\n--- Recent Log Context (Last 80 Lines) ---\n" + recent + "\n")
		}
	}
	sb.WriteString("==========================================================================\n")
	report := sb.String()

	if m != nil {
		// 仅将单行摘要推入内存环形缓冲区 m.ring，防止多次崩溃时 RecentLines(80) 把历史崩溃报告指数级套娃写入后续报告
		_, _ = m.writeInternal([]byte(report), false)
		m.appendRingLine(fmt.Sprintf("%s [%s] %s: %v", now.Format(time.RFC3339), kind, component, reason))
		m.Sync()
		m.mu.Lock()
		dir := m.logDir
		m.mu.Unlock()
		if dir != "" {
			_ = os.WriteFile(filepath.Join(dir, crashLatestName), []byte(report), 0o644)
			_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("crash-%s.log", now.Format("20060102-150405"))), []byte(report), 0o644)
		}
	} else {
		log.Print(report)
	}
	return report
}

func RecordFatalError(component string, err error) string {
	if err == nil {
		return ""
	}
	if mgr := EnsureDefault(); mgr != nil {
		return mgr.RecordFatal(component, err)
	}
	return ""
}

func RecoverAndLog(component string, onCrash func(recovered any, stack []byte)) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		EnsureDefault().RecordCrash(component, r, stack)
		if onCrash != nil {
			onCrash(r, stack)
		}
	}
}

func SafeGo(component string, fn func()) {
	go func() {
		defer RecoverAndLog(component, nil)
		fn()
	}()
}

func CleanLogs(logDir string) error {
	if strings.TrimSpace(logDir) == "" {
		return nil
	}
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			p := filepath.Join(logDir, e.Name())
			if e.Name() == logFileName {
				_ = os.Truncate(p, 0)
			} else {
				_ = os.Remove(p)
			}
		}
	}
	return nil
}
