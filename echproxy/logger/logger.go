// Package logger 提供本地持久化滚动日志（Rotating File Logger）、敏感参数脱敏、
// 内存环形日志缓冲以及全局报错（Fatal Error）与 Panic 闪退（Crash Dump）落盘能力。
// 当程序发生报错或闪退时，总是自动在 logs/ 目录下留下 ech-proxy.log 与 crash-latest.log 供排查分析。
// 本模块处于架构最底层，不依赖项目内任何其他包。
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
	// DefaultMaxLogSize 单个日志文件最大体积（默认 5 MB），超过后自动滚动切分。
	DefaultMaxLogSize = 5 * 1024 * 1024
	// DefaultMaxBackups 最多保留的历史滚动日志文件数量。
	DefaultMaxBackups = 5
	// DefaultRingLines 内存中保留的最近日志行数（用于崩溃上下文快照与 /debug/log 查看）。
	DefaultRingLines = 1000

	logFileName     = "ech-proxy.log"
	crashLatestName = "crash-latest.log"
	backupPrefix    = "ech-proxy-"
	backupSuffix    = ".log"
)

// Options 配置本地日志管理器。
type Options struct {
	LogDir       string    // 日志目录，默认 <DataDir>/logs
	LogFile      string    // 指定日志文件路径（可选，默认 <LogDir>/ech-proxy.log）
	MaxSizeBytes int64     // 单文件滚动阈值（默认 5MB）
	MaxBackups   int       // 历史日志文件保留数（默认 5）
	DisableFile  bool      // 是否禁用本地文件落盘（仅输出到控制台与内存缓冲）
	ConsoleOut   io.Writer // 控制台输出目标（默认 os.Stderr）
}

// Manager 管理本地日志文件写入、自动按大小滚动、内存环形缓冲与报错/崩溃快照转储。
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

// Default 返回当前全局日志管理器（若尚未初始化则返回 nil）。
func Default() *Manager {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalManager
}

// EnsureDefault 确保全局日志管理器已初始化（若尚未初始化，则自动在默认 logs 目录创建本地日志文件）。
// 保证即使在命令行参数解析阶段或初始化早期报错/闪退，也能在本地磁盘留下日志文件。
func EnsureDefault() *Manager {
	if m := Default(); m != nil {
		return m
	}
	m, err := Init(Options{})
	if err != nil {
		return Default()
	}
	return m
}

// Init 初始化全局日志管理器，并将标准库 log 的输出重定向到（控制台 + 本地滚动日志文件 + 内存缓冲）。
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

// NewManager 创建日志管理器实例。
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
				return nil, fmt.Errorf("create log dir %s (and fallback %s): %w", logDir, fallbackDir, err)
			}
			logDir = fallbackDir
			logFile = filepath.Join(logDir, logFileName)
		}

		m.logDir = logDir
		m.logFilePath = logFile
		if err := m.openFileLocked(true); err != nil { // 启动时清空已有日志文件
			return nil, err
		}
	}

	return m, nil
}

// DefaultLogDir 返回默认日志存储目录（优先 <dataDir>/logs，其次可执行文件同级 logs，最后用户配置目录）。
func DefaultLogDir(dataDir string) string {
	if strings.TrimSpace(dataDir) != "" {
		return filepath.Join(dataDir, "logs")
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if canWriteDir(exeDir) {
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
	// 始终保留 O_APPEND 写入：该 fd 同时被 debug.SetCrashOutput 绑定给 Go 运行时崩溃输出，
	// 并发写入时只有 append 能保证不互相覆盖/错位。
	// truncate=true 时附加 O_TRUNC：每次启动清空已有日志文件，不再跨会话累积 append（用户要求：
	// 每次启动时不再 append，而是直接清空文件）。
	// rotateLocked 走 truncate=false：活跃文件刚被 rename 成备份、路径已不存在，O_CREATE 新建空文件；
	// 即使 rename 失败也以 append 方式保留现有内容，绝不丢日志。
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if truncate {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(m.logFilePath, flags, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", m.logFilePath, err)
	}
	info, err := f.Stat()
	if err == nil {
		m.currentSize = info.Size()
	} else {
		m.currentSize = 0
	}
	m.file = f
	// 将 Go 运行时底层崩溃输出同步绑定到日志文件，确保即使遇到未捕获协程崩溃或底层 runtime throw 也能留下完整堆栈
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	return nil
}

// Write 实现 io.Writer，线程安全地同时写入控制台、本地滚动日志文件与内存环形缓冲。
func (m *Manager) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.consoleOut != nil {
		_, _ = m.consoleOut.Write(p)
	}

	text := strings.TrimRight(string(p), "\r\n")
	for _, line := range strings.Split(text, "\n") {
		m.ring = append(m.ring, line)
	}
	if len(m.ring) > m.maxRing {
		m.ring = append([]string(nil), m.ring[len(m.ring)-m.maxRing:]...)
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

func (m *Manager) rotateLocked() error {
	if m.file != nil {
		_ = m.file.Sync()
		_ = m.file.Close()
		m.file = nil
	}
	ts := time.Now().Format("20060102-150405.000")
	ts = strings.ReplaceAll(ts, ".", "-")
	backupName := fmt.Sprintf("%s%s%s", backupPrefix, ts, backupSuffix)
	backupPath := filepath.Join(m.logDir, backupName)

	_ = os.Rename(m.logFilePath, backupPath)
	m.pruneOldBackupsLocked()
	return m.openFileLocked(false) // 滚动后新建空文件，不清空
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

// LogDir 返回当前日志目录路径。
func (m *Manager) LogDir() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logDir
}

// LogFilePath 返回当前活跃日志文件的绝对路径。
func (m *Manager) LogFilePath() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.logFilePath
}

// CrashLogPath 返回最近一次报错/崩溃快照文件路径。
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

// RecentLines 返回内存环形缓冲中最近的 n 行日志文本。
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

// Sync 强制将底层日志文件缓冲区刷入磁盘。
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

// Close 关闭底层日志文件句柄。
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.file != nil {
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
		_ = m.file.Sync()
		err := m.file.Close()
		m.file = nil
		return err
	}
	return nil
}

// RedactArgs 对命令行参数中的敏感凭据（如 -token, -pass）进行脱敏，确保用户上传日志时不泄露密码。
func RedactArgs(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	sensitiveFlags := map[string]bool{
		"-token": true, "--token": true,
		"-pass": true, "--pass": true,
		"-password": true, "--password": true,
	}
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

// WriteStartupHeader 在日志文件中记录结构化启动诊断头（方便排障时立即获知系统环境、版本与运行参数）。
func (m *Manager) WriteStartupHeader(version string, args []string, extra map[string]string) {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("[DIAG] ech-proxy session started at %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("[DIAG] Version: %s | Go: %s | OS/Arch: %s/%s | CPUs: %d | PID: %d\n",
		version, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), os.Getpid()))
	if wd, err := os.Getwd(); err == nil {
		sb.WriteString(fmt.Sprintf("[DIAG] WorkDir: %s\n", wd))
	}
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

// RecordCrash 将捕获到的 panic 闪退异常或致命报错、完整调用栈与最近上下文日志写入本地 ech-proxy.log 与独立的 crash-latest.log。
func (m *Manager) RecordCrash(component string, recovered any, stack []byte) string {
	return m.recordDiagnosticReport("CRASH / PANIC", component, recovered, stack)
}

// RecordFatal 将导致程序退出的致命报错（Fatal Error）、完整调用栈与上下文日志持久化到 ech-proxy.log 与 crash-latest.log，确保报错闪退后必定留下日志供 debug。
func (m *Manager) RecordFatal(component string, err error) string {
	if err == nil {
		return ""
	}
	return m.recordDiagnosticReport("FATAL ERROR", component, err, debug.Stack())
}

func (m *Manager) recordDiagnosticReport(kind, component string, reason any, stack []byte) string {
	now := time.Now()
	wd, _ := os.Getwd()
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n==================== ECH-PROXY %s REPORT ====================\n", kind))
	sb.WriteString(fmt.Sprintf("Time:      %s\n", now.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Component: %s\n", component))
	sb.WriteString(fmt.Sprintf("OS/Arch:   %s/%s (%s)\n", runtime.GOOS, runtime.GOARCH, runtime.Version()))
	sb.WriteString(fmt.Sprintf("PID:       %d\n", os.Getpid()))
	sb.WriteString(fmt.Sprintf("WorkDir:   %s\n", wd))
	sb.WriteString(fmt.Sprintf("Args:      %v\n", RedactArgs(os.Args)))
	sb.WriteString(fmt.Sprintf("Detail:    %v\n\n", reason))
	if len(stack) > 0 {
		sb.WriteString("--- Stack Trace ---\n")
		sb.Write(stack)
		if !strings.HasSuffix(string(stack), "\n") {
			sb.WriteByte('\n')
		}
	}

	if m != nil {
		recent := m.RecentLines(80)
		if recent != "" {
			sb.WriteString("\n--- Recent Log Context (Last 80 Lines) ---\n")
			sb.WriteString(recent)
			sb.WriteByte('\n')
		}
	}
	sb.WriteString("==========================================================================\n")
	report := sb.String()

	if m != nil {
		_, _ = m.Write([]byte(report))
		m.Sync()
		m.mu.Lock()
		dir := m.logDir
		m.mu.Unlock()
		if dir != "" {
			latestPath := filepath.Join(dir, crashLatestName)
			tsPath := filepath.Join(dir, fmt.Sprintf("crash-%s.log", now.Format("20060102-150405")))
			_ = os.WriteFile(latestPath, []byte(report), 0o644)
			_ = os.WriteFile(tsPath, []byte(report), 0o644)
		}
	} else {
		log.Print(report)
	}
	return report
}

// RecordFatalError 记录导致程序退出的致命报错并立即刷盘（若全局日志器尚未初始化，会自动初始化默认日志器落盘）。
func RecordFatalError(component string, err error) string {
	if err == nil {
		return ""
	}
	mgr := EnsureDefault()
	if mgr != nil {
		return mgr.RecordFatal(component, err)
	}
	return ""
}

// RecoverAndLog 用作 defer 守卫，捕获任何未处理的 panic 并立即持久化到本地日志文件，防止无痕闪退。
func RecoverAndLog(component string, onCrash func(recovered any, stack []byte)) {
	if r := recover(); r != nil {
		stack := debug.Stack()
		EnsureDefault().RecordCrash(component, r, stack)
		if onCrash != nil {
			onCrash(r, stack)
		}
	}
}

// SafeGo 启动带自动 Panic 恢复与崩溃日志记录的后台协程，绝不因单个子协程异常导致主进程无日志闪退。
func SafeGo(component string, fn func()) {
	go func() {
		defer RecoverAndLog(component, nil)
		fn()
	}()
}

// CleanLogs 清理日志目录下的历史滚动日志与崩溃快照（保留当前活跃日志文件并清空内容）。
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
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".log") {
			p := filepath.Join(logDir, name)
			if name == logFileName {
				_ = os.Truncate(p, 0)
			} else {
				_ = os.Remove(p)
			}
		}
	}
	return nil
}
