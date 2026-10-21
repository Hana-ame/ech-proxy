package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy"
)

const (
	// DefaultReleasesPageURL 是 GitHub Releases 页面地址。
	DefaultReleasesPageURL = "https://github.com/Hana-ame/ech-proxy/releases"

	// DefaultReleaseDownloadBase 是 GitHub Releases 最新版资产下载前缀。
	DefaultReleaseDownloadBase = "https://github.com/Hana-ame/ech-proxy/releases/latest/download"

	// DefaultChecksumsURL 是最新版 checksums.txt 下载地址。
	DefaultChecksumsURL = DefaultReleaseDownloadBase + "/checksums.txt"

	// DefaultUpdateCheckInterval 是后台自动检查更新的默认周期（1 小时）。
	DefaultUpdateCheckInterval = 1 * time.Hour

	minValidBinarySize = 1024 // 最小合法二进制体积下限（测试中可覆写）
)

var sha256HexRE = regexp.MustCompile(`(?i)\b([0-9a-f]{64})\b`)

// ReleaseAssetNameForPlatform 根据操作系统与架构返回对应的 GitHub Release 资产文件名：
//   - windows/386   -> ech-proxy-windows-386.exe
//   - windows/amd64 -> ech-proxy-windows-amd64.exe
//   - windows/arm64 -> ech-proxy-windows-arm64.exe
//   - linux/386     -> ech-proxy-linux-386
//   - linux/amd64   -> ech-proxy-linux-amd64
//   - linux/arm64   -> ech-proxy-linux-arm64
//   - darwin/amd64  -> ech-proxy-darwin-amd64
func ReleaseAssetNameForPlatform(goos, goarch string) string {
	goos = strings.ToLower(strings.TrimSpace(goos))
	goarch = strings.ToLower(strings.TrimSpace(goarch))

	switch goos {
	case "windows":
		switch goarch {
		case "386", "x86":
			return "ech-proxy-windows-386.exe"
		case "arm64":
			return "ech-proxy-windows-arm64.exe"
		default:
			return "ech-proxy-windows-amd64.exe"
		}
	case "linux":
		switch goarch {
		case "386", "x86":
			return "ech-proxy-linux-386"
		case "arm64", "aarch64":
			return "ech-proxy-linux-arm64"
		default:
			return "ech-proxy-linux-amd64"
		}
	case "darwin":
		return "ech-proxy-darwin-amd64"
	default:
		return fmt.Sprintf("ech-proxy-%s-%s", goos, goarch)
	}
}

// ParseChecksumsTxt 解析 checksums.txt 内容，返回 map[资产文件名]sha256小写十六进制字符串。
// 同时兼容：
//  1. 标准 sha256sum 格式：`<64位hex>  ech-proxy-windows-amd64.exe` 或 `<64位hex> *ech-proxy-windows-amd64.exe`
//  2. GitHub Releases 页面多行格式：上一行为文件名 `ech-proxy-windows-amd64.exe`，下一行为 `sha256:<64位hex>`
//  3. 同行键值格式：`ech-proxy-windows-amd64.exe sha256:<64位hex>`
func ParseChecksumsTxt(raw []byte) map[string]string {
	out := make(map[string]string)
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	var pendingAsset string
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
			continue
		}

		// 检查本行是否包含 64 位 SHA256 hex
		m := sha256HexRE.FindStringSubmatch(s)
		if len(m) > 1 {
			hash := strings.ToLower(m[1])
			// 移除行中的 sha256:<hash> 或 <hash>，看同行是否还有文件名
			rest := strings.Replace(s, m[0], " ", 1)
			rest = strings.Replace(rest, "sha256:", " ", 1)
			rest = strings.Replace(rest, "SHA256:", " ", 1)
			fields := strings.Fields(rest)
			foundName := ""
			for _, f := range fields {
				clean := strings.TrimPrefix(strings.Trim(f, "*:()[]"), "./")
				base := filepath.Base(clean)
				if isLikelyAssetFilename(base) {
					foundName = base
					break
				}
			}
			if foundName != "" {
				out[foundName] = hash
				pendingAsset = ""
				continue
			}
			if pendingAsset != "" {
				out[pendingAsset] = hash
				pendingAsset = ""
				continue
			}
		}

		// 若本行不含 64 位 hex，检查是否为资产文件名行（如 "ech-proxy-windows-amd64.exe"）
		fields := strings.Fields(s)
		if len(fields) == 1 {
			cand := filepath.Base(strings.TrimPrefix(fields[0], "*"))
			if isLikelyAssetFilename(cand) {
				pendingAsset = cand
			}
		}
	}
	return out
}

func isLikelyAssetFilename(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	return strings.HasPrefix(lower, "ech-proxy") ||
		strings.HasSuffix(lower, ".exe") ||
		strings.HasSuffix(lower, ".apk") ||
		lower == "checksums.txt"
}

func fileSHA256Hex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func bytesSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// UpdaterOptions 配置自动更新器。
type UpdaterOptions struct {
	ExePath         string
	GOOS            string
	GOARCH          string
	ChecksumsURL    string
	DownloadBaseURL string
	CheckInterval   time.Duration
	MinBinaryBytes  int
	FetchFn         func(string) ([]byte, error)
	OnStateChanged  func()
}

// Updater 负责自动检查 https://github.com/Hana-ame/ech-proxy/releases 更新、校验 SHA-256、
// 自动下载新版二进制到 <exe>.new，并在程序退出或下次启动时完成平滑替换。
type Updater struct {
	mu              sync.RWMutex
	exePath         string
	goos            string
	goarch          string
	checksumsURL    string
	downloadBaseURL string
	checkInterval   time.Duration
	minBinaryBytes  int
	fetchFn         func(string) ([]byte, error)
	onStateChanged  func()

	updateStaged atomic.Bool
	stagedHash   string
	lastChecked  time.Time
	lastError    string
	stopOnce     sync.Once
	stopCh       chan struct{}
}

// NewUpdater 创建自动更新管理器。
func NewUpdater(opts UpdaterOptions) *Updater {
	exePath := strings.TrimSpace(opts.ExePath)
	if exePath == "" {
		if p, err := os.Executable(); err == nil {
			exePath = p
		}
	}
	goos := strings.TrimSpace(opts.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := strings.TrimSpace(opts.GOARCH)
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	csURL := strings.TrimSpace(opts.ChecksumsURL)
	if csURL == "" {
		csURL = DefaultChecksumsURL
	}
	dlBase := strings.TrimRight(strings.TrimSpace(opts.DownloadBaseURL), "/")
	if dlBase == "" {
		dlBase = DefaultReleaseDownloadBase
	}
	interval := opts.CheckInterval
	if interval <= 0 {
		interval = DefaultUpdateCheckInterval
	}
	minBytes := opts.MinBinaryBytes
	if minBytes <= 0 {
		minBytes = minValidBinarySize
	}
	fetch := opts.FetchFn
	if fetch == nil {
		fetch = echproxy.FetchBytes
	}

	u := &Updater{
		exePath:         exePath,
		goos:            goos,
		goarch:          goarch,
		checksumsURL:    csURL,
		downloadBaseURL: dlBase,
		checkInterval:   interval,
		minBinaryBytes:  minBytes,
		fetchFn:         fetch,
		onStateChanged:  opts.OnStateChanged,
		stopCh:          make(chan struct{}),
	}

	// 若磁盘上已存在上次下载的 <exe>.new，标记为已就绪
	if u.exePath != "" {
		if h, err := fileSHA256Hex(u.StagedPath()); err == nil && h != "" {
			u.stagedHash = h
			u.updateStaged.Store(true)
		}
	}
	return u
}

// AssetName 返回当前平台对应的 GitHub Release 资产文件名。
func (u *Updater) AssetName() string {
	if u == nil {
		return ReleaseAssetNameForPlatform(runtime.GOOS, runtime.GOARCH)
	}
	return ReleaseAssetNameForPlatform(u.goos, u.goarch)
}

// StagedPath 返回下载暂存的新版本文件路径（<exe>.new）。
func (u *Updater) StagedPath() string {
	if u == nil || u.exePath == "" {
		return ""
	}
	return u.exePath + ".new"
}

// BackupPath 返回更新替换时的旧版本备份路径（<exe>.old）。
func (u *Updater) BackupPath() string {
	if u == nil || u.exePath == "" {
		return ""
	}
	return u.exePath + ".old"
}

// IsUpdateStaged 返回是否已下载好新版本并等待退出/重启时替换。
func (u *Updater) IsUpdateStaged() bool {
	if u == nil {
		return false
	}
	return u.updateStaged.Load()
}

// StagedHash 返回已下载暂存的新版本 SHA-256。
func (u *Updater) StagedHash() string {
	if u == nil {
		return ""
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.stagedHash
}

// ApplyPendingUpdateOnStartup 在程序启动时清理残留的 <exe>.old，若发现待替换的 <exe>.new 则立即完成替换。
func ApplyPendingUpdateOnStartup(exePath string) (bool, error) {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		if p, err := os.Executable(); err == nil {
			exePath = p
		}
	}
	if exePath == "" {
		return false, nil
	}

	oldPath := exePath + ".old"
	newPath := exePath + ".new"

	// 1. 清理上次更新留下的 .old 文件
	_ = os.Remove(oldPath)

	// 2. 若存在待应用的 .new 文件，执行原子重命名替换
	info, err := os.Stat(newPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false, nil
	}

	if _, statErr := os.Stat(exePath); statErr == nil {
		if err := os.Rename(exePath, oldPath); err != nil {
			return false, fmt.Errorf("rename current exe to .old: %w", err)
		}
	}
	if err := os.Rename(newPath, exePath); err != nil {
		// 回滚
		_ = os.Rename(oldPath, exePath)
		return false, fmt.Errorf("rename .new to exe: %w", err)
	}
	_ = os.Chmod(exePath, 0o755)
	_ = os.Remove(oldPath)
	log.Printf("[Updater] Applied pending update on startup: %s", exePath)
	return true, nil
}

// CheckAndDownloadOnce 检查远程 checksums.txt，若发现当前平台二进制有更新（SHA-256 不同），
// 自动下载新版本并校验 SHA-256 后暂存至 <exe>.new，等待退出后替换。
func (u *Updater) CheckAndDownloadOnce() (bool, error) {
	if u == nil || u.exePath == "" || u.fetchFn == nil {
		return false, nil
	}

	rawChecksums, err := u.fetchFn(u.checksumsURL)
	if err != nil {
		u.setLastError(err.Error())
		return false, fmt.Errorf("fetch checksums.txt from %s: %w", u.checksumsURL, err)
	}

	checksums := ParseChecksumsTxt(rawChecksums)
	assetName := u.AssetName()
	expectedHash, ok := checksums[assetName]
	if !ok || expectedHash == "" {
		err := fmt.Errorf("asset %q not found in checksums.txt", assetName)
		u.setLastError(err.Error())
		return false, err
	}

	// 计算当前正在运行的可执行文件 SHA-256
	if curHash, err := fileSHA256Hex(u.exePath); err == nil && strings.EqualFold(curHash, expectedHash) {
		u.mu.Lock()
		u.lastChecked = time.Now()
		u.lastError = ""
		u.mu.Unlock()
		return false, nil
	}

	// 若 <exe>.new 已经存在且 SHA-256 已匹配最新 expectedHash，无需重复下载
	stagedPath := u.StagedPath()
	if stHash, err := fileSHA256Hex(stagedPath); err == nil && strings.EqualFold(stHash, expectedHash) {
		u.mu.Lock()
		u.stagedHash = expectedHash
		u.lastChecked = time.Now()
		u.lastError = ""
		cb := u.onStateChanged
		u.mu.Unlock()
		u.updateStaged.Store(true)
		if cb != nil {
			cb()
		}
		return true, nil
	}

	// 下载最新资产并严格校验 SHA-256
	assetURL := u.downloadBaseURL + "/" + assetName
	log.Printf("[Updater] New version detected for %s (sha256:%s), downloading from %s ...", assetName, expectedHash[:12], assetURL)
	binBytes, err := u.fetchFn(assetURL)
	if err != nil {
		u.setLastError(err.Error())
		return false, fmt.Errorf("download %s: %w", assetURL, err)
	}
	if len(binBytes) < u.minBinaryBytes {
		err := fmt.Errorf("downloaded %s is too small (%d bytes)", assetName, len(binBytes))
		u.setLastError(err.Error())
		return false, err
	}
	actualHash := bytesSHA256Hex(binBytes)
	if !strings.EqualFold(actualHash, expectedHash) {
		err := fmt.Errorf("SHA-256 mismatch for %s: got %s, want %s", assetName, actualHash, expectedHash)
		u.setLastError(err.Error())
		return false, err
	}

	tmpPath := stagedPath + ".tmp"
	if err := os.WriteFile(tmpPath, binBytes, 0o755); err != nil {
		u.setLastError(err.Error())
		return false, fmt.Errorf("write update temp file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, stagedPath); err != nil {
		_ = os.Remove(tmpPath)
		u.setLastError(err.Error())
		return false, fmt.Errorf("stage update file %s: %w", stagedPath, err)
	}

	u.mu.Lock()
	u.stagedHash = expectedHash
	u.lastChecked = time.Now()
	u.lastError = ""
	cb := u.onStateChanged
	u.mu.Unlock()
	u.updateStaged.Store(true)

	log.Printf("[Updater] Update downloaded and verified (sha256:%s) -> %s (will replace executable on exit / next launch)", expectedHash[:12], stagedPath)
	if cb != nil {
		cb()
	}
	return true, nil
}

func (u *Updater) setLastError(msg string) {
	u.mu.Lock()
	u.lastChecked = time.Now()
	u.lastError = msg
	u.mu.Unlock()
}

// ApplyStagedUpdateOnExit 在程序退出时将已下载验证的 <exe>.new 替换为 <exe>，使得用户退出后再次打开即为新版本。
func (u *Updater) ApplyStagedUpdateOnExit() (bool, error) {
	if u == nil || u.exePath == "" {
		return false, nil
	}
	stagedPath := u.StagedPath()
	info, err := os.Stat(stagedPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false, nil
	}

	oldPath := u.BackupPath()
	_ = os.Remove(oldPath)

	if _, statErr := os.Stat(u.exePath); statErr == nil {
		if err := os.Rename(u.exePath, oldPath); err != nil {
			// 若在 Windows 上重命名受阻，启动后台延迟替换脚本在进程退出后完成替换
			scheduleWindowsDelayedMove(stagedPath, u.exePath, oldPath)
			return false, err
		}
	}
	if err := os.Rename(stagedPath, u.exePath); err != nil {
		_ = os.Rename(oldPath, u.exePath)
		scheduleWindowsDelayedMove(stagedPath, u.exePath, oldPath)
		return false, err
	}
	_ = os.Chmod(u.exePath, 0o755)
	_ = os.Remove(oldPath)
	u.updateStaged.Store(false)
	log.Printf("[Updater] Successfully replaced executable with new version on exit: %s", u.exePath)
	return true, nil
}

// StartAutoCheck 启动后台自动检查与下载更新协程（启动后自动检查一次，随后按周期检查）。
func (u *Updater) StartAutoCheck(ctx context.Context) {
	if u == nil {
		return
	}
	echproxy.SafeGo("Updater-AutoCheck", func() {
		if _, err := u.CheckAndDownloadOnce(); err != nil {
			log.Printf("[Updater] Initial update check skipped: %v", err)
		}
		ticker := time.NewTicker(u.checkInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-u.stopCh:
				return
			case <-ticker.C:
				_, _ = u.CheckAndDownloadOnce()
			}
		}
	})
}

// Stop 停止后台自动检查更新协程。
func (u *Updater) Stop() {
	if u == nil {
		return
	}
	u.stopOnce.Do(func() {
		close(u.stopCh)
	})
}
