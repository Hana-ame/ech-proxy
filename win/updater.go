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
	DefaultReleasesPageURL     = "https://github.com/Hana-ame/ech-proxy/releases"
	DefaultReleaseDownloadBase = "https://github.com/Hana-ame/ech-proxy/releases/latest/download"
	DefaultChecksumsURL        = DefaultReleaseDownloadBase + "/checksums.txt"
	DefaultUpdateCheckInterval = 1 * time.Hour
	minValidBinarySize         = 1024
)

var sha256HexRE = regexp.MustCompile(`(?i)\b([0-9a-f]{64})\b`)

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

func ParseChecksumsTxt(raw []byte) map[string]string {
	out := make(map[string]string)
	var pendingAsset string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
			continue
		}
		if m := sha256HexRE.FindStringSubmatch(s); len(m) > 1 {
			hash := strings.ToLower(m[1])
			rest := strings.NewReplacer(m[0], " ", "sha256:", " ", "SHA256:", " ").Replace(s)
			foundName := ""
			for _, f := range strings.Fields(rest) {
				base := filepath.Base(strings.TrimPrefix(strings.Trim(f, "*:()[]"), "./"))
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
		if fields := strings.Fields(s); len(fields) == 1 {
			if cand := filepath.Base(strings.TrimPrefix(fields[0], "*")); isLikelyAssetFilename(cand) {
				pendingAsset = cand
			}
		}
	}
	return out
}

func isLikelyAssetFilename(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return lower != "" && (strings.HasPrefix(lower, "ech-proxy") || strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".apk") || lower == "checksums.txt")
}

func fileSHA256Hex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return bytesSHA256Hex(data), nil
}

func bytesSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

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

func NewUpdater(opts UpdaterOptions) *Updater {
	exePath := strings.TrimSpace(opts.ExePath)
	if exePath == "" {
		exePath, _ = os.Executable()
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
	if u.exePath != "" {
		if h, err := fileSHA256Hex(u.StagedPath()); err == nil && h != "" {
			u.stagedHash = h
			u.updateStaged.Store(true)
		}
	}
	return u
}

func (u *Updater) AssetName() string {
	if u == nil {
		return ReleaseAssetNameForPlatform(runtime.GOOS, runtime.GOARCH)
	}
	if u.exePath != "" {
		base := strings.ToLower(filepath.Base(u.exePath))
		if strings.Contains(base, ".443") {
			return "ech-proxy.443.exe"
		}
	}
	return ReleaseAssetNameForPlatform(u.goos, u.goarch)
}

func (u *Updater) StagedPath() string {
	if u == nil || u.exePath == "" {
		return ""
	}
	return u.exePath + ".new"
}

func (u *Updater) BackupPath() string {
	if u == nil || u.exePath == "" {
		return ""
	}
	return u.exePath + ".old"
}

func (u *Updater) IsUpdateStaged() bool {
	return u != nil && u.updateStaged.Load()
}

func (u *Updater) StagedHash() string {
	if u == nil {
		return ""
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.stagedHash
}

func ApplyPendingUpdateOnStartup(exePath string) (bool, error) {
	exePath = strings.TrimSpace(exePath)
	if exePath == "" {
		exePath, _ = os.Executable()
	}
	if exePath == "" {
		return false, nil
	}
	oldPath, newPath := exePath+".old", exePath+".new"
	_ = os.Remove(oldPath)
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
		_ = os.Rename(oldPath, exePath)
		return false, fmt.Errorf("rename .new to exe: %w", err)
	}
	_ = os.Chmod(exePath, 0o755)
	_ = os.Remove(oldPath)
	return true, nil
}

func (u *Updater) CheckAndDownloadOnce() (bool, error) {
	if u == nil || u.exePath == "" || u.fetchFn == nil {
		return false, nil
	}
	log.Printf("[Updater] Checking update for %s (%s)...", u.AssetName(), u.checksumsURL)
	rawChecksums, err := u.fetchFn(u.checksumsURL)
	if err != nil {
		u.setLastError(err.Error())
		log.Printf("[Updater] Failed to fetch checksums.txt: %v", err)
		return false, fmt.Errorf("fetch checksums.txt: %w", err)
	}
	checksums := ParseChecksumsTxt(rawChecksums)
	assetName := u.AssetName()
	expectedHash := checksums[assetName]
	if expectedHash == "" {
		err := fmt.Errorf("asset %q not found in checksums.txt", assetName)
		u.setLastError(err.Error())
		log.Printf("[Updater] %v", err)
		return false, err
	}
	curHash, curErr := fileSHA256Hex(u.exePath)
	if curErr == nil && strings.EqualFold(curHash, expectedHash) {
		u.setLastError("")
		log.Printf("[Updater] Already up to date (current sha256 matches latest: %s)", expectedHash[:12])
		return false, nil
	}
	stagedPath := u.StagedPath()
	if stHash, err := fileSHA256Hex(stagedPath); err == nil && strings.EqualFold(stHash, expectedHash) {
		u.markStaged(expectedHash)
		log.Printf("[Updater] New version already staged at %s (sha256:%s)", stagedPath, expectedHash[:12])
		return true, nil
	}
	assetURL := u.downloadBaseURL + "/" + assetName
	log.Printf("[Updater] Downloading new version: %s (latest sha256:%s)...", assetURL, expectedHash[:12])
	binBytes, err := u.fetchFn(assetURL)
	if err != nil {
		u.setLastError(err.Error())
		log.Printf("[Updater] Download failed: %v", err)
		return false, fmt.Errorf("download %s: %w", assetURL, err)
	}
	if len(binBytes) < u.minBinaryBytes {
		err := fmt.Errorf("downloaded %s is too small (%d bytes)", assetName, len(binBytes))
		u.setLastError(err.Error())
		log.Printf("[Updater] %v", err)
		return false, err
	}
	if actualHash := bytesSHA256Hex(binBytes); !strings.EqualFold(actualHash, expectedHash) {
		err := fmt.Errorf("SHA-256 mismatch for %s: got %s, want %s", assetName, actualHash, expectedHash)
		u.setLastError(err.Error())
		log.Printf("[Updater] %v", err)
		return false, err
	}
	tmpPath := stagedPath + ".tmp"
	if err := os.WriteFile(tmpPath, binBytes, 0o755); err != nil {
		u.setLastError(err.Error())
		log.Printf("[Updater] Failed to write temp file: %v", err)
		return false, err
	}
	if err := os.Rename(tmpPath, stagedPath); err != nil {
		_ = os.Remove(tmpPath)
		u.setLastError(err.Error())
		log.Printf("[Updater] Failed to rename temp file: %v", err)
		return false, err
	}
	u.markStaged(expectedHash)
	log.Printf("[Updater] Update staged successfully (sha256:%s) -> %s", expectedHash[:12], stagedPath)
	return true, nil
}

func (u *Updater) markStaged(hash string) {
	u.mu.Lock()
	u.stagedHash = hash
	u.lastChecked = time.Now()
	u.lastError = ""
	cb := u.onStateChanged
	u.mu.Unlock()
	u.updateStaged.Store(true)
	if cb != nil {
		cb()
	}
}

func (u *Updater) setLastError(msg string) {
	u.mu.Lock()
	u.lastChecked = time.Now()
	u.lastError = msg
	u.mu.Unlock()
}

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
	return true, nil
}

func (u *Updater) StartAutoCheck(ctx context.Context) {
	if u == nil {
		return
	}
	echproxy.SafeGo("Updater-AutoCheck", func() {
		_, _ = u.CheckAndDownloadOnce()
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

func (u *Updater) Stop() {
	if u != nil {
		u.stopOnce.Do(func() { close(u.stopCh) })
	}
}
