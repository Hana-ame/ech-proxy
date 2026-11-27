package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
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

// ── 拒绝「降级覆盖」 ────────────────────────────────────────────────────
//
// 更新器原先只用 SHA-256 判断「是否最新」：和 releases/latest 的资源哈希不等，
// 就认为有新版，下载下来在退出/下次启动时覆盖 exe。这对**发布版**成立，但对任何
// 本地或 CI 构建都是灾难——它们和线上资产哈希天然不同，于是每次启动都会把线上
// 发布版拉下来悄悄覆盖掉正在测的新构建。用户看到的现象就是「我明明换了新 exe，
// 打开后行为（含托盘勾选状态、默认参数）还是旧的」。
//
// 修法：用二进制里自带的 vcs.time 做一次新旧排序——只有当线上资产的构建时间
// **早于**当前运行的构建时才拒绝覆盖。任一侧取不到 vcs.time（从 tarball 编译、
// 或构建时 -buildvcs=false）就退回原有行为，不做判断，绝不误拒正常升级。

// vcsBuildTime 从 BuildInfo 里取 vcs.time（go build 在 git 仓库内默认会写入）。
func vcsBuildTime(info *debug.BuildInfo) (time.Time, bool) {
	if info == nil {
		return time.Time{}, false
	}
	for _, s := range info.Settings {
		if s.Key != "vcs.time" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.Value)); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// currentBuildTime 是「正在运行的这份二进制」的构建时间。
func currentBuildTime() (time.Time, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return time.Time{}, false
	}
	return vcsBuildTime(info)
}

// buildTimeOfReader / buildTimeOfFile 取候选二进制的构建时间。
// 前者用于刚下载到内存、尚未落盘的字节；后者用于磁盘上的 .new。
func buildTimeOfReader(r io.ReaderAt) (time.Time, bool) {
	info, err := buildinfo.Read(r)
	if err != nil {
		return time.Time{}, false
	}
	return vcsBuildTime(info)
}

func buildTimeOfFile(path string) (time.Time, bool) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return time.Time{}, false
	}
	return vcsBuildTime(info)
}

// downgradeDetail 判断候选构建是否比当前运行的更旧，并给出可读原因。
// 只有两边都拿到 vcs.time 才敢下结论，否则一律返回 false（保持原行为）。
func downgradeDetail(cand time.Time, candOK bool) (bool, string) {
	if !candOK || cand.IsZero() {
		return false, ""
	}
	cur, curOK := currentBuildTime()
	if !curOK || cur.IsZero() {
		return false, ""
	}
	if !cand.Before(cur) {
		return false, ""
	}
	return true, fmt.Sprintf("候选构建 %s 早于当前构建 %s",
		cand.Format(time.RFC3339), cur.Format(time.RFC3339))
}

// skipMarkerPath 记录「这一版线上资产已被判定为比当前构建旧」的资产哈希。
// 没有它的话，自动检查每小时都会把几十兆的安装包完整下载一遍再丢掉。
func (u *Updater) skipMarkerPath() string {
	if u == nil || u.exePath == "" {
		return ""
	}
	return u.exePath + ".skip"
}

func (u *Updater) skippedHash() string {
	p := u.skipMarkerPath()
	if p == "" {
		return ""
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func (u *Updater) markSkipped(hash string) {
	if p := u.skipMarkerPath(); p != "" {
		_ = os.WriteFile(p, []byte(hash), 0o644)
	}
}

func (u *Updater) clearSkipped() {
	if p := u.skipMarkerPath(); p != "" {
		_ = os.Remove(p)
	}
}

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
	// applyStarted 保证延迟替换只真正执行一次。退出路径上托盘退出、ctx.Done()、
	// main 的 defer 都会调 ApplyStagedUpdateOnExit：重复执行时 .new 已被首个调用搬走，
	// 后续调用白跑；更糟的是首个调用失败会拉起延迟替换 cmd，三次调用会并发拉起
	// 三个 cmd.exe 抢同一批文件。
	applyStarted atomic.Bool
	// checkMu 串行化 CheckAndDownloadOnce：后台 StartAutoCheck 的首次立即检查
	// 与用户在托盘点「检查更新」可能同时进入，两者共用同一个 .tmp 会互相覆盖/触发 ENOENT。
	checkMu     sync.Mutex
	stagedHash  string
	lastChecked time.Time
	lastError   string
	stopOnce    sync.Once
	stopCh      chan struct{}
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
	// 拒绝降级：.new 可能是旧版更新器留下的（把 CI 新构建误判为「待更新」，
	// 于是下载了 releases/latest）。启动时直接覆盖等于把用户手里的新版本静默回退，
	// 而回退后连「托盘勾选 / 默认参数」这类行为都会跟着变旧。发现即丢弃。
	if t, ok := buildTimeOfFile(newPath); ok {
		if older, detail := downgradeDetail(t, ok); older {
			log.Printf("[Updater] 启动时丢弃待替换文件 %s：%s", newPath, detail)
			_ = os.Remove(newPath)
			return false, nil
		}
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
	// 串行化：后台自动检查与托盘手动检查可能同时进入，二者共用同一个临时文件。
	u.checkMu.Lock()
	defer u.checkMu.Unlock()
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
	// 上一轮已判定「这一版线上资产比当前构建旧」，且线上还没有新资产：直接跳过，
	// 不再把整个安装包重新下载一遍。
	if sk := u.skippedHash(); sk != "" && strings.EqualFold(sk, expectedHash) {
		u.setLastError("")
		log.Printf("[Updater] %s (sha256:%s) 已判定比当前构建旧，跳过下载", assetName, expectedHash[:12])
		return false, nil
	}
	curHash, curErr := fileSHA256Hex(u.exePath)
	if curErr == nil && strings.EqualFold(curHash, expectedHash) {
		u.setLastError("")
		u.clearSkipped()
		// 已是最新版：清理可能残留的旧 .new 并撤销 staged 标记。
		// 否则它会在下次启动被 ApplyPendingUpdateOnStartup 直接覆盖上去，
		// 表现为「手动回退到旧版本，重启后又被装回新版本」。
		if _, statErr := os.Stat(u.StagedPath()); statErr == nil {
			_ = os.Remove(u.StagedPath())
			u.updateStaged.Store(false)
			u.mu.Lock()
			u.stagedHash = ""
			u.mu.Unlock()
			log.Printf("[Updater] Removed stale staged file (already up to date)")
		}
		log.Printf("[Updater] Already up to date (current sha256 matches latest: %s)", expectedHash[:12])
		return false, nil
	}
	stagedPath := u.StagedPath()
	if stHash, err := fileSHA256Hex(stagedPath); err == nil && strings.EqualFold(stHash, expectedHash) {
		// 磁盘上已经躺着同一版资产，但它可能是旧版更新器留下的降级包：
		// 复核构建时间，别把它重新标成「待应用」再在退出时覆盖上去。
		if t, ok := buildTimeOfFile(stagedPath); ok {
			if older, detail := downgradeDetail(t, ok); older {
				log.Printf("[Updater] 丢弃已暂存的旧构建 %s：%s", stagedPath, detail)
				_ = os.Remove(stagedPath)
				u.markSkipped(expectedHash)
				u.setLastError("")
				return false, nil
			}
		}
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
	// 哈希只能证明「下载到的是线上那一份」，证明不了「它比当前运行的更新」。
	// 本地/CI 构建的哈希永远不同于线上资产，若不加这一层，每次启动都会把线上
	// 发布版拉下来覆盖掉正在跑的新构建（表现为所有新修的行为突然「回退」）。
	// 落盘前先读一下它自带的 vcs.time：更旧就丢弃，不写盘、不标记 staged。
	if t, ok := buildTimeOfReader(bytes.NewReader(binBytes)); ok {
		if older, detail := downgradeDetail(t, ok); older {
			log.Printf("[Updater] 拒绝用 %s 覆盖当前 exe：%s", assetName, detail)
			u.markSkipped(expectedHash)
			u.setLastError("")
			return false, nil
		}
	}
	// 用 CreateTemp 生成唯一临时名，而不是固定的 stagedPath+".tmp"：
	// 固定名在并发场景下会让两次下载互相覆盖（A 写一半被 B 重命名走，或 rename 报 ENOENT）。
	// 虽然 CheckAndDownloadOnce 已由 checkMu 串行化，这里仍不依赖上层互斥——
	// 同一进程内多 Updater 实例或残留的旧 .tmp 都不该让新文件写失败。
	tmpFile, err := os.CreateTemp(filepath.Dir(stagedPath), ".ech-proxy-update-*.tmp")
	if err != nil {
		u.setLastError(err.Error())
		log.Printf("[Updater] Failed to create temp file: %v", err)
		return false, err
	}
	tmpPath := tmpFile.Name()
	if _, werr := tmpFile.Write(binBytes); werr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		u.setLastError(werr.Error())
		log.Printf("[Updater] Failed to write temp file: %v", werr)
		return false, werr
	}
	if cerr := tmpFile.Close(); cerr != nil {
		_ = os.Remove(tmpPath)
		u.setLastError(cerr.Error())
		log.Printf("[Updater] Failed to close temp file: %v", cerr)
		return false, cerr
	}
	_ = os.Chmod(tmpPath, 0o755)
	if err := os.Rename(tmpPath, stagedPath); err != nil {
		_ = os.Remove(tmpPath)
		u.setLastError(err.Error())
		log.Printf("[Updater] Failed to rename temp file: %v", err)
		return false, err
	}
	u.markStaged(expectedHash)
	u.clearSkipped()
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
	// 退出路径上托盘、ctx.Done()、main 的 defer 都会调到这里（历史上一共 5 处）。
	// 只让第一次「确实有 .new」的调用真正执行：后续调用若也走改名/延迟替换，
	// 会多个 cmd.exe 抢同一批文件。
	stagedPath := u.StagedPath()
	info, err := os.Stat(stagedPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false, nil
	}
	// CAS 放在 Stat 之后：早期某次调用可能 .new 尚未落地，不能让它提前消耗掉唯一机会。
	if !u.applyStarted.CompareAndSwap(false, true) {
		return false, nil
	}
	// 与启动路径同一条防线：这份 .new 可能是旧版更新器下载的降级包
	// （本进程没参与 staging，stagedHash 为空，下面的哈希复核兜不住它）。
	if t, ok := buildTimeOfFile(stagedPath); ok {
		if older, detail := downgradeDetail(t, ok); older {
			log.Printf("[Updater] 退出时拒绝应用旧构建 %s：%s", stagedPath, detail)
			_ = os.Remove(stagedPath)
			u.updateStaged.Store(false)
			return false, nil
		}
	}
	// 覆盖运行中的 exe 前复核哈希：.new 可能是上一次更新留下的旧文件，也可能是
	// 下载后被外部改动/截断的残骸。stagedHash 已知时必须一致，否则宁可放弃这次替换。
	if want := u.StagedHash(); want != "" {
		got, herr := fileSHA256Hex(stagedPath)
		if herr != nil || !strings.EqualFold(got, want) {
			u.setLastError(fmt.Sprintf("staged file hash mismatch before apply (got %q)", got))
			log.Printf("[Updater] Refusing to apply staged update: hash mismatch (got %q, want %q)", got, want)
			return false, fmt.Errorf("staged file hash mismatch: got %s, want %s", got, want)
		}
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
