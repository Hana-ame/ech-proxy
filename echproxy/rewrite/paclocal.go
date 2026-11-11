package rewrite

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LocalWhitelistFileName 是本地自定义 PAC 白名单文件名。
//
// 设计目标（issue：自定义本地 text 文件 pac.txt）：用户把一个 pac.txt 放在程序
// 同目录（或数据目录 / 当前工作目录）里，程序**默认就使用本地这一份**，完全离线、
// 不需要任何参数；只有本地文件不存在（或不可用）时才回退到在线地址。
//
// 判定优先级（见 ResolveWhitelistSource）：
//  1. 显式配置 -whitelist-url / ECH_PROXY_WHITELIST_URL；
//  2. 显式配置 -pac-file；
//  3. 自动探测：<exeDir>/pac.txt → <dataDir>/pac.txt → <cwd>/pac.txt；
//  4. 都没有 → 在线 DefaultWhitelistURL。
const LocalWhitelistFileName = "pac.txt"

// WhitelistSourceKind 的值（PAC 白名单实际来源的类别）。
const (
	// WhitelistKindExplicit 表示来源由用户显式指定（-whitelist-url / -pac-file / 环境变量）。
	WhitelistKindExplicit = "explicit"
	// WhitelistKindLocal 表示来源是自动探测到的本地 pac.txt。
	WhitelistKindLocal = "local-pac"
	// WhitelistKindRemote 表示来源是内置的在线默认地址。
	WhitelistKindRemote = "remote"
)

// WhitelistSourceOptions 是 ResolveWhitelistSource 的输入。
type WhitelistSourceOptions struct {
	// ExplicitURL 是用户显式指定的白名单来源（-whitelist-url / ECH_PROXY_WHITELIST_URL），
	// 非空时永远优先，本地 pac.txt 不再参与判定。
	ExplicitURL string
	// ExplicitPath 是用户显式指定的本地 pac.txt 路径（-pac-file / ECH_PROXY_PAC_FILE）。
	ExplicitPath string
	// DataDir 是程序数据目录（用于探测 <dataDir>/pac.txt），可为空。
	DataDir string
	// DisableLocal 为 true 时忽略一切本地 pac.txt（-no-local-pac），直接使用在线地址。
	DisableLocal bool
	// Candidates 可覆盖自动探测的候选路径顺序（测试用）；为空时使用
	// DefaultLocalWhitelistCandidates(DataDir)。
	Candidates []string
}

// WhitelistSource 是 PAC 白名单来源的解析结果。
type WhitelistSource struct {
	// URL 是最终交给 AdScriptManager 的来源（file:// 绝对路径 或 http(s) 地址）。
	URL string
	// Kind 是来源类别：explicit / local-pac / remote。
	Kind string
	// LocalPath 是命中的本地 pac.txt 绝对路径（仅 Kind == local-pac 或显式本地来源时非空）。
	LocalPath string
	// Warnings 是需要上报给日志/诊断的降级原因（探测到但不可用的本地文件等）。
	Warnings []string
}

// IsLocalWhitelistSource 判断白名单来源是否指向本地文件（file:// 前缀或非 http(s) 的裸路径）。
func IsLocalWhitelistSource(source string) bool {
	_, ok := localWhitelistPath(source)
	return ok
}

// localWhitelistPath 把 file:// URL 或裸路径还原为本地路径。
func localWhitelistPath(source string) (string, bool) {
	s := strings.TrimSpace(source)
	if s == "" {
		return "", false
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "file://") {
		p := strings.TrimPrefix(s, "file://")
		if strings.HasPrefix(p, "/") && len(p) > 1 && p[2] == ':' {
			// file:///C:/... 形式：去掉前导斜杠
			p = p[1:]
		}
		return p, p != ""
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return "", false
	}
	return s, true
}

// localSourceURL 把本地路径包装成 file:// 形式，便于日志与 FetchBytes 识别。
func localSourceURL(path string) string {
	p := strings.TrimSpace(path)
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return "file://" + filepath.ToSlash(p)
}

// DefaultLocalWhitelistCandidates 返回自动探测本地 pac.txt 的候选路径（按优先级）：
// 程序所在目录 → 数据目录 → 当前工作目录。结果已去重并清理。
func DefaultLocalWhitelistCandidates(dataDir string) []string {
	var out []string
	if exe, err := os.Executable(); err == nil {
		out = append(out, filepath.Join(filepath.Dir(exe), LocalWhitelistFileName))
	}
	if d := strings.TrimSpace(dataDir); d != "" {
		out = append(out, filepath.Join(d, LocalWhitelistFileName))
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, filepath.Join(wd, LocalWhitelistFileName))
	}
	return dedupePaths(out)
}

func dedupePaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		key := strings.ToLower(p)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

// ResolveWhitelistSource 按文档注释中的优先级决定 PAC 白名单的实际来源。
//
// 注意：本地 pac.txt 只影响「来源」，内容仍走 ParseDomainList 的既有解析与校验；
// 探测到存在但内容非法（空文件 / HTML 错误页 / 超长）的本地文件会被跳过并记录 Warning，
// 继续尝试下一个候选，最终回退到在线地址，绝不会让一份坏文件把白名单变成空表。
func ResolveWhitelistSource(opts WhitelistSourceOptions) WhitelistSource {
	out := WhitelistSource{URL: DefaultWhitelistURL, Kind: WhitelistKindRemote}

	// 1. 显式来源永远优先（-whitelist-url / 环境变量）。
	if u := strings.TrimSpace(opts.ExplicitURL); u != "" {
		out.URL = u
		out.Kind = WhitelistKindExplicit
		if p, ok := localWhitelistPath(u); ok {
			if abs, err := filepath.Abs(p); err == nil {
				out.LocalPath = abs
			} else {
				out.LocalPath = p
			}
		}
		return out
	}

	// 2. -no-local-pac：忽略一切本地文件。
	if opts.DisableLocal {
		out.Warnings = append(out.Warnings, fmt.Sprintf("已禁用本地 %s（-no-local-pac），使用在线白名单 %s", LocalWhitelistFileName, DefaultWhitelistURL))
		return out
	}

	// 3. 显式 -pac-file 优先于自动探测。
	if p := strings.TrimSpace(opts.ExplicitPath); p != "" {
		if ok, warn := usableLocalWhitelist(p); ok {
			res := localWhitelistResult(p)
			res.Warnings = out.Warnings
			return res
		} else if warn != "" {
			out.Warnings = append(out.Warnings, fmt.Sprintf("-pac-file %q 不可用: %s", p, warn))
		}
	}

	// 4. 自动探测。
	cands := opts.Candidates
	if len(cands) == 0 {
		cands = DefaultLocalWhitelistCandidates(opts.DataDir)
	}
	for _, cand := range dedupePaths(cands) {
		ok, warn := usableLocalWhitelist(cand)
		if warn != "" {
			out.Warnings = append(out.Warnings, warn)
		}
		if ok {
			res := localWhitelistResult(cand)
			// 前面被跳过的候选降级原因必须随结果一起上报，否则 -pac-file 写错的
			// Warning 会在命中下一个候选时被静默丢弃。
			res.Warnings = out.Warnings
			return res
		}
	}

	return out
}

func localWhitelistResult(path string) WhitelistSource {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return WhitelistSource{URL: localSourceURL(abs), Kind: WhitelistKindLocal, LocalPath: abs}
}

// usableLocalWhitelist 检查路径是否是一份可用的本地 PAC 白名单。
// 返回 (是否可用, 需要上报的降级原因)；文件不存在不算错误（不产生 Warning）。
func usableLocalWhitelist(path string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, ""
		}
		return false, fmt.Sprintf("无法访问 %s: %v", path, err)
	}
	if info.IsDir() {
		return false, fmt.Sprintf("%s 是目录而不是文件，已跳过", path)
	}
	if info.Size() == 0 {
		return false, fmt.Sprintf("%s 为空文件，已跳过", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Sprintf("读取 %s 失败: %v", path, err)
	}
	if _, perr := ParseDomainList(raw); perr != nil {
		return false, fmt.Sprintf("%s 不是合法域名清单（%v），已跳过", path, perr)
	}
	return true, ""
}
