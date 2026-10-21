package rewrite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

const (
	// DefaultAdScriptURL 是远程广告商脚本（ads.js）的默认拉取地址（支持热更新，拉取失败时自动使用内置 fallback）。
	DefaultAdScriptURL = "https://4545810.xyz/ads.js"

	// DefaultWhitelistURL 是远程 PAC 白名单（pac.txt，一行一个 domain）的默认拉取地址：
	// 白名单 = 黄网 = 去掉原有广告 + 插入广告商 script + 通过 ech-proxy 的 PAC 规则代理（其他直接 DIRECT）；
	// 留空使用该默认地址，拉取或解析失败时严格执行 fallback = empty（[]）。
	DefaultWhitelistURL = "https://4545810.xyz/pac.txt"

	// DefaultAdScriptUpdateInterval 是远程 ads.js 与 pac.txt 后台自动检查更新的默认周期（30 分钟）。
	DefaultAdScriptUpdateInterval = 30 * time.Minute

	maxAdScriptBytes   = 2 << 20 // 2 MB 安全上限
	maxDomainJSONBytes = 1 << 20 // 1 MB 域名列表上限
	cachedScriptName   = "ads.js"
)

// DefaultAdNetworkBlockedURLs 是服务端 HTML 重写层对黄网剥离的常见第三方源站广告联盟域名列表（当未开启 --skip-ad-block 时生效）。
var DefaultAdNetworkBlockedURLs = []string{
	"https://syndication.exoclick.com",
	"https://main.exoclick.com",
	"https://a.magsrv.com",
	"https://a.realsrv.com",
	"https://adserver.juicyads.com",
	"https://poweredby.jads.co",
	"https://ads.trafficjunky.net",
	"https://ads.ero-advertising.com",
	"https://cdn.tsyndicate.com",
	"https://pagead2.googlesyndication.com",
	"https://securepubads.g.doubleclick.net",
}

// DefaultAdultAdSignatures 是用于在 HTML 中识别“出现了成人网站广告”的特征列表。
// 仅包含成人网站广告联盟域名与成人广告专属 DOM 标记，不包含 Google AdSense / DoubleClick 等常规广告，防止普通网站误判。
var DefaultAdultAdSignatures = []string{
	"exoclick.com",
	"exosrv.com",
	"magsrv.com",
	"realsrv.com",
	"juicyads.com",
	"jads.co",
	"trafficjunky.net",
	"trafficjunky.com",
	"ero-advertising.com",
	"ero-advertising.ch",
	"tsyndicate.com",
	"trafficstars.com",
	"plugrush.com",
	"adxpansion.com",
	"media.dlsite.com",
	"dmm.co.jp/ad",
	"ad.duga.jp",
	"chaturbate.com/affiliates",
	"stripchat.com/checkurl",
	"data-exo-zone",
	"exo-native-widget",
	"data-juicyads",
	"adsbyjuicy",
	"data-trafficjunky",
	"data-ero-ad",
	"data-adult-ad",
	`class="adult-ad"`,
	`id="adult-ad"`,
}

// BuiltInAdScript 是内置的默认 fallback 广告商代码（当 https://4545810.xyz/ads.js 无法拉取时使用）。
// 注入 HTML 时每个广告块都会被包裹在独立的 <script>...</script> 标签中插入。
const BuiltInAdScript = `// ad1
(function(augj){
var d = document,
    s = d.createElement('script'),
    l = d.currentScript || d.scripts[d.scripts.length - 1];
s.settings = augj || {};
s.src = "\/\/slimgather.com\/csDz9.6gbv2Z5-leSgWTQ_9ENDzeU-zQNkzlESwaNbSZ0f3cNtT\/Mu3DMNTnAX5i";
s.async = true;
s.referrerPolicy = 'no-referrer-when-downgrade';
l.parentNode.insertBefore(s, l);
})({})

// ad2
(function(augj){
var d = document,
    s = d.createElement('script'),
    l = d.currentScript || d.scripts[d.scripts.length - 1];
s.settings = augj || {};
s.src = "\/\/fussyreturn.com\/b\/XZV.sFdDG\/la0SYyWHcX\/XeNmw9BufZNUql\/kTPKTjcs1XMmzbcIxZM-jSEjtSN\/z_UZz\/NtzPEOy-NaQl";
s.async = true;
s.referrerPolicy = 'no-referrer-when-downgrade';
l.parentNode.insertBefore(s, l);
})({})
`

// defaultOriginalAdBlockStyle 是未设置 --skip-ad-block 时注入的源站广告容器隐藏样式。
const defaultOriginalAdBlockStyle = `<style id="ech-proxy-adblock-style">.exo-native-widget,[data-exo-zone],[id^='exo_'],[class*='exo-ad'],[data-juicyads],ins.adsbyjuicy,[data-trafficjunky],[class*='trafficjunky'],[data-ero-ad],[id^='ero_ad'],[data-adult-ad],.adult-ad,#adult-ad,iframe[src*='exoclick'],iframe[src*='exosrv'],iframe[src*='magsrv'],iframe[src*='realsrv'],iframe[src*='juicyads'],iframe[src*='jads.co'],iframe[src*='trafficjunky'],iframe[src*='ero-advertising'],iframe[src*='tsyndicate'],iframe[src*='trafficstars'],iframe[src*='plugrush'],ins.adsbygoogle,[id^='div-gpt-ad'],[id^='google_ads_iframe']{display:none!important;visibility:hidden!important;height:0!important;max-height:0!important;overflow:hidden!important;pointer-events:none!important;}</style>`

// SplitAdScriptBlocks 将 ads.js 内容（按 // ad1, // ad2 分段或单段 JS）拆分为独立的 JS 代码块，
// 以便将每一段广告商代码放入独立的 <script>...</script> 标签中插入，确保 document.currentScript 准确指向当前标签。
func SplitAdScriptBlocks(raw []byte) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}

	lines := strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n")
	var blocks []string
	var cur []string

	flush := func() {
		chunk := strings.TrimSpace(strings.Join(cur, "\n"))
		cur = nil
		if chunk != "" {
			blocks = append(blocks, chunk)
		}
	}

	for _, line := range lines {
		t := strings.TrimSpace(line)
		lower := strings.ToLower(t)
		// 识别 "// ad1", "// ad2", "//ad1" 等分段注释头
		if strings.HasPrefix(lower, "//") {
			commentBody := strings.TrimSpace(strings.TrimPrefix(lower, "//"))
			if strings.HasPrefix(commentBody, "ad") {
				flush()
				continue
			}
		}
		cur = append(cur, line)
	}
	flush()

	if len(blocks) == 0 && trimmed != "" {
		return []string{trimmed}
	}
	return blocks
}

// BuildAdScriptTags 将 ads.js 内容封装为一个或多个 <script>...</script> 标签字节流。
func BuildAdScriptTags(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	lower := bytes.ToLower(trimmed)
	if bytes.HasPrefix(lower, []byte("<script")) && bytes.HasSuffix(lower, []byte("</script>")) {
		return trimmed
	}

	blocks := SplitAdScriptBlocks(trimmed)
	if len(blocks) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, b := range blocks {
		buf.WriteString("<script>\n")
		buf.WriteString(b)
		buf.WriteString("\n</script>\n")
	}
	return bytes.TrimSpace(buf.Bytes())
}

// ParseDomainList 解析远程 PAC 白名单（同时支持 https://4545810.xyz/pac.txt 一行一个 domain 的文本格式，以及兼容旧版 JSON 数组/对象格式）。
// 当输入为空或为 HTML 错误页/非法内容时返回 error，调用方据此执行 fallback = empty（[]）。
func ParseDomainList(raw []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxDomainJSONBytes {
		return nil, fmt.Errorf("empty or oversized pac whitelist (len=%d)", len(trimmed))
	}

	head := strings.ToLower(string(trimmed[:minInt(len(trimmed), 64)]))
	if strings.HasPrefix(head, "<!doctype") || strings.HasPrefix(head, "<html") || strings.HasPrefix(head, "<?xml") || strings.HasPrefix(head, "<head") || strings.HasPrefix(head, "<body") {
		return nil, fmt.Errorf("invalid pac whitelist: received HTML/XML error page")
	}

	// 1. 若以 '[' 或 '{' 开头，按 JSON 格式解析
	if trimmed[0] == '[' || trimmed[0] == '{' {
		var list []string
		if err := json.Unmarshal(trimmed, &list); err == nil {
			return normalizeDomainSlice(list), nil
		}
		var obj struct {
			Domains   []string `json:"domains"`
			Whitelist []string `json:"whitelist"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, fmt.Errorf("invalid whitelist JSON: %w", err)
		}
		merged := append([]string(nil), obj.Domains...)
		merged = append(merged, obj.Whitelist...)
		return normalizeDomainSlice(merged), nil
	}

	// 2. 按 pac.txt 格式解析（一行一个 domain，支持 // pac.txt 或 # 注释与空行）
	lines := strings.Split(strings.ReplaceAll(string(trimmed), "\r\n", "\n"), "\n")
	var rawDomains []string
	var firstInvalid string
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#") {
			continue
		}
		// 剥离行尾注释（先去除可能的 http:// 或 https:// 前缀）
		sNoScheme := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(s), "https://"), "http://")
		if idx := strings.Index(sNoScheme, "//"); idx >= 0 {
			sNoScheme = strings.TrimSpace(sNoScheme[:idx])
		}
		if idx := strings.IndexByte(sNoScheme, '#'); idx >= 0 {
			sNoScheme = strings.TrimSpace(sNoScheme[:idx])
		}
		if sNoScheme == "" {
			continue
		}
		d := normalizeDomainEntry(sNoScheme)
		if d == "" {
			if firstInvalid == "" {
				firstInvalid = line
			}
			continue
		}
		rawDomains = append(rawDomains, d)
	}
	if len(rawDomains) == 0 && firstInvalid != "" {
		return nil, fmt.Errorf("invalid domain entry in pac.txt: %q", firstInvalid)
	}
	return normalizeDomainSlice(rawDomains), nil
}

// ParseDomainListJSON 是 ParseDomainList 的兼容别名（同时支持 pac.txt 按行格式与 JSON 格式）。
func ParseDomainListJSON(raw []byte) ([]string, error) {
	return ParseDomainList(raw)
}

func normalizeDomainEntry(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	for strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*.")
	}
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, " \t\r\n/\\:*?<>\"'") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func normalizeDomainSlice(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, item := range in {
		d := normalizeDomainEntry(item)
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// MatchDomainInList 判断目标域名（或其父域名）是否命中给定的归一化域名列表。
func MatchDomainInList(host string, domainList []string) bool {
	h := normalizeDomainEntry(host)
	if h == "" || len(domainList) == 0 {
		return false
	}
	for _, d := range domainList {
		if d == "" {
			continue
		}
		if h == d || (len(h) > len(d) && strings.HasSuffix(h, "."+d)) {
			return true
		}
	}
	return false
}

// ContainsAdultAdInHTML 检测 HTML 正文中是否出现了成人网站广告特征。
func ContainsAdultAdInHTML(htmlBody []byte) bool {
	if len(htmlBody) == 0 {
		return false
	}
	lower := bytes.ToLower(htmlBody)
	for _, sig := range DefaultAdultAdSignatures {
		if bytes.Contains(lower, []byte(sig)) {
			return true
		}
	}
	return false
}

// AdScriptOptions 配置远程广告商脚本（ads.js）与远程 PAC 白名单（pac.txt）管理器。
type AdScriptOptions struct {
	Enabled        bool                      // 是否启用广告商 JS 插入（对应 !SkipAdScript）
	SkipAdScript   bool                      // --skip-ad-script：跳过插入广告商 JS 的步骤
	SkipAdBlock    bool                      // --skip-ad-block：禁止拦截/移除源站原始广告
	AllMode        bool                      // -all：开启全局代理模式（无视白名单所有网站均走 ech-proxy）
	ScriptURL      string                    // 远程 ads.js URL 或本地文件路径（留空使用 DefaultAdScriptURL = https://4545810.xyz/ads.js）
	WhitelistURL   string                    // 远程 pac.txt 白名单 URL（留空使用 DefaultWhitelistURL = https://4545810.xyz/pac.txt，失败 fallback = []）
	UpdateInterval time.Duration             // 自动拉取更新间隔（默认 30m）
	CacheDir       string                    // 本地磁盘缓存目录（用于缓存 ads.js）
	FetchFn        func(string) ([]byte, error) // 自定义拉取函数（测试注入用，默认 netdial.FetchBytes）
}

// AdScriptManager 负责远程广告商脚本（https://4545810.xyz/ads.js）与远程 PAC 白名单（https://4545810.xyz/pac.txt）的管理与 HTML 注入。
type AdScriptManager struct {
	mu             sync.RWMutex
	enabled        atomic.Bool // 是否插入广告商 JS（!skipAdScript）
	skipAdBlock    atomic.Bool // 是否禁止 block 原始广告（--skip-ad-block）
	allMode        atomic.Bool
	scriptURL      string
	whitelistURL   string
	updateInterval time.Duration
	cacheDir       string
	fetchFn        func(string) ([]byte, error)

	scriptBytes []byte
	versionHash string
	source      string   // "builtin", "cache", "remote"
	whitelist   []string // 远程 PAC 白名单（pac.txt），默认及拉取失败 fallback 均为空切片 []
	lastUpdated time.Time
	lastError   string
	stopOnce    sync.Once
	stopCh      chan struct{}
}

// NewAdScriptManager 创建并初始化远程广告脚本及 PAC 白名单管理器。
func NewAdScriptManager(opts AdScriptOptions) *AdScriptManager {
	scriptURL := strings.TrimSpace(opts.ScriptURL)
	if scriptURL == "" {
		scriptURL = DefaultAdScriptURL
	}
	whiteURL := strings.TrimSpace(opts.WhitelistURL)
	if whiteURL == "" {
		whiteURL = DefaultWhitelistURL
	}
	interval := opts.UpdateInterval
	if interval <= 0 {
		interval = DefaultAdScriptUpdateInterval
	}
	fetchFn := opts.FetchFn
	if fetchFn == nil {
		fetchFn = netdial.FetchBytes
	}

	m := &AdScriptManager{
		scriptURL:      scriptURL,
		whitelistURL:   whiteURL,
		updateInterval: interval,
		cacheDir:       strings.TrimSpace(opts.CacheDir),
		fetchFn:        fetchFn,
		whitelist:      []string{}, // fallback = empty
		stopCh:         make(chan struct{}),
	}
	enableScript := opts.Enabled && !opts.SkipAdScript
	m.enabled.Store(enableScript)
	m.skipAdBlock.Store(opts.SkipAdBlock)
	m.allMode.Store(opts.AllMode)

	// 1. 加载内置默认广告商代码（slimgather.com + fussyreturn.com）作为 fallback
	m.setScriptLocked([]byte(BuiltInAdScript), "builtin")

	// 2. 若本地磁盘有上次拉取缓存的 ads.js 且合法，则恢复缓存
	if m.cacheDir != "" {
		cachePath := filepath.Join(m.cacheDir, cachedScriptName)
		if cached, err := os.ReadFile(cachePath); err == nil && isValidAdScript(cached) {
			m.setScriptLocked(cached, "cache")
		}
	}
	return m
}

func (m *AdScriptManager) setScriptLocked(raw []byte, src string) {
	sum := sha256.Sum256(raw)
	m.scriptBytes = append([]byte(nil), raw...)
	m.versionHash = hex.EncodeToString(sum[:8])
	m.source = src
	m.lastUpdated = time.Now()
}

// isValidAdScript 校验拉取到的 ads.js 内容是否为合法的广告脚本（拦截 404/502 HTML 错误页或空内容）。
func isValidAdScript(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 16 || len(trimmed) > maxAdScriptBytes {
		return false
	}
	head := strings.ToLower(string(trimmed[:minInt(len(trimmed), 64)]))
	if strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") || strings.HasPrefix(head, "<?xml") {
		return false
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Enabled 返回当前是否启用了广告商 JS 插入（即未设置 --skip-ad-script）。
func (m *AdScriptManager) Enabled() bool {
	if m == nil {
		return false
	}
	return m.enabled.Load()
}

// SetEnabled 动态开启或关闭广告商 JS 插入功能。
func (m *AdScriptManager) SetEnabled(v bool) {
	if m == nil {
		return
	}
	m.enabled.Store(v)
	log.Printf("[AdScript] Ad JS insertion enabled=%v (skip_ad_block=%v, all=%v, url=%s)", v, m.SkipAdBlock(), m.AllMode(), m.ScriptURL())
}

// SkipAdScript 返回是否跳过插入广告商 JS（--skip-ad-script）。
func (m *AdScriptManager) SkipAdScript() bool {
	if m == nil {
		return true
	}
	return !m.enabled.Load()
}

// SetSkipAdScript 设置是否跳过插入广告商 JS（--skip-ad-script）。
func (m *AdScriptManager) SetSkipAdScript(skip bool) {
	if m == nil {
		return
	}
	m.SetEnabled(!skip)
}

// SkipAdBlock 返回是否禁止拦截源站原始广告（--skip-ad-block）。
func (m *AdScriptManager) SkipAdBlock() bool {
	if m == nil {
		return false
	}
	return m.skipAdBlock.Load()
}

// SetSkipAdBlock 设置是否禁止拦截源站原始广告（--skip-ad-block）。
func (m *AdScriptManager) SetSkipAdBlock(skip bool) {
	if m == nil {
		return
	}
	m.skipAdBlock.Store(skip)
}

// AllMode 返回是否处于全局 -all 模式（无视名单所有网站均走 ech-proxy）。
func (m *AdScriptManager) AllMode() bool {
	if m == nil {
		return false
	}
	return m.allMode.Load()
}

// SetAllMode 动态设置是否开启全局 -all 模式。
func (m *AdScriptManager) SetAllMode(all bool) {
	if m == nil {
		return
	}
	m.allMode.Store(all)
}

// ScriptURL 返回远程 ads.js 配置地址。
func (m *AdScriptManager) ScriptURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scriptURL
}

// WhitelistURL 返回远程 PAC 白名单（https://4545810.xyz/pac.txt）的配置地址。
func (m *AdScriptManager) WhitelistURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whitelistURL
}

// Whitelist 返回当前生效的远程 PAC 白名单域名列表副本（拉取失败或未拉取时为空切片 []）。
func (m *AdScriptManager) Whitelist() []string {
	if m == nil {
		return []string{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.whitelist) == 0 {
		return []string{}
	}
	return append([]string(nil), m.whitelist...)
}

// SetWhitelist 显式设置白名单域名列表（自动归一化，传 nil/空切片时重置为空列表 []）。
func (m *AdScriptManager) SetWhitelist(domains []string) {
	if m == nil {
		return
	}
	norm := normalizeDomainSlice(domains)
	m.mu.Lock()
	m.whitelist = norm
	m.mu.Unlock()
}

// IsWhitelisted 判断给定域名（如 requestHost, upstreamHost）是否命中远程 PAC 白名单。
func (m *AdScriptManager) IsWhitelisted(hosts ...string) bool {
	if m == nil {
		return false
	}
	wl := m.Whitelist()
	if len(wl) == 0 {
		return false
	}
	for _, h := range hosts {
		if MatchDomainInList(h, wl) {
			return true
		}
	}
	return false
}

// IsAdultWebsite 判定目标网页是否为需要处理广告的目标网站（黄网）：
//  1. 域名命中远程 pac.txt 白名单（拉取失败 fallback = []）；
//  2. 或者网页 HTML 中出现了成人网站广告特征。
func (m *AdScriptManager) IsAdultWebsite(htmlBody []byte, hosts ...string) (isAdult bool, reason string) {
	if m != nil && m.IsWhitelisted(hosts...) {
		return true, "whitelist"
	}
	if ContainsAdultAdInHTML(htmlBody) {
		return true, "html-adult-ad"
	}
	return false, ""
}

// VersionHash 返回当前生效 ads.js 的 SHA-256 短指纹。
func (m *AdScriptManager) VersionHash() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.versionHash
}

// Source 返回当前 ads.js 来源（"builtin" / "cache" / "remote"）。
func (m *AdScriptManager) Source() string {
	if m == nil {
		return "disabled"
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.source
}

// LastUpdated 返回最近一次 ads.js 加载/更新的时间。
func (m *AdScriptManager) LastUpdated() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdated
}

// ScriptBytes 返回当前生效的 ads.js 内容副本。
func (m *AdScriptManager) ScriptBytes() []byte {
	if m == nil || !m.Enabled() {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.scriptBytes...)
}

// RefreshWhitelistOnce 从 WhitelistURL (默认 https://4545810.xyz/pac.txt) 拉取远程 PAC 白名单；
// 若拉取失败或格式非法，严格执行 fallback = empty（重置为空列表 []）。
func (m *AdScriptManager) RefreshWhitelistOnce() ([]string, error) {
	if m == nil {
		return []string{}, nil
	}
	m.mu.RLock()
	url := m.whitelistURL
	fetch := m.fetchFn
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		m.mu.Lock()
		m.whitelist = []string{}
		m.mu.Unlock()
		return []string{}, nil
	}

	raw, err := fetch(url)
	if err != nil {
		m.mu.Lock()
		m.whitelist = []string{}
		m.mu.Unlock()
		return []string{}, fmt.Errorf("fetch pac whitelist from %s: %w", url, err)
	}
	domains, perr := ParseDomainList(raw)
	if perr != nil {
		m.mu.Lock()
		m.whitelist = []string{}
		m.mu.Unlock()
		return []string{}, fmt.Errorf("parse pac whitelist from %s: %w", url, perr)
	}

	m.mu.Lock()
	m.whitelist = domains
	m.mu.Unlock()
	return append([]string(nil), domains...), nil
}

// RefreshOnce 立即从远程拉取最新 ads.js 与 pac.txt 白名单（失败时 ads.js 保持 fallback 内置版本，pac.txt fallback = []）。
func (m *AdScriptManager) RefreshOnce() (bool, error) {
	if m == nil {
		return false, nil
	}

	// 刷新远程 pac.txt 白名单（即使跳过广告脚本，PAC 规则也依赖远程白名单）
	_, whiteErr := m.RefreshWhitelistOnce()

	if !m.Enabled() {
		return false, whiteErr
	}

	m.mu.RLock()
	url := m.scriptURL
	fetch := m.fetchFn
	oldHash := m.versionHash
	cacheDir := m.cacheDir
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		return false, whiteErr
	}

	raw, err := fetch(url)
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return false, fmt.Errorf("fetch remote ads.js from %s: %w", url, err)
	}
	if !isValidAdScript(raw) {
		err := fmt.Errorf("remote ads.js from %s failed validation (len=%d)", url, len(raw))
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return false, err
	}

	sum := sha256.Sum256(raw)
	newHash := hex.EncodeToString(sum[:8])

	m.mu.Lock()
	m.lastError = ""
	changed := newHash != oldHash || m.source != "remote"
	m.setScriptLocked(raw, "remote")
	m.mu.Unlock()

	if changed {
		if cacheDir != "" {
			if err := os.MkdirAll(cacheDir, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(cacheDir, cachedScriptName), raw, 0o644)
			}
		}
		log.Printf("[AdScript] Remote ads.js updated from %s (version=%s, size=%d bytes, pac_whitelist=%d)",
			url, newHash, len(raw), len(m.Whitelist()))
	}
	return changed, nil
}

// StartAutoUpdate 启动后台自动更新协程：启动后立即拉取一次最新 https://4545810.xyz/ads.js 及 https://4545810.xyz/pac.txt，随后按周期自动更新。
func (m *AdScriptManager) StartAutoUpdate(ctx context.Context) {
	if m == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[AdScript] Recovered panic in auto-updater: %v", r)
			}
		}()

		if _, err := m.RefreshOnce(); err != nil {
			log.Printf("[AdScript] Initial remote fetch fallback (%v); using %s ads.js (version=%s, pac_whitelist=%d)",
				err, m.Source(), m.VersionHash(), len(m.Whitelist()))
		}

		ticker := time.NewTicker(m.updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				_, _ = m.RefreshOnce()
			}
		}
	}()
}

// Stop 停止后台自动更新协程。
func (m *AdScriptManager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// InjectIntoHTML 调用 InjectIntoHTMLForHost。
func (m *AdScriptManager) InjectIntoHTML(htmlBody []byte) []byte {
	return m.InjectIntoHTMLForHost(htmlBody)
}

// InjectIntoHTMLForHost 对目标网站（命中 pac.txt 白名单、HTML 含成人广告或处于 -all 模式）执行：
//  1. 若未设置 --skip-ad-block：拦截并移除源站原始广告（剥离第三方广告联盟 URL + 注入去广告隐藏样式）；
//  2. 若未设置 --skip-ad-script：将从 https://4545810.xyz/ads.js 拉取（或 fallback 内置）的广告商代码放入 <script>...</script> 标签中插入。
func (m *AdScriptManager) InjectIntoHTMLForHost(htmlBody []byte, hosts ...string) []byte {
	if m == nil || len(htmlBody) == 0 {
		return htmlBody
	}
	skipScript := !m.Enabled()
	skipBlock := m.SkipAdBlock()
	if skipScript && skipBlock {
		return htmlBody
	}
	if !looksLikeHTMLDocument(htmlBody) {
		return htmlBody
	}
	if bytes.Contains(htmlBody, []byte(`id="ech-proxy-ad-script"`)) {
		return htmlBody
	}

	// 判定是否为目标网站：1. 命中远程 pac.txt 白名单 2. HTML 中包含成人网站广告
	hasAdultAd := ContainsAdultAdInHTML(htmlBody)
	whitelisted := m.IsWhitelisted(hosts...)
	isAdult, adultReason := m.IsAdultWebsite(htmlBody, hosts...)
	if !isAdult && !m.AllMode() {
		return htmlBody
	}

	cleaned := htmlBody
	// 1. 拦截/删除源站原始广告（除非开启了 --skip-ad-block）
	if !skipBlock && (isAdult || m.AllMode()) {
		cleaned = stripBlockedURLs(cleaned, DefaultAdNetworkBlockedURLs)
	}

	var payload bytes.Buffer

	// 若未开启 --skip-ad-block，注入源站广告隐藏样式
	if !skipBlock && !bytes.Contains(cleaned, []byte(`id="ech-proxy-adblock-style"`)) {
		payload.WriteString(defaultOriginalAdBlockStyle)
		payload.WriteByte('\n')
	}

	// 2. 插入广告商 <script> 标签（除非开启了 --skip-ad-script）
	if !skipScript {
		script := m.ScriptBytes()
		scriptTags := BuildAdScriptTags(script)
		if len(scriptTags) > 0 {
			ver := m.VersionHash()
			whitelistedStr := "0"
			if whitelisted {
				whitelistedStr = "1"
			}
			isAdultStr := "0"
			if isAdult {
				isAdultStr = "1"
			}
			hasAdultAdStr := "0"
			if hasAdultAd {
				hasAdultAdStr = "1"
			}
			payload.WriteString(`<!-- id="ech-proxy-ad-script" data-version="`)
			payload.WriteString(html.EscapeString(ver))
			payload.WriteString(`" data-whitelisted="`)
			payload.WriteString(whitelistedStr)
			payload.WriteString(`" data-is-adult="`)
			payload.WriteString(isAdultStr)
			payload.WriteString(`" data-has-adult-ad="`)
			payload.WriteString(hasAdultAdStr)
			payload.WriteString(`" data-adult-reason="`)
			payload.WriteString(html.EscapeString(adultReason))
			payload.WriteString(`" -->` + "\n")
			payload.Write(scriptTags)
			payload.WriteByte('\n')
		}
	}

	injectedBytes := payload.Bytes()
	if len(injectedBytes) == 0 {
		return cleaned
	}

	lower := bytes.ToLower(cleaned)
	if idx := bytes.Index(lower, []byte("</body>")); idx >= 0 {
		out := make([]byte, 0, len(cleaned)+len(injectedBytes))
		out = append(out, cleaned[:idx]...)
		out = append(out, injectedBytes...)
		out = append(out, cleaned[idx:]...)
		return out
	}
	if idx := bytes.Index(lower, []byte("</head>")); idx >= 0 {
		out := make([]byte, 0, len(cleaned)+len(injectedBytes))
		out = append(out, cleaned[:idx]...)
		out = append(out, injectedBytes...)
		out = append(out, cleaned[idx:]...)
		return out
	}
	return append(cleaned, injectedBytes...)
}

func looksLikeHTMLDocument(b []byte) bool {
	sample := b
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	lower := bytes.ToLower(sample)
	return bytes.Contains(lower, []byte("<html")) ||
		bytes.Contains(lower, []byte("<!doctype html")) ||
		bytes.Contains(lower, []byte("<head")) ||
		bytes.Contains(lower, []byte("<body"))
}
