package rewrite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

const (
	// DefaultAdScriptURL 是 PAC 方案专属的远程广告商脚本（ads.js）默认地址（失败自动使用内置 fallback）。
	DefaultAdScriptURL = "https://" + netdial.DefaultSiteHost + "/ads.js"

	// DefaultWhitelistURL 是 PAC 方案专属的远程白名单（pac.txt，一行一个 domain）默认地址（失败 fallback = []）。
	DefaultWhitelistURL = "https://" + netdial.DefaultSiteHost + "/pac.txt"

	// DefaultAdultSitesURL 是「成人网站清单」（adult.txt，一行一个 domain）默认地址 ——
	// 与 pac.txt 并列的第二个文件：pac.txt 只决定 PAC 路由，adult.txt 决定是否去广告 + 插入自有广告。
	// 采用手动维护，不再依赖 HTML 自动检测。
	DefaultAdultSitesURL = "https://" + netdial.DefaultSiteHost + "/adult.txt"

	// DefaultBlocklistURL 是 PAC 方案专属的远程广告屏蔽规则（block.json）默认地址：
	//   - 兼容 JSON 数组/对象、EasyList ||domain^、##selector、HOSTS 格式；
	//   - 与 certs/ 路径完全解耦（certs/ 完全只与 8443 方案相关），拉取失败使用内存内置规则兜底。
	DefaultBlocklistURL = "https://" + netdial.DefaultSiteHost + "/block.json"

	// DefaultOnURL 是 PAC 方案专属的远程广告开关（on.txt）默认地址：
	//   - 对 on.txt 重试 2 次之后若仍失败，直接置 on（即开启显示广告，instead of 不显示）。
	DefaultOnURL = "https://" + netdial.DefaultSiteHost + "/on.txt"

	// DefaultOnRetryCount 是拉取 on.txt 失败后的重试次数（重试 2 次，即最多尝试 3 次；仍失败直接置 on）。
	DefaultOnRetryCount = 2

	// DefaultEasyListURL 是 EasyList 网络过滤清单（只取「域名 / 域名+path」子集）。
	DefaultEasyListURL = "https://easylist.to/easylist/easylist.txt"

	// DefaultAdsAllowlistURL 是 EasyList 拦截的放行清单（ads.txt，一行一个 host/path，必须带 path）。
	DefaultAdsAllowlistURL = "https://" + netdial.DefaultSiteHost + "/ads.txt"

	// DefaultAdScriptUpdateInterval 是远程配置后台自动检查更新周期（30 分钟）。
	DefaultAdScriptUpdateInterval = 30 * time.Minute

	maxAdScriptBytes   = 2 << 20
	maxDomainJSONBytes = 1 << 20
	cachedScriptName   = "ads.js"
)

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

var DefaultAdultAdSignatures = []string{
	"exoclick.com", "exosrv.com", "magsrv.com", "realsrv.com",
	"juicyads.com", "jads.co", "trafficjunky.net", "trafficjunky.com",
	"ero-advertising.com", "ero-advertising.ch", "tsyndicate.com",
	"trafficstars.com", "plugrush.com", "adxpansion.com",
	"media.dlsite.com", "dmm.co.jp/ad", "ad.duga.jp",
	"chaturbate.com/affiliates", "stripchat.com/checkurl",
	"data-exo-zone", "exo-native-widget", "data-juicyads", "adsbyjuicy",
	"data-trafficjunky", "data-ero-ad", "data-adult-ad",
	`class="adult-ad"`, `id="adult-ad"`,
}

var DefaultAdBlockSelectors = []string{
	".exo-native-widget", "[data-exo-zone]", "[id^='exo_']", "[class*='exo-ad']",
	"[data-juicyads]", "ins.adsbyjuicy", "[data-trafficjunky]", "[class*='trafficjunky']",
	"[data-ero-ad]", "[id^='ero_ad']", "[data-adult-ad]", ".adult-ad", "#adult-ad",
	"iframe[src*='exoclick']", "iframe[src*='exosrv']", "iframe[src*='magsrv']",
	"iframe[src*='realsrv']", "iframe[src*='juicyads']", "iframe[src*='jads.co']",
	"iframe[src*='trafficjunky']", "iframe[src*='ero-advertising']",
	"iframe[src*='tsyndicate']", "iframe[src*='trafficstars']", "iframe[src*='plugrush']",
	"ins.adsbygoogle", "[id^='div-gpt-ad']", "[id^='google_ads_iframe']",
}

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

const defaultOriginalAdBlockStyle = `<style id="ech-proxy-adblock-style">.exo-native-widget,[data-exo-zone],[id^='exo_'],[class*='exo-ad'],[data-juicyads],ins.adsbyjuicy,[data-trafficjunky],[class*='trafficjunky'],[data-ero-ad],[id^='ero_ad'],[data-adult-ad],.adult-ad,#adult-ad,iframe[src*='exoclick'],iframe[src*='exosrv'],iframe[src*='magsrv'],iframe[src*='realsrv'],iframe[src*='juicyads'],iframe[src*='jads.co'],iframe[src*='trafficjunky'],iframe[src*='ero-advertising'],iframe[src*='tsyndicate'],iframe[src*='trafficstars'],iframe[src*='plugrush'],ins.adsbygoogle,[id^='div-gpt-ad'],[id^='google_ads_iframe']{display:none!important;visibility:hidden!important;height:0!important;max-height:0!important;overflow:hidden!important;pointer-events:none!important;}</style>`

// BlocklistRules 表示从 block.json 解析出的广告拦截规则集合（与 certs/ 完全解耦）。
type BlocklistRules struct {
	Domains     []string `json:"domains,omitempty"`
	BlockedURLs []string `json:"blocked_urls,omitempty"`
	Selectors   []string `json:"selectors,omitempty"`
}

func isHTMLOrXMLErrorPage(trimmed []byte) bool {
	headLen := len(trimmed)
	if headLen > 64 {
		headLen = 64
	}
	head := strings.ToLower(string(trimmed[:headLen]))
	for _, p := range []string{"<!doctype", "<html", "<?xml", "<head", "<body"} {
		if strings.HasPrefix(head, p) {
			return true
		}
	}
	return false
}

// ParseOnSwitch 解析远程 on.txt 内容：
//   - "1", "true", "on", "yes", "enable", "enabled" -> true
//   - "0", "false", "off", "no", "disable", "disabled" -> false
//   - 空内容、HTML 错误页或未知值返回 error（供上层重试 2 次后直接置 on）。
func ParseOnSwitch(raw []byte) (bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > 4096 {
		return false, fmt.Errorf("empty or oversized on.txt (len=%d)", len(trimmed))
	}
	if isHTMLOrXMLErrorPage(trimmed) {
		return false, fmt.Errorf("invalid on.txt: received HTML/XML error page")
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(trimmed), "\r\n", "\n"), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#") {
			continue
		}
		if idx := strings.Index(s, "//"); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
		}
		if idx := strings.IndexByte(s, '#'); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
		}
		switch strings.ToLower(s) {
		case "1", "true", "on", "yes", "enable", "enabled":
			return true, nil
		case "0", "false", "off", "no", "disable", "disabled":
			return false, nil
		default:
			return false, fmt.Errorf("unrecognized on.txt value: %q", s)
		}
	}
	return false, fmt.Errorf("no valid switch token in on.txt")
}

// ParseBlocklist 解析远程 block.json 规则（兼容 JSON 数组/对象、EasyList ||domain^、##selector、HOSTS 格式）。
func ParseBlocklist(raw []byte) (BlocklistRules, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxDomainJSONBytes {
		return BlocklistRules{}, fmt.Errorf("empty or oversized blocklist (len=%d)", len(trimmed))
	}
	if isHTMLOrXMLErrorPage(trimmed) {
		return BlocklistRules{}, fmt.Errorf("invalid blocklist: received HTML/XML error page")
	}

	var entries []string
	var explicitSelectors []string

	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return BlocklistRules{}, fmt.Errorf("invalid block.json array: %w", err)
		}
	} else if trimmed[0] == '{' {
		var obj struct {
			Domains      []string `json:"domains"`
			Hosts        []string `json:"hosts"`
			BlockedHosts []string `json:"blocked_hosts"`
			BlockedURLs  []string `json:"blocked_urls"`
			URLs         []string `json:"urls"`
			Rules        []string `json:"rules"`
			Blocklist    []string `json:"blocklist"`
			Ads          []string `json:"ads"`
			Selectors    []string `json:"selectors"`
			CSS          []string `json:"css"`
			Elements     []string `json:"elements"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return BlocklistRules{}, fmt.Errorf("invalid block.json object: %w", err)
		}
		entries = append(entries, obj.Domains...)
		entries = append(entries, obj.Hosts...)
		entries = append(entries, obj.BlockedHosts...)
		entries = append(entries, obj.BlockedURLs...)
		entries = append(entries, obj.URLs...)
		entries = append(entries, obj.Rules...)
		entries = append(entries, obj.Blocklist...)
		entries = append(entries, obj.Ads...)
		explicitSelectors = append(explicitSelectors, obj.Selectors...)
		explicitSelectors = append(explicitSelectors, obj.CSS...)
		explicitSelectors = append(explicitSelectors, obj.Elements...)
	} else {
		entries = strings.Split(strings.ReplaceAll(string(trimmed), "\r\n", "\n"), "\n")
	}

	domainSeen := make(map[string]bool)
	urlSeen := make(map[string]bool)
	selSeen := make(map[string]bool)
	var out BlocklistRules

	addDomain := func(d string) {
		norm := netdial.NormalizeDomainEntry(d)
		if norm == "" || norm == "localhost" || norm == "localhost.localdomain" || norm == "local" || norm == "broadcasthost" {
			return
		}
		if !domainSeen[norm] {
			domainSeen[norm] = true
			out.Domains = append(out.Domains, norm)
		}
		u := "https://" + norm
		if !urlSeen[u] {
			urlSeen[u] = true
			out.BlockedURLs = append(out.BlockedURLs, u)
		}
	}

	addURL := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if !urlSeen[u] {
			urlSeen[u] = true
			out.BlockedURLs = append(out.BlockedURLs, u)
		}
		if d := netdial.NormalizeDomainEntry(u); d != "" && !domainSeen[d] {
			domainSeen[d] = true
			out.Domains = append(out.Domains, d)
		}
	}

	addSelector := func(sel string) {
		sel = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sel), "##"))
		if sel == "" || strings.ContainsAny(sel, "{}") {
			return
		}
		if !selSeen[sel] {
			selSeen[sel] = true
			out.Selectors = append(out.Selectors, sel)
		}
	}

	for _, sel := range explicitSelectors {
		addSelector(sel)
	}

	for _, rawLine := range entries {
		s := strings.TrimSpace(rawLine)
		if s == "" || strings.HasPrefix(s, "!") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "[") || strings.HasPrefix(s, "@@") || strings.Contains(s, "#@#") {
			continue
		}
		// EasyList element hiding rule: ##selector or domain.com##selector
		if idx := strings.Index(s, "##"); idx >= 0 {
			addSelector(s[idx+2:])
			continue
		}
		// Pure comment starting with single #
		if strings.HasPrefix(s, "#") {
			continue
		}
		// EasyList ||domain^ or |https://...
		if strings.HasPrefix(s, "||") {
			rule := strings.TrimPrefix(s, "||")
			if optIdx := strings.IndexByte(rule, '$'); optIdx >= 0 {
				rule = rule[:optIdx]
			}
			rule = strings.TrimRight(rule, "^/")
			addDomain(rule)
			continue
		}
		if strings.HasPrefix(s, "|") {
			rule := strings.TrimPrefix(s, "|")
			if optIdx := strings.IndexByte(rule, '$'); optIdx >= 0 {
				rule = rule[:optIdx]
			}
			rule = strings.TrimRight(rule, "^")
			if strings.HasPrefix(strings.ToLower(rule), "http://") || strings.HasPrefix(strings.ToLower(rule), "https://") {
				addURL(rule)
			} else {
				addDomain(rule)
			}
			continue
		}
		// Strip inline # comment for HOSTS / plain domain lines
		if idx := strings.IndexByte(s, '#'); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
		}
		if s == "" {
			continue
		}
		// HOSTS format: 0.0.0.0 domain.com / 127.0.0.1 domain.com / ::1 domain.com
		fields := strings.Fields(s)
		if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1" || fields[0] == "::1" || fields[0] == "::" || fields[0] == "::0") {
			for _, f := range fields[1:] {
				addDomain(f)
			}
			continue
		}
		if strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://") {
			addURL(strings.TrimRight(s, "^/"))
			continue
		}
		if optIdx := strings.IndexByte(s, '$'); optIdx >= 0 {
			s = s[:optIdx]
		}
		s = strings.TrimRight(s, "^/")
		addDomain(s)
	}

	if len(out.Domains) == 0 && len(out.BlockedURLs) == 0 && len(out.Selectors) == 0 {
		return BlocklistRules{}, fmt.Errorf("no valid blocklist rules parsed")
	}
	return out, nil
}

func SplitAdScriptBlocks(raw []byte) []string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	var blocks, cur []string
	flush := func() {
		if chunk := strings.TrimSpace(strings.Join(cur, "\n")); chunk != "" {
			blocks = append(blocks, chunk)
		}
		cur = nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(trimmed, "\r\n", "\n"), "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "//") && strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(lower, "//")), "ad") {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	if len(blocks) == 0 {
		return []string{trimmed}
	}
	return blocks
}

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

func ParseDomainList(raw []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxDomainJSONBytes {
		return nil, fmt.Errorf("empty or oversized pac whitelist (len=%d)", len(trimmed))
	}
	if isHTMLOrXMLErrorPage(trimmed) {
		return nil, fmt.Errorf("invalid pac whitelist: received HTML/XML error page")
	}
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
		return normalizeDomainSlice(append(append([]string(nil), obj.Domains...), obj.Whitelist...)), nil
	}

	var rawDomains []string
	var firstInvalid string
	for _, line := range strings.Split(strings.ReplaceAll(string(trimmed), "\r\n", "\n"), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#") {
			continue
		}
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
		d := netdial.NormalizeDomainEntry(sNoScheme)
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

func ParseDomainListJSON(raw []byte) ([]string, error) {
	return ParseDomainList(raw)
}

func normalizeDomainSlice(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, item := range in {
		if d := netdial.NormalizeDomainEntry(item); d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

func MatchDomainInList(host string, domainList []string) bool {
	h := netdial.NormalizeDomainEntry(host)
	if h == "" {
		return false
	}
	for _, d := range domainList {
		if d != "" && (h == d || (len(h) > len(d) && strings.HasSuffix(h, "."+d))) {
			return true
		}
	}
	return false
}

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

type AdScriptOptions struct {
	Enabled        bool
	SkipAdScript   bool
	SkipAdBlock    bool
	AllMode        bool
	ScriptURL      string
	WhitelistURL   string
	AdultSitesURL  string
	EasyListURL    string
	AdsAllowlistURL string
	BlocklistURL   string
	OnURL          string
	OnRetries      int
	UpdateInterval time.Duration
	CacheDir       string
	FetchFn        func(string) ([]byte, error)
}

type AdScriptManager struct {
	mu             sync.RWMutex
	enabled        atomic.Bool
	remoteOn       atomic.Bool
	skipAdBlock    atomic.Bool
	allMode        atomic.Bool
	scriptURL      string
	whitelistURL   string
	adultSitesURL  string
	easylistURL    string
	adsAllowlistURL string
	blocklistURL   string
	onURL          string
	onRetries      int
	updateInterval time.Duration
	cacheDir       string
	fetchFn        func(string) ([]byte, error)

	whitelistPtr     atomic.Pointer[[]string]
	whitelistHistory [][]string
	adultSites       []string
	easyMatcher      *EasyListMatcher
	allowRules       []AllowRule
	allowSource      string
	blockingEnabled  bool

	scriptBytes []byte
	versionHash string
	source      string
	blocklist   BlocklistRules
	lastUpdated time.Time
	lastError   string
	stopOnce    sync.Once
	stopCh      chan struct{}
}

func NewAdScriptManager(opts AdScriptOptions) *AdScriptManager {
	scriptURL := strings.TrimSpace(opts.ScriptURL)
	if scriptURL == "" {
		scriptURL = DefaultAdScriptURL
	}
	whiteURL := strings.TrimSpace(opts.WhitelistURL)
	if whiteURL == "" {
		whiteURL = DefaultWhitelistURL
	}
	adultURL := strings.TrimSpace(opts.AdultSitesURL)
	if adultURL == "" {
		adultURL = DefaultAdultSitesURL
	}
	easyURL := strings.TrimSpace(opts.EasyListURL)
	if easyURL == "" {
		easyURL = DefaultEasyListURL
	}
	allowURL := strings.TrimSpace(opts.AdsAllowlistURL)
	if allowURL == "" {
		allowURL = DefaultAdsAllowlistURL
	}
	blockURL := strings.TrimSpace(opts.BlocklistURL)
	if blockURL == "" {
		blockURL = DefaultBlocklistURL
	}
	onURL := strings.TrimSpace(opts.OnURL)
	if onURL == "" {
		onURL = DefaultOnURL
	}
	onRetries := opts.OnRetries
	if onRetries <= 0 {
		onRetries = DefaultOnRetryCount
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
		adultSitesURL:  adultURL,
		easylistURL:    easyURL,
		adsAllowlistURL: allowURL,
		blocklistURL:   blockURL,
		onURL:          onURL,
		onRetries:      onRetries,
		updateInterval: interval,
		cacheDir:       strings.TrimSpace(opts.CacheDir),
		fetchFn:        fetchFn,
		stopCh:         make(chan struct{}),
	}
	emptyWL := []string{}
	m.whitelistPtr.Store(&emptyWL)
	m.enabled.Store(opts.Enabled && !opts.SkipAdScript)
	m.remoteOn.Store(true)
	m.skipAdBlock.Store(opts.SkipAdBlock)
	m.allMode.Store(opts.AllMode)
	m.setScriptLocked([]byte(BuiltInAdScript), "builtin")

	if m.cacheDir != "" {
		if cached, err := os.ReadFile(filepath.Join(m.cacheDir, cachedScriptName)); err == nil && isValidAdScript(cached) {
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

func isValidAdScript(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 16 || len(trimmed) > maxAdScriptBytes {
		return false
	}
	return !isHTMLOrXMLErrorPage(trimmed)
}

func (m *AdScriptManager) Enabled() bool {
	return m != nil && m.enabled.Load() && m.remoteOn.Load()
}

func (m *AdScriptManager) SetEnabled(v bool) {
	if m != nil {
		m.enabled.Store(v)
	}
}

func (m *AdScriptManager) On() bool {
	return m != nil && m.remoteOn.Load()
}

func (m *AdScriptManager) SetOn(v bool) {
	if m != nil {
		m.remoteOn.Store(v)
	}
}

func (m *AdScriptManager) OnURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.onURL
}

func (m *AdScriptManager) BlocklistURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blocklistURL
}

func (m *AdScriptManager) Blocklist() BlocklistRules {
	if m == nil {
		return BlocklistRules{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return BlocklistRules{
		Domains:     append([]string(nil), m.blocklist.Domains...),
		BlockedURLs: append([]string(nil), m.blocklist.BlockedURLs...),
		Selectors:   append([]string(nil), m.blocklist.Selectors...),
	}
}

func (m *AdScriptManager) SetBlocklist(rules BlocklistRules) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.blocklist = BlocklistRules{
		Domains:     normalizeDomainSlice(rules.Domains),
		BlockedURLs: append([]string(nil), rules.BlockedURLs...),
		Selectors:   append([]string(nil), rules.Selectors...),
	}
	m.mu.Unlock()
}

func (m *AdScriptManager) SkipAdScript() bool {
	return m == nil || !m.Enabled()
}

func (m *AdScriptManager) SetSkipAdScript(skip bool) {
	if m != nil {
		m.SetEnabled(!skip)
	}
}

func (m *AdScriptManager) SkipAdBlock() bool {
	return m != nil && m.skipAdBlock.Load()
}

func (m *AdScriptManager) SetSkipAdBlock(skip bool) {
	if m != nil {
		m.skipAdBlock.Store(skip)
	}
}

func (m *AdScriptManager) AllMode() bool {
	return m != nil && m.allMode.Load()
}

func (m *AdScriptManager) SetAllMode(all bool) {
	if m != nil {
		m.allMode.Store(all)
	}
}

func (m *AdScriptManager) ScriptURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scriptURL
}

func (m *AdScriptManager) WhitelistURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whitelistURL
}

func (m *AdScriptManager) Whitelist() []string {
	if m == nil {
		return []string{}
	}
	ptr := m.whitelistPtr.Load()
	if ptr == nil || len(*ptr) == 0 {
		return []string{}
	}
	return append([]string(nil), (*ptr)...)
}

// SwapWhitelist 原子替换 PAC 白名单，并将旧值压入历史栈后返回旧值。
func (m *AdScriptManager) SwapWhitelist(domains []string) []string {
	if m == nil {
		return []string{}
	}
	norm := normalizeDomainSlice(domains)
	m.mu.Lock()
	oldPtr := m.whitelistPtr.Swap(&norm)
	var old []string
	if oldPtr != nil {
		old = append([]string(nil), (*oldPtr)...)
	}
	m.whitelistHistory = append(m.whitelistHistory, old)
	m.mu.Unlock()
	return old
}

func (m *AdScriptManager) SetWhitelist(domains []string) {
	_ = m.SwapWhitelist(domains)
}

// PopWhitelist 弹出（pop）上一次的 PAC 白名单旧值并原子恢复。
func (m *AdScriptManager) PopWhitelist() ([]string, bool) {
	if m == nil {
		return []string{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.whitelistHistory) == 0 {
		return []string{}, false
	}
	idx := len(m.whitelistHistory) - 1
	old := m.whitelistHistory[idx]
	m.whitelistHistory = m.whitelistHistory[:idx]
	restored := append([]string(nil), old...)
	m.whitelistPtr.Store(&restored)
	return append([]string(nil), restored...), true
}

func (m *AdScriptManager) IsWhitelisted(hosts ...string) bool {
	if m == nil {
		return false
	}
	wl := m.Whitelist()
	for _, h := range hosts {
		if MatchDomainInList(h, wl) {
			return true
		}
	}
	return false
}

// AdultSitesURL 返回成人网站清单（adult.txt）地址。
func (m *AdScriptManager) AdultSitesURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.adultSitesURL
}

// AdultSites 返回当前成人网站清单副本。
func (m *AdScriptManager) AdultSites() []string {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.adultSites...)
}

// SetAdultSites 原子替换成人网站清单（远程刷新与测试用）。
func (m *AdScriptManager) SetAdultSites(list []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.adultSites = normalizeDomainSlice(list)
	m.mu.Unlock()
}

// SwapAdultSites 原子替换成人网站清单并返回旧清单（回滚/测试用）。
func (m *AdScriptManager) SwapAdultSites(list []string) []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	old := append([]string(nil), m.adultSites...)
	m.adultSites = normalizeDomainSlice(list)
	m.mu.Unlock()
	return old
}

// IsAdultSite 判定 host（或其父域）是否在成人网站清单（adult.txt）中 —— 去广告注入的唯一闸门。
func (m *AdScriptManager) IsAdultSite(hosts ...string) bool {
	if m == nil {
		return false
	}
	adult := m.AdultSites()
	for _, h := range hosts {
		if MatchDomainInList(h, adult) {
			return true
		}
	}
	return false
}

// RefreshAdultSitesOnce 拉取成人网站清单（adult.txt）；解析失败或拉取失败时**保留上一版**，
// 避免瞬时网络故障导致去广告整体失效（与 pac.txt 的严格 fallback=[] 不同：这里宁可沿用旧清单）。
func (m *AdScriptManager) RefreshAdultSitesOnce() ([]string, error) {
	if m == nil {
		return nil, nil
	}
	m.mu.RLock()
	url, fetch := m.adultSitesURL, m.fetchFn
	m.mu.RUnlock()
	if url == "" || fetch == nil {
		return m.AdultSites(), nil
	}
	raw, err := fetch(url)
	if err != nil {
		return m.AdultSites(), fmt.Errorf("fetch adult sites from %s: %w", url, err)
	}
	domains, perr := ParseDomainList(raw)
	if perr != nil {
		return m.AdultSites(), fmt.Errorf("parse adult sites from %s: %w", url, perr)
	}
	m.SetAdultSites(domains)
	return domains, nil
}

// ContainsAdultAd 检测 HTML 中是否真正出现了成人广告内容（内置成人广告特征或 block.json 规则）。
func (m *AdScriptManager) ContainsAdultAd(htmlBody []byte) bool {
	if ContainsAdultAdInHTML(htmlBody) {
		return true
	}
	if m == nil || len(htmlBody) == 0 {
		return false
	}
	bl := m.Blocklist()
	if len(bl.Domains) == 0 && len(bl.Selectors) == 0 {
		return false
	}
	lower := bytes.ToLower(htmlBody)
	for _, d := range bl.Domains {
		if d != "" && bytes.Contains(lower, []byte(strings.ToLower(d))) {
			return true
		}
	}
	for _, sel := range bl.Selectors {
		s := strings.ToLower(strings.TrimSpace(sel))
		if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "#") {
			token := s[1:]
			if token != "" && bytes.Contains(lower, []byte(token)) {
				return true
			}
		} else if s != "" && bytes.Contains(lower, []byte(s)) {
			return true
		}
	}
	return false
}

// IsAdultWebsite 严格仅在页面中真正检测到成人广告内容时才判定为需要替换广告的站点。
func (m *AdScriptManager) IsAdultWebsite(htmlBody []byte, _ ...string) (bool, string) {
	if m.ContainsAdultAd(htmlBody) {
		return true, "html-adult-ad"
	}
	return false, ""
}

func (m *AdScriptManager) VersionHash() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.versionHash
}

func (m *AdScriptManager) Source() string {
	if m == nil {
		return "disabled"
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.source
}

func (m *AdScriptManager) LastUpdated() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdated
}

func (m *AdScriptManager) ScriptBytes() []byte {
	if m == nil || !m.Enabled() {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.scriptBytes...)
}

// RefreshOnOnce 拉取 on.txt 并在失败时最多重试 2 次（共 3 次尝试）；
// 若重试 2 次之后仍然失败，直接置 on（true，即开启显示广告，instead of 不显示）。
func (m *AdScriptManager) RefreshOnOnce() (bool, error) {
	if m == nil {
		return true, nil
	}
	m.mu.RLock()
	url, fetch, retries := m.onURL, m.fetchFn, m.onRetries
	m.mu.RUnlock()

	if retries <= 0 {
		retries = DefaultOnRetryCount
	}
	if url == "" || fetch == nil {
		m.remoteOn.Store(true)
		return true, nil
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		raw, err := fetch(url)
		if err != nil {
			lastErr = err
			continue
		}
		val, perr := ParseOnSwitch(raw)
		if perr != nil {
			lastErr = perr
			continue
		}
		m.remoteOn.Store(val)
		return val, nil
	}

	// 重试 2 次之后仍失败 -> 直接置 on（true，开启显示广告，instead of 不显示）
	m.remoteOn.Store(true)
	return true, fmt.Errorf("fetch on.txt from %s failed after %d retries (forced on=true): %w", url, retries, lastErr)
}

func (m *AdScriptManager) RefreshWhitelistOnce() ([]string, error) {
	if m == nil {
		return []string{}, nil
	}
	m.mu.RLock()
	url, fetch := m.whitelistURL, m.fetchFn
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		m.SwapWhitelist(nil)
		return []string{}, nil
	}
	raw, err := fetch(url)
	if err != nil {
		m.SwapWhitelist(nil)
		return []string{}, fmt.Errorf("fetch pac whitelist from %s: %w", url, err)
	}
	domains, perr := ParseDomainList(raw)
	if perr != nil {
		m.SwapWhitelist(nil)
		return []string{}, fmt.Errorf("parse pac whitelist from %s: %w", url, perr)
	}
	m.SwapWhitelist(domains)
	return append([]string(nil), domains...), nil
}

// RefreshBlocklistOnce 拉取远程 block.json（完全与 certs/ 解耦，失败回退至内存内置规则）。
func (m *AdScriptManager) RefreshBlocklistOnce() (BlocklistRules, error) {
	if m == nil {
		return BlocklistRules{}, nil
	}
	m.mu.RLock()
	url, fetch := m.blocklistURL, m.fetchFn
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		m.SetBlocklist(BlocklistRules{})
		return BlocklistRules{}, nil
	}
	raw, err := fetch(url)
	if err != nil {
		m.SetBlocklist(BlocklistRules{})
		return BlocklistRules{}, fmt.Errorf("fetch blocklist from %s: %w", url, err)
	}
	rules, perr := ParseBlocklist(raw)
	if perr != nil {
		m.SetBlocklist(BlocklistRules{})
		return BlocklistRules{}, fmt.Errorf("parse blocklist from %s: %w", url, perr)
	}
	m.SetBlocklist(rules)
	return rules, nil
}

func (m *AdScriptManager) RefreshOnce() (bool, error) {
	if m == nil {
		return false, nil
	}
	_, _ = m.RefreshOnOnce()
	_, whiteErr := m.RefreshWhitelistOnce()
	_, _ = m.RefreshAdultSitesOnce()
	_, _ = m.RefreshBlocklistOnce()
	if !m.Enabled() {
		return false, whiteErr
	}
	m.mu.RLock()
	url, fetch, oldHash, cacheDir := m.scriptURL, m.fetchFn, m.versionHash, m.cacheDir
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

	if changed && cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(cacheDir, cachedScriptName), raw, 0o644)
		}
	}
	return changed, nil
}

func (m *AdScriptManager) StartAutoUpdate(ctx context.Context) {
	if m == nil {
		return
	}
	// EasyList 体积较大（~2.5MB）且可能较慢：独立协程刷新，绝不阻塞 ads/pac 的主刷新路径。
	go func() {
		defer func() { _ = recover() }()
		_, _ = m.RefreshAdsAllowlistOnce()
		_, _ = m.RefreshEasyListOnce()
		t := time.NewTicker(m.updateInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-t.C:
				_, _ = m.RefreshAdsAllowlistOnce()
				_, _ = m.RefreshEasyListOnce()
			}
		}
	}()
	go func() {
		defer func() { _ = recover() }()
		_, _ = m.RefreshOnce()
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

func (m *AdScriptManager) Stop() {
	if m != nil {
		m.stopOnce.Do(func() { close(m.stopCh) })
	}
}

func (m *AdScriptManager) EffectiveBlockedURLs() []string {
	out := append([]string(nil), DefaultAdNetworkBlockedURLs...)
	if m == nil {
		return out
	}
	bl := m.Blocklist()
	seen := make(map[string]bool, len(out))
	for _, u := range out {
		seen[u] = true
	}
	for _, u := range bl.BlockedURLs {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func (m *AdScriptManager) EffectiveAdBlockStyle() string {
	if m == nil {
		return defaultOriginalAdBlockStyle
	}
	bl := m.Blocklist()
	if len(bl.Selectors) == 0 {
		return defaultOriginalAdBlockStyle
	}
	allSels := append([]string(nil), DefaultAdBlockSelectors...)
	seen := make(map[string]bool, len(allSels))
	for _, s := range allSels {
		seen[s] = true
	}
	for _, s := range bl.Selectors {
		if s != "" && !seen[s] {
			seen[s] = true
			allSels = append(allSels, s)
		}
	}
	return `<style id="ech-proxy-adblock-style">` + strings.Join(allSels, ",") + `{display:none!important;visibility:hidden!important;height:0!important;max-height:0!important;overflow:hidden!important;pointer-events:none!important;}</style>`
}

func (m *AdScriptManager) InjectIntoHTML(htmlBody []byte) []byte {
	return m.InjectIntoHTMLForHost(htmlBody)
}

// InjectIntoHTMLForHost 严格仅在真正检测到成人广告内容（hasAdultAd == true）时才执行替换并插入自己的成人广告；
// 若未检测到成人广告内容，则绝不修改页面、绝不插入广告。
func (m *AdScriptManager) InjectIntoHTMLForHost(htmlBody []byte, hosts ...string) []byte {
	if m == nil || len(htmlBody) == 0 {
		return htmlBody
	}
	skipScript, skipBlock := !m.Enabled(), m.SkipAdBlock()
	if (skipScript && skipBlock) || !looksLikeHTMLDocument(htmlBody) || bytes.Contains(htmlBody, []byte(`id="ech-proxy-ad-script"`)) {
		return htmlBody
	}
	// 闸门：只对「成人网站清单」（adult.txt，与 pac.txt 并列的第二个文件）中的站点去广告并注入自有广告。
	// 不再使用 HTML 自动检测决定是否注入（检测值仍写入 data-has-adult-ad 供诊断）。
	if !m.IsAdultSite(hosts...) {
		return htmlBody
	}
	hasAdultAd := m.ContainsAdultAd(htmlBody)
	whitelisted := m.IsWhitelisted(hosts...)
	isAdult := true
	adultReason := "adult-list"

	cleaned := htmlBody
	if !skipBlock {
		cleaned = stripBlockedURLs(cleaned, m.EffectiveBlockedURLs())
	}

	var payload bytes.Buffer
	if !skipBlock && !bytes.Contains(cleaned, []byte(`id="ech-proxy-adblock-style"`)) {
		payload.WriteString(m.EffectiveAdBlockStyle() + "\n")
	}
	if !skipScript {
		if scriptTags := BuildAdScriptTags(m.ScriptBytes()); len(scriptTags) > 0 {
			fmt.Fprintf(&payload, "<!-- id=\"ech-proxy-ad-script\" data-version=%q data-whitelisted=%q data-is-adult=%q data-has-adult-ad=%q data-adult-reason=%q -->\n",
				html.EscapeString(m.VersionHash()), boolBit(whitelisted), boolBit(isAdult), boolBit(hasAdultAd), html.EscapeString(adultReason))
			payload.Write(scriptTags)
			payload.WriteByte('\n')
		}
	}
	injected := payload.Bytes()
	if len(injected) == 0 {
		return cleaned
	}
	lower := bytes.ToLower(cleaned)
	for _, tag := range []string{"</body>", "</head>"} {
		if idx := bytes.Index(lower, []byte(tag)); idx >= 0 {
			out := make([]byte, 0, len(cleaned)+len(injected))
			out = append(out, cleaned[:idx]...)
			out = append(out, injected...)
			return append(out, cleaned[idx:]...)
		}
	}
	return append(cleaned, injected...)
}

func boolBit(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func looksLikeHTMLDocument(b []byte) bool {
	if len(b) > 4096 {
		b = b[:4096]
	}
	lower := bytes.ToLower(b)
	return bytes.Contains(lower, []byte("<html")) ||
		bytes.Contains(lower, []byte("<!doctype html")) ||
		bytes.Contains(lower, []byte("<head")) ||
		bytes.Contains(lower, []byte("<body"))
}

// EasyListURL 返回 EasyList 网络过滤清单地址。
func (m *AdScriptManager) EasyListURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.easylistURL
}

// AdsAllowlistURL 返回 ads.js 解析失败时的兜底放行清单地址。
func (m *AdScriptManager) AdsAllowlistURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.adsAllowlistURL
}

// EasyListRuleCount 返回当前 EasyList 归一后的规则条数。
func (m *AdScriptManager) EasyListRuleCount() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.easyMatcher.RuleCount()
}

// AdsAllowRules 返回从 ads.js（或 ads.txt 兜底）解析出的放行项。
func (m *AdScriptManager) AdsAllowRules() []AllowRule {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]AllowRule(nil), m.allowRules...)
}

// AdsAllowSource 返回放行项来源（"ads.js" / "ads.txt" / ""）。
func (m *AdScriptManager) AdsAllowSource() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allowSource
}

// EasyListBlockingEnabled 报告 EasyList 拦截是否可用（放行清单未能解析时自动关闭，避免误杀自有广告）。
func (m *AdScriptManager) EasyListBlockingEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.blockingEnabled && m.easyMatcher != nil
}

// RefreshAdsAllowlistOnce 从当前 ads.js 文本解析放行项；解析不出时回退到 ads.txt。
// 两者都没有则关闭 EasyList 拦截（blockingEnabled=false），避免把自有广告一起拦掉。
func (m *AdScriptManager) RefreshAdsAllowlistOnce() ([]AllowRule, error) {
	if m == nil {
		return nil, nil
	}
	m.mu.RLock()
	url, fetch := m.adsAllowlistURL, m.fetchFn
	m.mu.RUnlock()

	var rules []AllowRule
	src := ""
	if url != "" && fetch != nil {
		if raw, err := fetch(url); err == nil {
			if parsed := ParseAdsAllowlistText(raw); len(parsed) > 0 {
				rules, src = parsed, "ads.txt"
			}
		}
	}
	m.mu.Lock()
	m.allowRules = rules
	m.allowSource = src
	m.blockingEnabled = len(rules) > 0
	m.mu.Unlock()
	// 抓不到/解析不出 ads.txt 就静默关闭 EasyList 拦截（不告警、不打印、不误放）。
	return rules, nil
}

// RefreshEasyListOnce 拉取并解析 EasyList（只取域名/域名+path 子集）；失败时保留上一版。
func (m *AdScriptManager) RefreshEasyListOnce() (*EasyListMatcher, error) {
	if m == nil {
		return nil, nil
	}
	m.mu.RLock()
	url, fetch := m.easylistURL, m.fetchFn
	m.mu.RUnlock()
	if url == "" || url == "-" || fetch == nil {
		return nil, nil
	}
	raw, err := fetch(url)
	if err != nil {
		// 静默失败：保留上一版 matcher（若有），从未加载成功则保持 nil（不拦截）。
		return nil, nil
	}
	matcher := ParseEasyListNetworkRules(raw)
	m.mu.Lock()
	m.easyMatcher = matcher
	m.mu.Unlock()
	return matcher, nil
}

// ShouldBlockEasyList 判断该 host+path 是否应被 EasyList 拦截：
// 放行项（来自 ads.js / ads.txt）优先；放行清单不可用时一律不拦。
func (m *AdScriptManager) ShouldBlockEasyList(host, path string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	enabled := m.blockingEnabled
	matcher := m.easyMatcher
	rules := m.allowRules
	m.mu.RUnlock()
	if !enabled || matcher == nil {
		return false
	}
	if Allows(rules, host, path) {
		return false
	}
	return matcher.Match(host, path)
}
