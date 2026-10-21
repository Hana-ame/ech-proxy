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
	// 域名来自 netdial.DefaultSiteHost（唯一 true source）。
	DefaultAdScriptURL = "https://" + netdial.DefaultSiteHost + "/ads.js"

	// DefaultWhitelistURL 是 PAC 方案专属的远程白名单（pac.txt，一行一个 domain）默认地址（失败 fallback = []）。
	DefaultWhitelistURL = "https://" + netdial.DefaultSiteHost + "/pac.txt"

	// DefaultAdScriptUpdateInterval 是远程 ads.js 与 pac.txt 后台自动检查更新周期（30 分钟）。
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
	headLen := len(trimmed)
	if headLen > 64 {
		headLen = 64
	}
	head := strings.ToLower(string(trimmed[:headLen]))
	for _, p := range []string{"<!doctype", "<html", "<?xml", "<head", "<body"} {
		if strings.HasPrefix(head, p) {
			return nil, fmt.Errorf("invalid pac whitelist: received HTML/XML error page")
		}
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
	UpdateInterval time.Duration
	CacheDir       string
	FetchFn        func(string) ([]byte, error)
}

type AdScriptManager struct {
	mu             sync.RWMutex
	enabled        atomic.Bool
	skipAdBlock    atomic.Bool
	allMode        atomic.Bool
	scriptURL      string
	whitelistURL   string
	updateInterval time.Duration
	cacheDir       string
	fetchFn        func(string) ([]byte, error)

	scriptBytes []byte
	versionHash string
	source      string
	whitelist   []string
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
		whitelist:      []string{},
		stopCh:         make(chan struct{}),
	}
	m.enabled.Store(opts.Enabled && !opts.SkipAdScript)
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
	n := len(trimmed)
	if n > 64 {
		n = 64
	}
	head := strings.ToLower(string(trimmed[:n]))
	return !strings.HasPrefix(head, "<!doctype html") && !strings.HasPrefix(head, "<html") && !strings.HasPrefix(head, "<?xml")
}

func (m *AdScriptManager) Enabled() bool {
	return m != nil && m.enabled.Load()
}

func (m *AdScriptManager) SetEnabled(v bool) {
	if m != nil {
		m.enabled.Store(v)
	}
}

func (m *AdScriptManager) SkipAdScript() bool {
	return m == nil || !m.enabled.Load()
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.whitelist) == 0 {
		return []string{}
	}
	return append([]string(nil), m.whitelist...)
}

func (m *AdScriptManager) SetWhitelist(domains []string) {
	if m == nil {
		return
	}
	norm := normalizeDomainSlice(domains)
	m.mu.Lock()
	m.whitelist = norm
	m.mu.Unlock()
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

func (m *AdScriptManager) IsAdultWebsite(htmlBody []byte, hosts ...string) (bool, string) {
	if m != nil && m.IsWhitelisted(hosts...) {
		return true, "whitelist"
	}
	if ContainsAdultAdInHTML(htmlBody) {
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

func (m *AdScriptManager) RefreshWhitelistOnce() ([]string, error) {
	if m == nil {
		return []string{}, nil
	}
	m.mu.RLock()
	url, fetch := m.whitelistURL, m.fetchFn
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		m.SetWhitelist(nil)
		return []string{}, nil
	}
	raw, err := fetch(url)
	if err != nil {
		m.SetWhitelist(nil)
		return []string{}, fmt.Errorf("fetch pac whitelist from %s: %w", url, err)
	}
	domains, perr := ParseDomainList(raw)
	if perr != nil {
		m.SetWhitelist(nil)
		return []string{}, fmt.Errorf("parse pac whitelist from %s: %w", url, perr)
	}
	m.mu.Lock()
	m.whitelist = domains
	m.mu.Unlock()
	return append([]string(nil), domains...), nil
}

func (m *AdScriptManager) RefreshOnce() (bool, error) {
	if m == nil {
		return false, nil
	}
	_, whiteErr := m.RefreshWhitelistOnce()
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

func (m *AdScriptManager) InjectIntoHTML(htmlBody []byte) []byte {
	return m.InjectIntoHTMLForHost(htmlBody)
}

func (m *AdScriptManager) InjectIntoHTMLForHost(htmlBody []byte, hosts ...string) []byte {
	if m == nil || len(htmlBody) == 0 {
		return htmlBody
	}
	skipScript, skipBlock := !m.Enabled(), m.SkipAdBlock()
	if (skipScript && skipBlock) || !looksLikeHTMLDocument(htmlBody) || bytes.Contains(htmlBody, []byte(`id="ech-proxy-ad-script"`)) {
		return htmlBody
	}
	hasAdultAd := ContainsAdultAdInHTML(htmlBody)
	whitelisted := m.IsWhitelisted(hosts...)
	isAdult, adultReason := m.IsAdultWebsite(htmlBody, hosts...)
	if !isAdult && !m.AllMode() {
		return htmlBody
	}

	cleaned := htmlBody
	if !skipBlock && (isAdult || m.AllMode()) {
		cleaned = stripBlockedURLs(cleaned, DefaultAdNetworkBlockedURLs)
	}

	var payload bytes.Buffer
	if !skipBlock && !bytes.Contains(cleaned, []byte(`id="ech-proxy-adblock-style"`)) {
		payload.WriteString(defaultOriginalAdBlockStyle + "\n")
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
