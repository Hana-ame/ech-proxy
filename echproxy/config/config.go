// Package config 负责解析与匹配 8443 方案专属的 upstream.json 配置文件（certs/l.moonchan.xyz/upstream.json），
// 同时为 PAC 主线方案与 443 方案提供无任何硬编码规则的原域名自动透传解析能力。
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/orderedmap"
)

const (
	DefaultConfigURL = "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/upstream.json?proxy_host=raw.githubusercontent.com"
	PortalDomain     = "l.moonchan.xyz"
)

func IsPortalDomain(host string) bool {
	h := netdial.CleanHost(host)
	return h == PortalDomain || strings.HasSuffix(h, "."+PortalDomain)
}

func IsOriginalDomainMode(host string) bool {
	h := netdial.CleanHost(host)
	return h != "" && !IsPortalDomain(h)
}

type HeaderRule struct {
	Value           string         `json:"value,omitempty"`
	Delete          bool           `json:"delete,omitempty"`
	Replace         []string       `json:"replace,omitempty"`
	CompiledReplace *regexp.Regexp `json:"-"`
}

func (h *HeaderRule) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		h.Value = str
		return nil
	}
	var raw struct {
		Value   string   `json:"value"`
		Set     string   `json:"set"`
		Delete  bool     `json:"delete"`
		Replace []string `json:"replace"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	h.Delete, h.Replace = raw.Delete, raw.Replace
	if raw.Value != "" {
		h.Value = raw.Value
	} else {
		h.Value = raw.Set
	}
	return nil
}

type BodyReplaceRule struct {
	Old      string         `json:"old,omitempty"`
	New      string         `json:"new,omitempty"`
	Regex    bool           `json:"regex,omitempty"`
	Compiled *regexp.Regexp `json:"-"`
}

func (r *BodyReplaceRule) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) >= 2 {
		r.Old, r.New = arr[0], arr[1]
		return nil
	}
	var raw struct {
		Replace []string `json:"replace"`
		Old     string   `json:"old"`
		New     string   `json:"new"`
		From    string   `json:"from"`
		To      string   `json:"to"`
		Regex   bool     `json:"regex"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Regex = raw.Regex
	switch {
	case len(raw.Replace) >= 2:
		r.Old, r.New = raw.Replace[0], raw.Replace[1]
	case raw.Old != "":
		r.Old, r.New = raw.Old, raw.New
	default:
		r.Old, r.New = raw.From, raw.To
	}
	return nil
}

type WildcardRule struct {
	Prefix          string                `json:"prefix,omitempty"`
	EntrySuffix     string                `json:"entry_suffix,omitempty"`
	UpstreamSuffix  string                `json:"upstream_suffix,omitempty"`
	Entry           string                `json:"entry,omitempty"`
	Upstream        string                `json:"upstream,omitempty"`
	Referer         string                `json:"referer,omitempty"`
	Origin          string                `json:"origin,omitempty"`
	XSite           string                `json:"x_site,omitempty"`
	Headers         map[string]HeaderRule `json:"headers,omitempty"`
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"`
	Cookie          string                `json:"cookie,omitempty"`
	CookieFile      string                `json:"cookie_file,omitempty"`
	CookieDomain    string                `json:"cookie_domain,omitempty"`
	CookiePriority  string                `json:"cookie_priority,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	IPMode          string                `json:"ip_mode,omitempty"`
	SNIServerName   string                `json:"sni_server_name,omitempty"`
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	BodyReplace     []BodyReplaceRule     `json:"body_replace,omitempty"`
}

type UpstreamConfig struct {
	Host            string                `json:"host"`
	Describe        string                `json:"describe,omitempty"`
	Display         bool                  `json:"display,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	IPMode          string                `json:"ip_mode,omitempty"`
	SNIServerName   string                `json:"sni_server_name,omitempty"`
	Referer         string                `json:"referer,omitempty"`
	Origin          string                `json:"origin,omitempty"`
	XSite           string                `json:"x_site,omitempty"`
	Headers         map[string]HeaderRule `json:"headers,omitempty"`
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"`
	Cookie          string                `json:"cookie,omitempty"`
	CookieFile      string                `json:"cookie_file,omitempty"`
	CookieDomain    string                `json:"cookie_domain,omitempty"`
	CookiePriority  string                `json:"cookie_priority,omitempty"`
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	BodyReplace     []BodyReplaceRule     `json:"body_replace,omitempty"`
	Wildcard        *WildcardRule         `json:"wildcard,omitempty"`
}

type UpstreamMap map[string]UpstreamConfig

type Config struct {
	mu            sync.RWMutex `json:"-"`
	CertPath      string       `json:"cert_path"`
	KeyPath       string       `json:"key_path"`
	IPMode        string       `json:"ip_mode,omitempty"`
	Upstreams     UpstreamMap  `json:"upstreams"`
	BlockedHosts  []string     `json:"blocked_hosts"`
	UpstreamOrder []string     `json:"-"`
}

func (c *Config) ReplaceFrom(other *Config) {
	if c == nil || other == nil {
		return
	}
	c.mu.Lock()
	c.CertPath = other.CertPath
	c.KeyPath = other.KeyPath
	if c.IPMode == "" {
		c.IPMode = other.IPMode
	}
	c.Upstreams = other.Upstreams
	c.BlockedHosts = other.BlockedHosts
	c.UpstreamOrder = other.UpstreamOrder
	c.mu.Unlock()
}

func (c *Config) Snapshot() (UpstreamMap, []string) {
	if c == nil {
		return nil, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Upstreams, c.BlockedHosts
}

func (c *Config) OrderSnapshot() []string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.UpstreamOrder...)
}

func Load(source string) (*Config, error) {
	defaultSource := source == ""
	if defaultSource {
		source = DefaultConfigURL
	}
	buf, err := netdial.FetchBytes(source)
	if err != nil {
		if defaultSource {
			for _, cand := range []string{
				filepath.Join("certs", "l.moonchan.xyz", "upstream.json"),
				filepath.Join("..", "certs", "l.moonchan.xyz", "upstream.json"),
			} {
				if localBuf, lerr := os.ReadFile(cand); lerr == nil && len(localBuf) > 0 {
					return Parse(localBuf)
				}
			}
		}
		return nil, fmt.Errorf("fetch upstream config: %w", err)
	}
	return Parse(buf)
}

func Parse(buf []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("decode upstream config: %w", err)
	}
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("upstream config has no upstreams")
	}

	om := orderedmap.New()
	if err := json.Unmarshal(buf, om); err == nil {
		if us, ok := om.Get("upstreams"); ok {
			switch m := us.(type) {
			case orderedmap.OrderedMap:
				cfg.UpstreamOrder = m.Keys()
			case *orderedmap.OrderedMap:
				cfg.UpstreamOrder = m.Keys()
			}
		}
	}

	normalize(&cfg)
	return &cfg, nil
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ech", "sni", "direct":
		return strings.ToLower(strings.TrimSpace(mode))
	case "fragment", "bypass", "gfw":
		return "fragment"
	case "auto", "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizeCookiePriority(p string) string {
	if strings.EqualFold(strings.TrimSpace(p), "seed") {
		return "seed"
	}
	return "browser"
}

func normalize(cfg *Config) {
	cfg.IPMode = netdial.EffectiveIPMode(cfg.IPMode)

	for host, uc := range cfg.Upstreams {
		uc.Mode = normalizeMode(uc.Mode)
		uc.IPMode = netdial.NormalizeIPMode(uc.IPMode)
		if uc.IPMode == "" {
			uc.IPMode = cfg.IPMode
		}
		uc.CookiePriority = normalizeCookiePriority(uc.CookiePriority)
		uc.SNIServerName = strings.TrimSpace(uc.SNIServerName)
		uc.Headers = mergeLegacyHeaders(uc.Headers, uc.Referer, uc.Origin, uc.XSite)
		if r, ok := uc.Headers["Referer"]; ok && !r.Delete && len(r.Replace) == 0 {
			uc.Referer = r.Value
		}
		if r, ok := uc.Headers["Origin"]; ok && !r.Delete && len(r.Replace) == 0 {
			uc.Origin = r.Value
		}
		if r, ok := uc.Headers["X-Site"]; ok && !r.Delete && len(r.Replace) == 0 {
			uc.XSite = r.Value
		}
		compileHeaderRules(uc.Headers)
		compileHeaderRules(uc.ResponseHeaders)
		compileBodyReplace(uc.BodyReplace)

		if w := uc.Wildcard; w != nil {
			if w.EntrySuffix == "" && strings.HasPrefix(w.Entry, "*.") {
				w.EntrySuffix = w.Entry[1:]
			}
			if w.UpstreamSuffix == "" && strings.HasPrefix(w.Upstream, "*.") {
				w.UpstreamSuffix = w.Upstream[1:]
			}
			if w.EntrySuffix == "" {
				if idx := strings.Index(host, "."); idx >= 0 {
					w.EntrySuffix = host[idx:]
					if w.Prefix == "" {
						w.Prefix = host[:idx] + "-"
					}
				}
			}
			if w.UpstreamSuffix == "" && uc.Host != "" {
				w.UpstreamSuffix = "." + strings.TrimPrefix(uc.Host, ".")
			}
			if w.Mode = normalizeMode(w.Mode); w.Mode == "" {
				w.Mode = uc.Mode
			}
			if w.IPMode = netdial.NormalizeIPMode(w.IPMode); w.IPMode == "" {
				w.IPMode = uc.IPMode
			}
			if w.CookieDomain == "" {
				w.CookieDomain = uc.CookieDomain
			}
			if w.CookiePriority == "" {
				w.CookiePriority = uc.CookiePriority
			} else {
				w.CookiePriority = normalizeCookiePriority(w.CookiePriority)
			}
			if w.SNIServerName == "" {
				w.SNIServerName = uc.SNIServerName
			}
			w.Headers = mergeLegacyHeaders(w.Headers, w.Referer, w.Origin, w.XSite)
			if r, ok := w.Headers["Referer"]; ok && !r.Delete && len(r.Replace) == 0 {
				w.Referer = r.Value
			}
			compileHeaderRules(w.Headers)
			compileHeaderRules(w.ResponseHeaders)
			compileBodyReplace(w.BodyReplace)
		}
		cfg.Upstreams[host] = uc
	}
}

func mergeLegacyHeaders(headers map[string]HeaderRule, referer, origin, xsite string) map[string]HeaderRule {
	if headers == nil {
		headers = make(map[string]HeaderRule)
	}
	if referer != "" {
		if _, ok := headers["Referer"]; !ok {
			headers["Referer"] = HeaderRule{Value: referer}
		}
	}
	if origin != "" {
		if _, ok := headers["Origin"]; !ok {
			headers["Origin"] = HeaderRule{Value: origin}
		}
	}
	if xsite != "" {
		if _, ok := headers["X-Site"]; !ok {
			headers["X-Site"] = HeaderRule{Value: xsite}
		}
	}
	if _, hasOrigin := headers["Origin"]; !hasOrigin {
		if ref, ok := headers["Referer"]; ok && ref.Value != "" && !ref.Delete {
			if u, err := url.Parse(ref.Value); err == nil && u.Host != "" {
				headers["Origin"] = HeaderRule{Value: u.Scheme + "://" + u.Host}
			}
		}
	}
	return headers
}

func compileHeaderRules(rules map[string]HeaderRule) {
	for k, r := range rules {
		if len(r.Replace) >= 2 && r.Replace[0] != "" && r.CompiledReplace == nil {
			r.CompiledReplace, _ = regexp.Compile(r.Replace[0])
			rules[k] = r
		}
	}
}

func CompileBodyReplace(rules []BodyReplaceRule) {
	compileBodyReplace(rules)
}

func compileBodyReplace(rules []BodyReplaceRule) {
	for i := range rules {
		if rules[i].Old != "" && rules[i].Compiled == nil {
			rules[i].Compiled, _ = regexp.Compile(rules[i].Old)
		}
	}
}

// Resolve 根据请求域名解析目标配置：
//   - 若 upstreams 中存在匹配项（8443 方案的 *.l.moonchan.xyz 门户规则），则按规则返回；
//   - 若为非 l.moonchan.xyz 原域名（PAC 方案与 443 方案复用），直接生成纯粹的原域名透传配置，不内置任何特定域名逻辑。
func Resolve(upstreams UpstreamMap, host string) (UpstreamConfig, bool) {
	host = netdial.CleanHost(host)
	if host == "" {
		return UpstreamConfig{}, false
	}
	if uc, ok := upstreams[host]; ok {
		return uc, true
	}
	if uc, ok := MatchWildcard(upstreams, host); ok {
		return uc, true
	}
	if !IsPortalDomain(host) && net.ParseIP(host) == nil && strings.Contains(host, ".") {
		return UpstreamConfig{
			Host:           host,
			Mode:           "auto",
			IPMode:         netdial.DefaultIPMode,
			CookiePriority: "browser",
		}, true
	}
	return UpstreamConfig{}, false
}

func MatchWildcard(upstreams UpstreamMap, host string) (UpstreamConfig, bool) {
	host = netdial.CleanHost(host)
	for _, uc := range upstreams {
		w := uc.Wildcard
		if w == nil {
			continue
		}
		sub := strings.TrimPrefix(host, w.Prefix)
		if sub == "" || (w.Prefix != "" && sub == host) || !strings.HasSuffix(sub, w.EntrySuffix) {
			continue
		}
		sub = strings.TrimSuffix(sub, w.EntrySuffix)
		if sub == "" || strings.ContainsAny(sub, ":/") {
			continue
		}

		out := uc
		out.Host = sub + w.UpstreamSuffix
		if len(w.Headers) > 0 || w.Referer != "" {
			merged := make(map[string]HeaderRule, len(uc.Headers)+len(w.Headers)+1)
			for k, v := range uc.Headers {
				merged[k] = v
			}
			for k, v := range w.Headers {
				merged[k] = v
			}
			if w.Referer != "" {
				merged["Referer"] = HeaderRule{Value: w.Referer}
				out.Referer = w.Referer
			}
			out.Headers = merged
		}
		if len(w.ResponseHeaders) > 0 {
			merged := make(map[string]HeaderRule, len(uc.ResponseHeaders)+len(w.ResponseHeaders))
			for k, v := range uc.ResponseHeaders {
				merged[k] = v
			}
			for k, v := range w.ResponseHeaders {
				merged[k] = v
			}
			out.ResponseHeaders = merged
		}
		if w.Cookie != "" {
			out.Cookie = w.Cookie
		}
		if w.CookieFile != "" {
			out.CookieFile = w.CookieFile
		}
		if w.CookieDomain != "" {
			out.CookieDomain = w.CookieDomain
		}
		if w.CookiePriority != "" {
			out.CookiePriority = w.CookiePriority
		}
		if w.Mode != "" {
			out.Mode = w.Mode
		}
		if w.IPMode != "" {
			out.IPMode = w.IPMode
		}
		if w.SNIServerName != "" {
			out.SNIServerName = w.SNIServerName
		}
		if w.SWInject {
			out.SWInject = true
		}
		if len(w.BodyReplace) > 0 {
			out.BodyReplace = append(append([]BodyReplaceRule(nil), uc.BodyReplace...), w.BodyReplace...)
		}
		return out, true
	}
	return UpstreamConfig{}, false
}

func InheritWildcard(upstreams UpstreamMap, entry string) *WildcardRule {
	for _, uc := range upstreams {
		if w := uc.Wildcard; w != nil && strings.HasPrefix(entry, w.Prefix) && strings.HasSuffix(entry, w.EntrySuffix) {
			return w
		}
	}
	return nil
}