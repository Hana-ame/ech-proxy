// Package config 负责解析、归一化与匹配 upstream.json 配置文件。
// 除了 l.moonchan.xyz 及其代理子域名按映射规则转发外，任何通过修改 hosts=127.0.0.1
// 接入的非 l.moonchan.xyz 域名（无论是否显式写入 upstream.json）均可自动透传转发。
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/orderedmap"
)

// DefaultConfigURL 是默认远程 upstream.json 配置地址。
const DefaultConfigURL = "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/upstream.json?proxy_host=raw.githubusercontent.com"

// PortalDomain 是门户与 8443 代理子域名的根域名。
const PortalDomain = "l.moonchan.xyz"

// IsPortalDomain 判断域名是否为 l.moonchan.xyz 或 *.l.moonchan.xyz。
// 除该域名体系外，其余所有域名均使用本地自签 CA 证书并通过自动 SNI/ECH 转发至真实服务器。
func IsPortalDomain(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	return h == PortalDomain || strings.HasSuffix(h, "."+PortalDomain)
}

// HeaderRule 定义单个请求头或响应头的操作规则。
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
	h.Delete = raw.Delete
	h.Replace = raw.Replace
	if raw.Value != "" {
		h.Value = raw.Value
	} else {
		h.Value = raw.Set
	}
	return nil
}

// BodyReplaceRule 定义响应正文替换规则。
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

// WildcardRule 定义泛子域名映射规则。
type WildcardRule struct {
	Prefix          string                `json:"prefix,omitempty"`
	EntrySuffix     string                `json:"entry_suffix,omitempty"`
	UpstreamSuffix  string                `json:"upstream_suffix,omitempty"`
	Referer         string                `json:"referer,omitempty"`
	Origin          string                `json:"origin,omitempty"`
	XSite           string                `json:"x_site,omitempty"`
	Headers         map[string]HeaderRule `json:"headers,omitempty"`
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"`
	Cookie          string                `json:"cookie,omitempty"`
	CookieFile      string                `json:"cookie_file,omitempty"`
	CookieDomain    string                `json:"cookie_domain,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	IPMode          string                `json:"ip_mode,omitempty"`
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	BodyReplace     []BodyReplaceRule     `json:"body_replace,omitempty"`
}

// UpstreamConfig 定义单条上游代理规则。
type UpstreamConfig struct {
	Host            string                `json:"host"`
	Describe        string                `json:"describe,omitempty"`
	Display         bool                  `json:"display,omitempty"`
	Mode            string                `json:"mode,omitempty"`    // ""/"auto", "ech", "sni", "direct"
	IPMode          string                `json:"ip_mode,omitempty"` // ""/"auto", "v4", "v6"
	Referer         string                `json:"referer,omitempty"`
	Origin          string                `json:"origin,omitempty"`
	XSite           string                `json:"x_site,omitempty"`
	Headers         map[string]HeaderRule `json:"headers,omitempty"`
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"`
	Cookie          string                `json:"cookie,omitempty"`
	CookieFile      string                `json:"cookie_file,omitempty"`
	CookieDomain    string                `json:"cookie_domain,omitempty"`
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	BodyReplace     []BodyReplaceRule     `json:"body_replace,omitempty"`
	Wildcard        *WildcardRule         `json:"wildcard,omitempty"`
}

// UpstreamMap 是按入口域名索引的上游配置表。
type UpstreamMap map[string]UpstreamConfig

// Config 表示完整的 upstream.json 配置结构。
type Config struct {
	CertPath      string      `json:"cert_path"`
	KeyPath       string      `json:"key_path"`
	Upstreams     UpstreamMap `json:"upstreams"`
	BlockedHosts  []string    `json:"blocked_hosts"`
	UpstreamOrder []string    `json:"-"`
}

// Load 从本地路径或远程 URL 加载并解析 upstream.json。
func Load(source string) (*Config, error) {
	if source == "" {
		source = DefaultConfigURL
	}
	buf, err := netdial.FetchBytes(source)
	if err != nil {
		return nil, fmt.Errorf("fetch upstream config: %w", err)
	}
	return Parse(buf)
}

// Parse 解析 upstream.json 字节流并完成规则归一化与正则预编译。
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

func normalize(cfg *Config) {
	for host, uc := range cfg.Upstreams {
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
			if w.IPMode == "" {
				w.IPMode = uc.IPMode
			}
			if w.CookieDomain == "" {
				w.CookieDomain = uc.CookieDomain
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
		if len(r.Replace) >= 2 && r.Replace[0] != "" {
			r.CompiledReplace, _ = regexp.Compile(r.Replace[0])
			rules[k] = r
		}
	}
}

// CompileBodyReplace 预编译正文替换规则中的正则表达式。
func CompileBodyReplace(rules []BodyReplaceRule) {
	compileBodyReplace(rules)
}

func compileBodyReplace(rules []BodyReplaceRule) {
	for i := range rules {
		if rules[i].Old != "" {
			rules[i].Compiled, _ = regexp.Compile(rules[i].Old)
		}
	}
}

// Resolve 根据请求域名查找匹配的上游配置：
//  1. 优先精确匹配 upstream.json 中的条目；
//  2. 其次匹配 upstream.json 中的 Wildcard 泛域名规则；
//  3. 若请求域名不属于 l.moonchan.xyz 体系（即用户通过修改 hosts=127.0.0.1 指向本机的任意真实域名），
//     即使未显式写入 upstream.json，也自动生成原域名透传配置（Mode: "auto"），交由 SNI/ECH 自动探测转发。
func Resolve(upstreams UpstreamMap, host string) (UpstreamConfig, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return UpstreamConfig{}, false
	}
	if uc, ok := upstreams[host]; ok {
		return uc, true
	}
	if uc, ok := MatchWildcard(upstreams, host); ok {
		return uc, true
	}
	// 非 l.moonchan.xyz 域名（且为合法域名而非纯 IP）：自动启用原域名透明反代，由底层自动选择 SNI/ECH
	if !IsPortalDomain(host) && net.ParseIP(host) == nil && strings.Contains(host, ".") {
		return UpstreamConfig{
			Host: host,
			Mode: "auto",
		}, true
	}
	return UpstreamConfig{}, false
}

// MatchWildcard 根据泛域名规则匹配请求域名，并合成对应的目标 UpstreamConfig。
func MatchWildcard(upstreams UpstreamMap, host string) (UpstreamConfig, bool) {
	for _, uc := range upstreams {
		w := uc.Wildcard
		if w == nil {
			continue
		}
		sub := strings.TrimPrefix(host, w.Prefix)
		if sub == "" || (w.Prefix != "" && sub == host) {
			continue
		}
		if !strings.HasSuffix(sub, w.EntrySuffix) {
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
		if w.Mode != "" {
			out.Mode = w.Mode
		}
		if w.IPMode != "" {
			out.IPMode = w.IPMode
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

// InheritWildcard 为没有显式配置 Wildcard 的子条目查找可继承的同前缀泛域名规则。
func InheritWildcard(upstreams UpstreamMap, entry string) *WildcardRule {
	for _, uc := range upstreams {
		if w := uc.Wildcard; w != nil {
			if strings.HasPrefix(entry, w.Prefix) && strings.HasSuffix(entry, w.EntrySuffix) {
				return w
			}
		}
	}
	return nil
}
