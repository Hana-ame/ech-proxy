package echproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
	"github.com/Hana-ame/orderedmap"
)

// HeaderRule defines operational rules for an individual header:
// Supports string shorthand (direct set/override): "Origin": "https://www.iwara.tv"
// Supports advanced object controls:
//  - Delete: {"delete": true}
//  - Replace: {"replace": ["before", "after"]}
type HeaderRule struct {
	Value           string         `json:"value,omitempty"`
	Delete          bool           `json:"delete,omitempty"`
	Replace         []string       `json:"replace,omitempty"` // [before, after]
	compiledReplace *regexp.Regexp // pre-compiled regex for Replace[0]; nil if not a valid regex
}

func (h *HeaderRule) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		h.Value = str
		return nil
	}
	type rawRule struct {
		Value   string   `json:"value,omitempty"`
		Set     string   `json:"set,omitempty"`
		Delete  bool     `json:"delete,omitempty"`
		Replace []string `json:"replace,omitempty"`
	}
	var raw rawRule
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	h.Delete = raw.Delete
	h.Replace = raw.Replace
	if raw.Value != "" {
		h.Value = raw.Value
	} else if raw.Set != "" {
		h.Value = raw.Set
	}
	return nil
}

func (h HeaderRule) MarshalJSON() ([]byte, error) {
	if h.Delete {
		return json.Marshal(map[string]bool{"delete": true})
	}
	if len(h.Replace) > 0 {
		return json.Marshal(map[string][]string{"replace": h.Replace})
	}
	return json.Marshal(h.Value)
}

// BodyReplaceRule defines an individual response body replacement rule:
// Supports array shorthand: ["old", "new"]
// Supports advanced object: {"replace": ["old", "new"]}
// Supports explicit key-value: {"from": "old", "to": "new"}
type BodyReplaceRule struct {
	Old      string         `json:"old,omitempty"`
	New      string         `json:"new,omitempty"`
	Regex    bool           `json:"regex,omitempty"`
	compiled *regexp.Regexp // pre-compiled regex for Old; nil if not a valid regex
}

func (r *BodyReplaceRule) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil && len(arr) >= 2 {
		r.Old = arr[0]
		r.New = arr[1]
		return nil
	}
	var objReplace struct {
		Replace []string `json:"replace"`
		Regex   bool     `json:"regex"`
	}
	if err := json.Unmarshal(data, &objReplace); err == nil && len(objReplace.Replace) >= 2 {
		r.Old = objReplace.Replace[0]
		r.New = objReplace.Replace[1]
		r.Regex = objReplace.Regex
		return nil
	}
	var raw struct {
		Old   string `json:"old"`
		New   string `json:"new"`
		From  string `json:"from"`
		To    string `json:"to"`
		Regex bool   `json:"regex"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Old != "" {
		r.Old = raw.Old
		r.New = raw.New
	} else {
		r.Old = raw.From
		r.New = raw.To
	}
	r.Regex = raw.Regex
	return nil
}

// WildcardRule defines wildcard upstream routing rules:
// Incoming host = Prefix + <sub> + EntrySuffix -> forwarded to <sub> + UpstreamSuffix.
// Example: entry="iwara-*.l.moonchan.xyz" upstream="*.iwara.tv"
type WildcardRule struct {
	// Modern intuitive syntax (avoids leaking implementation details like prefix / suffix):
	Entry    string `json:"entry,omitempty"`    // Entry pattern, e.g. "iwara-*.l.moonchan.xyz" or "iwara-*"
	Upstream string `json:"upstream,omitempty"` // Upstream pattern, e.g. "*.iwara.tv" or "iwara.tv"
	Host     string `json:"host,omitempty"`     // Associated target host, e.g. "iwara.tv"
	Match    string `json:"match,omitempty"`    // Alias (same as entry)
	Target   string `json:"target,omitempty"`   // Alias (same as upstream)

	// Historical compatibility fields (for backward compatibility with legacy slice parameters):
	Prefix          string                `json:"prefix,omitempty"`           // Legacy slice prefix, e.g. "iwara-"
	EntrySuffix     string                `json:"entry_suffix,omitempty"`     // Legacy slice entry suffix, e.g. ".l.moonchan.xyz"
	UpstreamSuffix  string                `json:"upstream_suffix,omitempty"`  // Legacy slice upstream suffix, e.g. ".iwara.tv"
	Headers         map[string]HeaderRule `json:"headers,omitempty"`          // Custom request header override/replace/delete (Referer, Origin, X-Site, etc.)
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"` // Custom response header override/replace/delete
	Cookie          string                `json:"cookie,omitempty"`
	CookieFile      string                `json:"cookie_file,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	BodyReplace     []BodyReplaceRule     `json:"body_replace,omitempty"` // Generic body replacement rules [ ["old", "new"], ... ]

	// Legacy compatibility fields (merged into Headers during load)
	Referer string `json:"referer,omitempty"`
	Origin  string `json:"origin,omitempty"`
	XSite   string `json:"x_site,omitempty"`
}

func (w *WildcardRule) UnmarshalJSON(data []byte) error {
	// 1. Support boolean: "wildcard": true (auto-deduces prefix and suffix from upstream config)
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if !b {
			*w = WildcardRule{}
		}
		return nil
	}
	// 2. Support string shorthand: "wildcard": "iwara-*" or "iwara-*.l.moonchan.xyz"
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		w.Entry = s
		return nil
	}
	// 3. Support standard object deserialization
	type alias WildcardRule
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*w = WildcardRule(a)
	return nil
}

// UpstreamConfig represents an upstream proxy routing rule.
// Mode "" / "ech": Cloudflare ECH domain fronting (target must be behind Cloudflare).
// Mode "sni": SNI camouflage direct connection (DoH resolves real IP + fake SNI + Host routing,
// used for non-Cloudflare sites blocked only by SNI).
// Rewrites: enables response domain replacement: key is real domain, value is proxy entry domain.
// Replacements apply to response headers (Location/Refresh) and text bodies (html/js/json/xml),
// routing all absolute URLs pointing to the real domain through the proxy.
type UpstreamConfig struct {
	Host            string                `json:"host"`
	Describe        string                `json:"describe,omitempty"`
	Display         bool                  `json:"display,omitempty"`
	Headers         map[string]HeaderRule `json:"headers,omitempty"`          // Generic request headers (to upstream: override/inject/delete)
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"` // Generic response headers (to client: override/inject/delete)
	Cookie          string                `json:"cookie,omitempty"`           // Fixed cookie string or local file path
	CookieFile      string                `json:"cookie_file,omitempty"`      // Local cookie file path
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	BodyReplace     []BodyReplaceRule     `json:"body_replace,omitempty"` // Generic body replacement rules [ ["old", "new"], ... ]
	Wildcard        *WildcardRule         `json:"wildcard,omitempty"`

	// Legacy compatibility fields (merged into Headers during load)
	Referer string `json:"referer,omitempty"`
	Origin  string `json:"origin,omitempty"`
	XSite   string `json:"x_site,omitempty"`
}

// UpstreamMap is a map of upstream configurations indexed by request domain.
type UpstreamMap map[string]UpstreamConfig

// WildcardList supports deserialization from both array [ {...} ] and dictionary { "key": {...} } formats.
type WildcardList []WildcardRule

func (wl *WildcardList) UnmarshalJSON(data []byte) error {
	var list []WildcardRule
	if err := json.Unmarshal(data, &list); err == nil {
		*wl = list
		return nil
	}
	var m map[string]WildcardRule
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	res := make([]WildcardRule, 0, len(m))
	for k, v := range m {
		if v.Entry == "" {
			v.Entry = k
		}
		res = append(res, v)
	}
	*wl = res
	return nil
}

// Config represents the complete proxy configuration, including certificate paths, upstream routing rules, and the original entry sequence from JSON.
type Config struct {
	CertPath      string       `json:"cert_path"`
	KeyPath       string       `json:"key_path"`
	Upstreams     UpstreamMap  `json:"upstreams"`
	Wildcards     WildcardList `json:"wildcards,omitempty"` // Standalone wildcard list (supports array or map)
	BlockedHosts  []string     `json:"blocked_hosts"`
	UpstreamOrder []string     `json:"-"`
}

// FetchBytes retrieves byte data from a remote URL with retry and timeout handling.
func FetchBytes(rawURL string) ([]byte, error) {
	client := netdial.Client(netdial.OpTimeout)
	resp, err := netdial.Retry(context.Background(), netdial.RetryAttempts, netdial.RetryBackoff, func() (*http.Response, error) {
		r, e := client.Get(rawURL)
		if e != nil {
			if r != nil {
				r.Body.Close()
			}
			return nil, e
		}
		return r, nil
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// LoadConfig loads the upstream JSON configuration from a remote URL (cert URLs + routing rules).
func LoadConfig(rawURL string) (*Config, error) {
	client := netdial.Client(netdial.OpTimeout)
	resp, err := netdial.Retry(context.Background(), netdial.RetryAttempts, netdial.RetryBackoff, func() (*http.Response, error) {
		r, e := client.Get(rawURL)
		if e != nil {
			if r != nil {
				r.Body.Close()
			}
			return nil, e
		}
		return r, nil
	})
	if err != nil {
		return nil, fmt.Errorf("fetch upstream config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("read upstream config: %w", err)
	}
	return ParseConfig(buf)
}

// ParseConfig parses JSON configuration data into a Config object.
func ParseConfig(buf []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(buf, &cfg); err != nil {
		return nil, fmt.Errorf("decode upstream config: %w", err)
	}
	om := orderedmap.New()
	if err := json.Unmarshal(buf, om); err == nil {
		if us, ok := om.Get("upstreams"); ok {
			switch usMap := us.(type) {
			case orderedmap.OrderedMap:
				cfg.UpstreamOrder = usMap.Keys()
			case *orderedmap.OrderedMap:
				cfg.UpstreamOrder = usMap.Keys()
			}
		}
	}
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("upstream config has no upstreams")
	}
	normalizeConfig(&cfg)
	return &cfg, nil
}

// ApplyHeaderRules applies generic header rules to the target http.Header:
// 1. When rule.Delete is true: completely remove the header
// 2. When rule.Replace is present: perform [before, after] replacement on the header value (supports regex or string)
// 3. When rule.Value is empty: remove the header
// 4. When rule.Value is non-empty:
//    - For Origin header: smart protection, only inject if client sent Origin or method is not GET/HEAD, preventing pollution of normal navigation
//    - For other headers: directly set/overwrite
func ApplyHeaderRules(h http.Header, rules map[string]HeaderRule, isRequest bool, clientReq *http.Request) {
	for k, rule := range rules {
		if rule.Delete {
			h.Del(k)
			continue
		}
		if len(rule.Replace) >= 2 {
			cur := h.Get(k)
			if cur != "" {
				if rule.compiledReplace != nil {
					h.Set(k, rule.compiledReplace.ReplaceAllString(cur, rule.Replace[1]))
				} else {
					h.Set(k, strings.ReplaceAll(cur, rule.Replace[0], rule.Replace[1]))
				}
			}
			continue
		}
		if rule.Value == "" {
			h.Del(k)
			continue
		}
		if isRequest && strings.EqualFold(k, "Origin") && clientReq != nil {
			if clientReq.Header.Get("Origin") != "" || (clientReq.Method != http.MethodGet && clientReq.Method != http.MethodHead) {
				h.Set(k, rule.Value)
			}
		} else {
			h.Set(k, rule.Value)
		}
	}
}

// normalizeConfig normalizes upstream configurations:
// 1. Converges legacy referer, origin, and x_site into the unified Headers map;
// 2. Automatically derives upstream Origin from Headers["Referer"] or referer if not explicitly set;
// 3. Automatically infers omitted suffix and prefix based on upstream hostnames, eliminating redundancy;
// 4. Backfills legacy struct fields to maintain full bidirectional compatibility.
func normalizeConfig(cfg *Config) {
	// Extract common entry root domain from existing upstreams (e.g. ".l.moonchan.xyz")
	var defaultEntrySuffix string
	for hostKey := range cfg.Upstreams {
		if idx := strings.Index(hostKey, "."); idx >= 0 {
			defaultEntrySuffix = hostKey[idx:]
			break
		}
	}

	for host, uc := range cfg.Upstreams {
		if uc.Headers == nil {
			uc.Headers = make(map[string]HeaderRule)
		}
		if uc.Referer != "" {
			if _, ok := uc.Headers["Referer"]; !ok {
				uc.Headers["Referer"] = HeaderRule{Value: uc.Referer}
			}
		}
		if uc.Origin != "" {
			if _, ok := uc.Headers["Origin"]; !ok {
				uc.Headers["Origin"] = HeaderRule{Value: uc.Origin}
			}
		}
		if uc.XSite != "" {
			if _, ok := uc.Headers["X-Site"]; !ok {
				uc.Headers["X-Site"] = HeaderRule{Value: uc.XSite}
			}
		}
		if _, hasOrigin := uc.Headers["Origin"]; !hasOrigin {
			if refRule, ok := uc.Headers["Referer"]; ok && refRule.Value != "" && !refRule.Delete {
				if u, err := url.Parse(refRule.Value); err == nil && u.Host != "" {
					uc.Headers["Origin"] = HeaderRule{Value: u.Scheme + "://" + u.Host}
				}
			}
		}
		if r, ok := uc.Headers["Referer"]; ok && !r.Delete && len(r.Replace) == 0 {
			uc.Referer = r.Value
		}
		if r, ok := uc.Headers["Origin"]; ok && !r.Delete && len(r.Replace) == 0 {
			uc.Origin = r.Value
		}
		if r, ok := uc.Headers["X-Site"]; ok && !r.Delete && len(r.Replace) == 0 {
			uc.XSite = r.Value
		}

		if w := uc.Wildcard; w != nil {
			// If entry_suffix is omitted, infer automatically from current host (e.g. "iwara.l.moonchan.xyz" -> ".l.moonchan.xyz")
			if w.EntrySuffix == "" {
				if idx := strings.Index(host, "."); idx >= 0 {
					w.EntrySuffix = host[idx:]
					if w.Prefix == "" {
						w.Prefix = host[:idx] + "-"
					}
				} else if defaultEntrySuffix != "" {
					w.EntrySuffix = defaultEntrySuffix
				}
			}
			// If upstream_suffix is omitted, infer automatically from uc.Host (e.g. "iwara.tv" -> ".iwara.tv")
			if w.UpstreamSuffix == "" && uc.Host != "" {
				w.UpstreamSuffix = "." + strings.TrimPrefix(uc.Host, ".")
			}
			normalizeWildcardRule(w)
		}
		cfg.Upstreams[host] = uc
	}

	// Normalize standalone top-level wildcards list, merge with associated upstream or register independently
	for i := range cfg.Wildcards {
		w := &cfg.Wildcards[i]
		normalizeWildcardRule(w)

		// If using entry: "*.domain.com" or Host is set, derive Prefix and EntrySuffix from existing matching upstream
		if w.Prefix == "" || w.EntrySuffix == "" {
			targetHost := w.Host
			if targetHost == "" && w.UpstreamSuffix != "" {
				targetHost = strings.TrimPrefix(w.UpstreamSuffix, ".")
			}
			for host, uc := range cfg.Upstreams {
				if (targetHost != "" && uc.Host == targetHost) || (w.UpstreamSuffix != "" && uc.Wildcard != nil && uc.Wildcard.UpstreamSuffix == w.UpstreamSuffix) {
					if uc.Wildcard != nil {
						if w.Prefix == "" {
							w.Prefix = uc.Wildcard.Prefix
						}
						if w.EntrySuffix == "" {
							w.EntrySuffix = uc.Wildcard.EntrySuffix
						}
						if w.UpstreamSuffix == "" {
							w.UpstreamSuffix = uc.Wildcard.UpstreamSuffix
						}
					} else {
						if idx := strings.Index(host, "."); idx >= 0 {
							if w.Prefix == "" {
								w.Prefix = host[:idx] + "-"
							}
							if w.EntrySuffix == "" {
								w.EntrySuffix = host[idx:]
							}
						}
					}
					break
				}
			}
		}

		if w.EntrySuffix == "" && defaultEntrySuffix != "" {
			w.EntrySuffix = defaultEntrySuffix
		}
		if w.Prefix == "" {
			targetHost := w.Host
			if targetHost == "" && w.UpstreamSuffix != "" {
				targetHost = strings.TrimPrefix(w.UpstreamSuffix, ".")
			}
			if targetHost != "" {
				parts := strings.Split(targetHost, ".")
				w.Prefix = parts[0] + "-"
			}
		}
		if w.UpstreamSuffix == "" && w.Host != "" {
			w.UpstreamSuffix = "." + strings.TrimPrefix(w.Host, ".")
		}

		// Check if any existing upstream matches this wildcard rule
		matched := false
		for host, uc := range cfg.Upstreams {
			isMatch := false
			if uc.Wildcard != nil {
				if w.Prefix != "" && w.EntrySuffix != "" && uc.Wildcard.Prefix == w.Prefix && uc.Wildcard.EntrySuffix == w.EntrySuffix {
					isMatch = true
				} else if w.UpstreamSuffix != "" && uc.Wildcard.UpstreamSuffix == w.UpstreamSuffix {
					isMatch = true
				} else if w.Host != "" && uc.Host == w.Host {
					isMatch = true
				}
			} else if (w.Host != "" && uc.Host == w.Host) || (w.UpstreamSuffix != "" && w.UpstreamSuffix == "."+strings.TrimPrefix(uc.Host, ".")) {
				isMatch = true
			}

			if isMatch {
				matched = true
				if uc.Wildcard == nil {
					wCopy := *w
					if wCopy.EntrySuffix == "" {
						if idx := strings.Index(host, "."); idx >= 0 {
							wCopy.EntrySuffix = host[idx:]
						}
					}
					if wCopy.Prefix == "" {
						if idx := strings.Index(host, "."); idx >= 0 {
							wCopy.Prefix = host[:idx] + "-"
						}
					}
					if wCopy.UpstreamSuffix == "" && uc.Host != "" {
						wCopy.UpstreamSuffix = "." + strings.TrimPrefix(uc.Host, ".")
					}
					uc.Wildcard = &wCopy
				}
				if len(w.Headers) > 0 {
					if uc.Wildcard.Headers == nil {
						uc.Wildcard.Headers = make(map[string]HeaderRule)
					}
					for k, v := range w.Headers {
						uc.Wildcard.Headers[k] = v
					}
				}
				if len(w.ResponseHeaders) > 0 {
					if uc.Wildcard.ResponseHeaders == nil {
						uc.Wildcard.ResponseHeaders = make(map[string]HeaderRule)
					}
					for k, v := range w.ResponseHeaders {
						uc.Wildcard.ResponseHeaders[k] = v
					}
				}
				if w.Cookie != "" {
					uc.Wildcard.Cookie = w.Cookie
				}
				if w.CookieFile != "" {
					uc.Wildcard.CookieFile = w.CookieFile
				}
				if w.Mode != "" {
					uc.Wildcard.Mode = w.Mode
				}
				if len(w.Rewrites) > 0 {
					if uc.Wildcard.Rewrites == nil {
						uc.Wildcard.Rewrites = make(map[string]string)
					}
					for k, v := range w.Rewrites {
						uc.Wildcard.Rewrites[k] = v
					}
				}
				cfg.Upstreams[host] = uc
				break
			}
		}

		// If no matching existing upstream, register as standalone wildcard upstream in cfg.Upstreams
		if !matched {
			virtualHost := w.Entry
			if virtualHost == "" || strings.HasPrefix(virtualHost, "*.") {
				virtualHost = w.Prefix + "*" + w.EntrySuffix
			}
			wCopy := *w
			cfg.Upstreams[virtualHost] = UpstreamConfig{
				Host:            w.UpstreamSuffix,
				Headers:         w.Headers,
				ResponseHeaders: w.ResponseHeaders,
				Cookie:          w.Cookie,
				CookieFile:      w.CookieFile,
				Mode:            w.Mode,
				Rewrites:        w.Rewrites,
				SWInject:        w.SWInject,
				Wildcard:        &wCopy,
			}
		}
	}

	compilePatterns(cfg)
}

// compilePatterns pre-compiles all regex patterns in the config so they are not
// recompiled on every request. Covers HeaderRule.Replace and BodyReplaceRule.Old
// across upstreams, response headers, and wildcard rules.
func compilePatterns(cfg *Config) {
	for host, uc := range cfg.Upstreams {
		compileBodyReplaceRules(uc.BodyReplace)
		compileHeaderRules(uc.Headers)
		compileHeaderRules(uc.ResponseHeaders)
		if w := uc.Wildcard; w != nil {
			compileBodyReplaceRules(w.BodyReplace)
			compileHeaderRules(w.Headers)
			compileHeaderRules(w.ResponseHeaders)
		}
		// BodyReplace slice elements are modified in-place via index;
		// Headers/ResponseHeaders maps are reference types. No reassign needed
		// unless struct-level fields were changed — they weren't.
		_ = host
	}
}

// compileBodyReplaceRules pre-compiles regex patterns for body replacement rules.
func compileBodyReplaceRules(rules []BodyReplaceRule) {
	for i := range rules {
		if rules[i].Old != "" {
			rules[i].compiled, _ = regexp.Compile(rules[i].Old)
		}
	}
}

// compileHeaderRules pre-compiles regex patterns for header replacement rules.
func compileHeaderRules(rules map[string]HeaderRule) {
	for k, rule := range rules {
		if len(rule.Replace) >= 2 {
			rule.compiledReplace, _ = regexp.Compile(rule.Replace[0])
			rules[k] = rule
		}
	}
}

// normalizeWildcardRule normalizes wildcard rules:
// 1. Supports direct upstream target pattern: entry: "*.iwara.tv" (minimal syntax)
// 2. Supports intuitive entry/upstream pattern: entry: "iwara-*.l.moonchan.xyz", upstream: "*.iwara.tv"
// 3. Supports match/target/host aliases, eliminating low-level slice field coupling
// 4. Converges referer, origin, and x_site into the Headers map
func normalizeWildcardRule(w *WildcardRule) {
	if w == nil {
		return
	}
	if w.Entry == "" && w.Match != "" {
		w.Entry = w.Match
	}
	if w.Upstream == "" {
		if w.Target != "" {
			w.Upstream = w.Target
		} else if w.Host != "" {
			w.Upstream = w.Host
		}
	}
	// Pattern 1: entry in "*.domain.com" form (e.g. entry: "*.iwara.tv")
	if strings.HasPrefix(w.Entry, "*.") {
		targetDomain := strings.TrimPrefix(w.Entry, "*.")
		if w.Upstream == "" {
			w.Upstream = w.Entry
		}
		if w.UpstreamSuffix == "" {
			w.UpstreamSuffix = "." + targetDomain
		}
		if w.Host == "" {
			w.Host = targetDomain
		}
	} else if w.Entry != "" && (w.Prefix == "" && w.EntrySuffix == "") {
		// Pattern 2: entry in "iwara-*.l.moonchan.xyz" form
		if idx := strings.Index(w.Entry, "*"); idx >= 0 {
			w.Prefix = w.Entry[:idx]
			w.EntrySuffix = w.Entry[idx+1:]
		} else if strings.HasSuffix(w.Entry, "-") {
			w.Prefix = w.Entry
		}
	}
	// Parse UpstreamSuffix from Upstream pattern
	if w.Upstream != "" && w.UpstreamSuffix == "" {
		if idx := strings.Index(w.Upstream, "*"); idx >= 0 {
			w.UpstreamSuffix = w.Upstream[idx+1:]
		} else {
			if strings.HasPrefix(w.Upstream, ".") {
				w.UpstreamSuffix = w.Upstream
			} else {
				w.UpstreamSuffix = "." + w.Upstream
			}
		}
	}
	if w.Entry == "" && w.Prefix != "" && w.EntrySuffix != "" {
		w.Entry = w.Prefix + "*" + w.EntrySuffix
	}
	if w.Upstream == "" && w.UpstreamSuffix != "" {
		w.Upstream = "*" + w.UpstreamSuffix
	}
	if w.Headers == nil {
		w.Headers = make(map[string]HeaderRule)
	}
	if w.Referer != "" {
		if _, ok := w.Headers["Referer"]; !ok {
			w.Headers["Referer"] = HeaderRule{Value: w.Referer}
		}
	}
	if w.Origin != "" {
		if _, ok := w.Headers["Origin"]; !ok {
			w.Headers["Origin"] = HeaderRule{Value: w.Origin}
		}
	}
	if w.XSite != "" {
		if _, ok := w.Headers["X-Site"]; !ok {
			w.Headers["X-Site"] = HeaderRule{Value: w.XSite}
		}
	}
	if _, hasOrigin := w.Headers["Origin"]; !hasOrigin {
		if refRule, ok := w.Headers["Referer"]; ok && refRule.Value != "" && !refRule.Delete {
			if u, err := url.Parse(refRule.Value); err == nil && u.Host != "" {
				w.Headers["Origin"] = HeaderRule{Value: u.Scheme + "://" + u.Host}
			}
		}
	}
	if r, ok := w.Headers["Referer"]; ok && !r.Delete && len(r.Replace) == 0 {
		w.Referer = r.Value
	}
	if r, ok := w.Headers["Origin"]; ok && !r.Delete && len(r.Replace) == 0 {
		w.Origin = r.Value
	}
	if r, ok := w.Headers["X-Site"]; ok && !r.Delete && len(r.Replace) == 0 {
		w.XSite = r.Value
	}
}
