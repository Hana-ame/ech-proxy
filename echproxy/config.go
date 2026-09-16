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

// HeaderRule 定义单个 Header 的操作规则:
// 支持字符串简写 (直接设置/替换): "Origin": "https://www.iwara.tv"
// 支持对象高级控制:
//  - 删除: {"delete": true}
//  - 替换: {"replace": ["before", "after"]}
type HeaderRule struct {
	Value   string   `json:"value,omitempty"`
	Delete  bool     `json:"delete,omitempty"`
	Replace []string `json:"replace,omitempty"` // [before, after]
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

// WildcardRule 通配上游规则:
// 请求域名 = Prefix + <sub> + EntrySuffix 时, 转发到 <sub> + UpstreamSuffix。
// 例: entry="iwara-*.l.moonchan.xyz" upstream="*.iwara.tv"
type WildcardRule struct {
	// 直观现代语法 (完全摒弃 prefix / suffix 等实现细节泄露 key):
	Entry    string `json:"entry,omitempty"`    // 入口模式, 如 "iwara-*.l.moonchan.xyz" 或 "iwara-*"
	Upstream string `json:"upstream,omitempty"` // 上游模式, 如 "*.iwara.tv" 或 "iwara.tv"
	Host     string `json:"host,omitempty"`     // 关联的目标主机, 如 "iwara.tv"
	Match    string `json:"match,omitempty"`    // 别名 (同 entry)
	Target   string `json:"target,omitempty"`   // 别名 (同 upstream)

	// 历史兼容字段 (仅用于向后兼容旧配置中的底层切片参数):
	Prefix          string                `json:"prefix,omitempty"`           // 历史切片前缀, 如 "iwara-"
	EntrySuffix     string                `json:"entry_suffix,omitempty"`     // 历史切片入口后缀, 如 ".l.moonchan.xyz"
	UpstreamSuffix  string                `json:"upstream_suffix,omitempty"`  // 历史切片上游后缀, 如 ".iwara.tv"
	Headers         map[string]HeaderRule `json:"headers,omitempty"`          // 自定义请求头覆盖/替换/删除 (含 Referer, Origin, X-Site 等)
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"` // 自定义响应头覆盖/替换/删除
	Cookie          string                `json:"cookie,omitempty"`
	CookieFile      string                `json:"cookie_file,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`

	// 历史兼容字段 (加载时自动合入 Headers)
	Referer string `json:"referer,omitempty"`
	Origin  string `json:"origin,omitempty"`
	XSite   string `json:"x_site,omitempty"`
}

func (w *WildcardRule) UnmarshalJSON(data []byte) error {
	// 1. 支持布尔值: "wildcard": true (自动从上游配置推导全部前缀与后缀)
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if !b {
			*w = WildcardRule{}
		}
		return nil
	}
	// 2. 支持字符串简写: "wildcard": "iwara-*" 或 "iwara-*.l.moonchan.xyz"
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		w.Entry = s
		return nil
	}
	// 3. 支持常规对象反序列化
	type alias WildcardRule
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*w = WildcardRule(a)
	return nil
}

// UpstreamConfig 表示一条上游转发规则。
// Mode 为 "" / "ech" 时走 ECH 域前置（要求目标在 Cloudflare 后面），
// 为 "sni" 时走 SNI 伪装直连（DoH 解析真实 IP + 假 SNI + Host 路由，
// 用于不在 Cloudflare 后面、仅被 SNI 阻断的站点）。
// Rewrites 非空时启用响应域名替换：key 为真实域名，value 为代理入口域名。
// 替换应用到响应头（Location/Refresh）与文本 body（html/js/json/xml），
// 使页面内所有指向真实域名的绝对 URL 都改走代理入口，形成闭环。
type UpstreamConfig struct {
	Host            string                `json:"host"`
	Describe        string                `json:"describe,omitempty"`
	Display         bool                  `json:"display,omitempty"`
	Headers         map[string]HeaderRule `json:"headers,omitempty"`          // 通用请求头字典 (发往上游: 覆盖/注入/删除)
	ResponseHeaders map[string]HeaderRule `json:"response_headers,omitempty"` // 通用响应头字典 (返回客户端: 覆盖/注入/删除)
	Cookie          string                `json:"cookie,omitempty"`           // 固定 Cookie 字符串或本地文件路径
	CookieFile      string                `json:"cookie_file,omitempty"`      // 本地 Cookie 文件路径
	SWInject        bool                  `json:"sw_inject,omitempty"`
	Mode            string                `json:"mode,omitempty"`
	Rewrites        map[string]string     `json:"rewrites,omitempty"`
	Wildcard        *WildcardRule         `json:"wildcard,omitempty"`

	// 历史兼容字段 (加载时自动合入 Headers)
	Referer string `json:"referer,omitempty"`
	Origin  string `json:"origin,omitempty"`
	XSite   string `json:"x_site,omitempty"`
}

// UpstreamMap 按请求域名索引的上游配置集合。
type UpstreamMap map[string]UpstreamConfig

// WildcardList 支持数组 [ {...} ] 或字典 { "key": {...} } 格式的反序列化
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

// Config 是代理的完整配置，包含证书路径、上游路由规则及各入口在 JSON 中的原始书写顺序。
type Config struct {
	CertPath      string       `json:"cert_path"`
	KeyPath       string       `json:"key_path"`
	Upstreams     UpstreamMap  `json:"upstreams"`
	Wildcards     WildcardList `json:"wildcards,omitempty"` // 独立通配列表 (支持数组或字典)
	BlockedHosts  []string     `json:"blocked_hosts"`
	UpstreamOrder []string     `json:"-"`
}

// FetchBytes 从远程 URL 获取字节数据，支持重试与超时控制。
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

// LoadConfig 从远程 URL 加载上游配置 JSON（证书 URL + 路由规则）。
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

// ParseConfig 解析 JSON 配置数据为 Config 对象。
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

// ApplyHeaderRules 应用通用 Header 规则集合到目标 http.Header:
// 1. rule.Delete 为 true 时: 彻底剔除该 Header
// 2. rule.Replace 存在时: 对该 Header 的值做 [before, after] 替换 (支持正则或普通字符串)
// 3. rule.Value 为空字符串时: 剔除该 Header
// 4. rule.Value 非空时:
//    - 若为 Origin 请求头: 智能防护，仅在客户端带 Origin 或非 GET/HEAD 谓词时注入，防止污染普通导航
//    - 其他 Header: 直接覆盖设置
func ApplyHeaderRules(h http.Header, rules map[string]HeaderRule, isRequest bool, clientReq *http.Request) {
	for k, rule := range rules {
		if rule.Delete {
			h.Del(k)
			continue
		}
		if len(rule.Replace) >= 2 {
			cur := h.Get(k)
			if cur != "" {
				before := rule.Replace[0]
				after := rule.Replace[1]
				if re, err := regexp.Compile(before); err == nil {
					h.Set(k, re.ReplaceAllString(cur, after))
				} else {
					h.Set(k, strings.ReplaceAll(cur, before, after))
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

// normalizeConfig 对上游配置做归一化收敛:
// 1. 将历史配置中的 referer, origin, x_site 收敛到通用的 Headers 字典;
// 2. 若未显式配置 Origin, 则自动从 Headers["Referer"] 或 referer 推导出上游 Origin;
// 3. 自动根据上游主机名推导省略的 suffix 与 prefix，消除冗余配置项;
// 4. 反向同步补全结构体历史字段, 保证向前向后双向兼容。
func normalizeConfig(cfg *Config) {
	// 从已有上游提取公共 entry 根域名 (例如 ".l.moonchan.xyz")
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
			// 如果未手动写 entry_suffix，从当前 host 自动推断 (如 "iwara.l.moonchan.xyz" -> ".l.moonchan.xyz")
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
			// 如果未手动写 upstream_suffix，从 uc.Host 自动推断 (如 "iwara.tv" -> ".iwara.tv")
			if w.UpstreamSuffix == "" && uc.Host != "" {
				w.UpstreamSuffix = "." + strings.TrimPrefix(uc.Host, ".")
			}
			normalizeWildcardRule(w)
		}
		cfg.Upstreams[host] = uc
	}

	// 规范化顶层独立 wildcards 列表，并与关联的 upstream 进行合并或独立注册
	for i := range cfg.Wildcards {
		w := &cfg.Wildcards[i]
		normalizeWildcardRule(w)

		// 若使用 entry: "*.domain.com" 或设置了 Host，从已有同名 upstream 自动推导 Prefix 与 EntrySuffix
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

		// 检查是否有关联的 upstream 匹配该通配规则
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

		// 若无关联的现有 upstream，作为独立通配上游注册进 cfg.Upstreams
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
}

// normalizeWildcardRule 规范化通配规则:
// 1. 支持直接指向上游目标的模式: entry: "*.iwara.tv" (极简写法)
// 2. 支持直观 entry/upstream 模式: entry: "iwara-*.l.moonchan.xyz", upstream: "*.iwara.tv"
// 3. 支持 match/target/host 别名，完全消除底层切片字段对配置的侵入
// 4. 将 referer, origin, x_site 收敛到 Headers 字典中
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
	// 模式 1: entry 形式为 "*.domain.com" (如 entry: "*.iwara.tv")
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
		// 模式 2: entry 形式为 "iwara-*.l.moonchan.xyz"
		if idx := strings.Index(w.Entry, "*"); idx >= 0 {
			w.Prefix = w.Entry[:idx]
			w.EntrySuffix = w.Entry[idx+1:]
		} else if strings.HasSuffix(w.Entry, "-") {
			w.Prefix = w.Entry
		}
	}
	// 从 Upstream 模式解析 UpstreamSuffix
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
