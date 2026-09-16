package echproxy

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// MatchWildcardForTest 导出通配匹配判断, 供 main 路由分发确认
func MatchWildcardForTest(cfg UpstreamMap, host string) (UpstreamConfig, bool) {
	return matchWildcard(cfg, host)
}

func matchWildcard(cfg UpstreamMap, host string) (UpstreamConfig, bool) {
	for _, uc := range cfg {
		w := uc.Wildcard
		if w == nil {
			continue
		}
		sub := strings.TrimPrefix(host, w.Prefix)
		if sub == host || sub == "" {
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
		if w.Referer != "" {
			out.Referer = w.Referer
		}
		if len(w.Headers) > 0 {
			merged := make(map[string]HeaderRule, len(out.Headers)+len(w.Headers))
			for k, v := range out.Headers {
				merged[k] = v
			}
			for k, v := range w.Headers {
				merged[k] = v
			}
			out.Headers = merged
		}
		if len(w.ResponseHeaders) > 0 {
			merged := make(map[string]HeaderRule, len(out.ResponseHeaders)+len(w.ResponseHeaders))
			for k, v := range out.ResponseHeaders {
				merged[k] = v
			}
			for k, v := range w.ResponseHeaders {
				merged[k] = v
			}
			out.ResponseHeaders = merged
		}
		if out.Headers != nil {
			if o, ok := out.Headers["Origin"]; ok && o.Value != "" {
				out.Origin = o.Value
			}
			if x, ok := out.Headers["X-Site"]; ok && x.Value != "" {
				out.XSite = x.Value
			}
		}
		if w.Cookie != "" {
			out.Cookie = w.Cookie
		}
		if w.CookieFile != "" {
			out.CookieFile = w.CookieFile
		}
		if out.Cookie == "" {
			out.Cookie = uc.Cookie
		}
		if !out.SWInject {
			out.SWInject = uc.SWInject
		}
		if len(w.BodyReplace) > 0 {
			out.BodyReplace = append(out.BodyReplace, w.BodyReplace...)
		}
		if out.Mode == "" || out.Mode == "ech" {
			out.Mode = wildcardMode(context.Background(), out.Host)
		}
		debugLogf("[通配] %s -> %s (mode=%s referer=%s origin=%s xsite=%s headers=%d)", host, out.Host, out.Mode, out.Referer, out.Origin, out.XSite, len(out.Headers))
		return out, true
	}
	return UpstreamConfig{}, false
}

var wildcardModeCache sync.Map

type modeCacheEntry struct {
	mode   string
	expiry time.Time
}

const wildcardModeTTL = 10 * time.Minute

var resolveIPFn = resolveHostIP

func wildcardMode(ctx context.Context, host string) string {
	if v, ok := wildcardModeCache.Load(host); ok {
		e := v.(modeCacheEntry)
		if time.Now().Before(e.expiry) {
			return e.mode
		}
	}
	mode := ""
	if ip, err := resolveIPFn(ctx, host); err == nil {
		if !isCloudflareIP(net.ParseIP(ip)) {
			mode = "sni"
		}
	}
	wildcardModeCache.Store(host, modeCacheEntry{mode: mode, expiry: time.Now().Add(wildcardModeTTL)})
	return mode
}

var cloudflareCIDRs = []string{
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"141.101.64.0/18",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var cloudflareNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cloudflareCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func inheritWildcard(cfg UpstreamMap, entry string) *WildcardRule {
	for _, uc := range cfg {
		w := uc.Wildcard
		if w == nil {
			continue
		}
		if strings.HasPrefix(entry, w.Prefix) && strings.HasSuffix(entry, w.EntrySuffix) {
			return w
		}
	}
	return nil
}
