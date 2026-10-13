// route_cache.go implements per-host route detection and caching for the
// ech-proxy. When the upstream config specifies "auto" mode (or a hint that
// fails at runtime), the proxy probes the host to determine whether it should
// be reached via Cloudflare ECH, SNI camouflage, or a direct connection.
//
// Detection is three-layered:
//
//  1. Cloudflare IP check — pure DNS resolution, no network probe. If the
//     host resolves to a known Cloudflare IP range, ECH is the correct path.
//  2. ECH probe — a HEAD request through the ECH tunnel with a short timeout.
//  3. SNI probe — a HEAD request through SNI camouflage with a short timeout.
//  4. Direct fallback — if both tunnel probes fail, try a plain HTTPS request.
//
// Results are cached per-host with a configurable TTL so subsequent requests
// to the same host skip probing entirely.
package echproxy

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	cloudflare_ech "github.com/Hana-ame/ech-proxy/echproxy/ech"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

const (
	// routeCacheTTL is how long a route decision stays valid before re-probing.
	routeCacheTTL = 24 * time.Hour

	// probeTimeout bounds each individual probe attempt.
	probeTimeout = 5 * time.Second

	// probeProbeTimeout is the extra margin for DNS resolution before the
	// probe timeout starts ticking.
	dnsTimeout = 3 * time.Second
)

// RouteDecision records the successful transport mode for a host.
type RouteDecision struct {
	Mode     string    // "ech", "sni", or "direct"
	Resolved time.Time // when the decision was made
}

// RouteCache is a thread-safe per-host route decision cache.
type RouteCache struct {
	mu     sync.RWMutex
	routes map[string]*RouteDecision
}

// The global route cache shared by all requests.
var globalRouteCache = &RouteCache{
	routes: make(map[string]*RouteDecision),
}

// GetRoute returns the cached route for host, or false if absent or expired.
func GetRoute(host string) (string, bool) {
	host = normalizeHost(host)
	globalRouteCache.mu.RLock()
	defer globalRouteCache.mu.RUnlock()
	d, ok := globalRouteCache.routes[host]
	if !ok || time.Since(d.Resolved) > routeCacheTTL {
		return "", false
	}
	return d.Mode, true
}

// SetRoute caches the successful mode for host.
func SetRoute(host, mode string) {
	host = normalizeHost(host)
	globalRouteCache.mu.Lock()
	defer globalRouteCache.mu.Unlock()
	globalRouteCache.routes[host] = &RouteDecision{
		Mode:     mode,
		Resolved: time.Now(),
	}
}

// ClearRoute removes the cached route for host (used on probe failure).
func ClearRoute(host string) {
	host = normalizeHost(host)
	globalRouteCache.mu.Lock()
	defer globalRouteCache.mu.Unlock()
	delete(globalRouteCache.routes, host)
}

func normalizeHost(h string) string {
	if h == "" {
		return ""
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// --- Probe logic ---

// probeRoute detects the optimal transport for host using the three-layer
// strategy. It returns the mode name that worked.
func probeRoute(req *http.Request, host string) string {
	// Layer 1: Cloudflare IP check (fastest — pure DNS, no probe).
	if isCloudflareHost(host) {
		return "ech"
	}

	// Layer 2: ECH probe.
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout+probeTimeout)
	defer cancel()
	probeReq := cloneRequest(ctx, req, host)
	if resp, err := cloudflare_ech.Do(probeReq, "auto"); err == nil {
		resp.Body.Close()
		return "ech"
	}

	// Layer 3: SNI probe.
	probeReq2 := cloneRequest(ctx, req, host)
	if resp, err := sniFrontDo(probeReq2); err == nil {
		resp.Body.Close()
		return "sni"
	}

	// Layer 4: Direct fallback.
	probeReq3 := cloneRequest(ctx, req, host)
	if resp, err := netdial.Client(probeTimeout).Do(probeReq3); err == nil {
		resp.Body.Close()
		return "direct"
	}

	// Nothing worked — return "ech" as default so the caller can retry with
	// full logging. The caller's fallback chain will try the others.
	return "ech"
}

// cloneRequest creates a lightweight HEAD clone of req targeting host, suitable
// for probing. It strips the request body and sets a HEAD method.
func cloneRequest(ctx context.Context, req *http.Request, host string) *http.Request {
	probeReq, _ := http.NewRequestWithContext(ctx, http.MethodHead, req.URL.String(), nil)
	probeReq.Host = host
	probeReq.Header.Set("User-Agent", "ech-proxy-probe/1.0")
	probeReq.Header.Set("Accept", "*/*")
	return probeReq
}

// --- Cloudflare IP detection ---

// cloudflareIPv4Ranges are the v4 CIDR blocks currently published by Cloudflare
// (https://www.cloudflare.com/ips-v4/). These are refreshed on demand but the
// list is small and stable; a stale range only means a false negative (we'd
// probe instead of shortcutting), never a false positive.
var cloudflareIPv4Ranges = []string{
	"104.16.0.0/13",
	"104.24.0.0/14",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
}

// cloudflareIPv6Ranges are the v6 prefixes currently published by Cloudflare
// (https://www.cloudflare.com/ips-v6/).
var cloudflareIPv6Ranges = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2c0f:fb50::/32",
	"2a06:98c0::/29",
	"2a06:98c1::/32",
	"2a06:98c2::/31",
}

// isCloudflareHost resolves host and checks if any A/AAAA record falls within
// Cloudflare's published IP ranges. Returns true on a positive match.
// This is distinct from isCloudflareIP (wildcard.go) which checks a single IP.
func isCloudflareHost(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		ipStr := ip.String()

		// v4 check
		if ip.To4() != nil {
			for _, cidr := range cloudflareIPv4Ranges {
				if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
					return true
				}
			}
		}
		// v6 check
		if ip.To4() == nil {
			for _, cidr := range cloudflareIPv6Ranges {
				if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
					return true
				}
			}
		}
		_ = ipStr
	}
	return false
}

// --- Auto-roundTrip: the wrapper that combines hint, cache, and probe ---

// autoRoundTrip is the drop-in replacement for proxyRoundTrip that adds hint
// validation, cache lookup, probe fallback, and cache invalidation.
//
// Flow:
//  1. Check RouteCache for host. Hit → use cached mode.
//  2. Try hint mode (including empty, which defaults to "ech"). Success → cache and return.
//  3. Hint fails → probeRoute() to find the right mode → cache → retry.
//  4. Probe mode also fails → try the remaining modes in fallback order.
//  5. Clear cache on total failure so next request re-probes.
//
// Empty hint mode ("") is NOT treated as "auto" — it means the config didn't
// specify a mode, which defaults to "ech" in proxyRoundTrip. We try that first,
// and only probe if it fails.
func autoRoundTrip(req *http.Request, hintMode, ipMode string) (*http.Response, error) {
	host := extractHost(req)

	// Fast path: cached route.
	if cachedMode, ok := GetRoute(host); ok {
		resp, err := roundTripFn(req, cachedMode, ipMode)
		if err == nil {
			return resp, nil
		}
		// Cached mode broke — clear and fall through to probe.
		ClearRoute(host)
		log.Printf("[route] cached mode %q failed for %s, re-probing", cachedMode, host)
	}

	// Explicit "auto" mode: skip hint and go straight to detection.
	if hintMode == "auto" {
		probed := probeRoute(req, host)
		SetRoute(host, probed)
		log.Printf("[route] probed %s -> %s", host, probed)
		resp, err := roundTripFn(req, probed, ipMode)
		if err == nil {
			return resp, nil
		}
		// Probed mode failed too — try fallback chain.
		ClearRoute(host)
		return fallbackRoundTrip(req, host, probed, ipMode)
	}

	// Hint mode (including empty = default "ech"): try it first.
	resp, err := roundTripFn(req, hintMode, ipMode)
	if err == nil {
		SetRoute(host, hintMode)
		return resp, nil
	}

	// Hint failed — probe for the real mode.
	probed := probeRoute(req, host)
	SetRoute(host, probed)
	log.Printf("[route] hint %q failed for %s, probed -> %s", hintMode, host, probed)
	resp, err = roundTripFn(req, probed, ipMode)
	if err == nil {
		return resp, nil
	}

	// Probe also failed — clear and try fallback.
	ClearRoute(host)
	return fallbackRoundTrip(req, host, probed, ipMode)
}

// fallbackRoundTrip tries the remaining modes after a hint/probe failure.
// It skips the already-attempted mode and tries the others in order.
func fallbackRoundTrip(req *http.Request, host, skipMode, ipMode string) (*http.Response, error) {
	modes := []string{"ech", "sni", "direct"}
	var lastErr error
	for _, m := range modes {
		if m == skipMode {
			continue
		}
		resp, err := roundTripFn(req, m, ipMode)
		if err == nil {
			SetRoute(host, m)
			log.Printf("[route] fallback: %s -> %s (via %s)", host, m, "fallback")
			return resp, nil
		}
		lastErr = err
		log.Printf("[route] fallback %s failed for %s: %v", m, host, err)
	}
	return nil, lastErr
}

// extractHost returns the hostname from the request URL or Host header.
func extractHost(req *http.Request) string {
	h := req.URL.Host
	if h == "" {
		h = req.Host
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(h)
}
