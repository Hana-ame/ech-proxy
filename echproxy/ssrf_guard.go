package echproxy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Destination validation for the CONNECT tunnel.
//
// Why this lives where it does, and not somewhere "smarter":
//
// The tunnel is opaque. handleConnect parses host:port out of the request,
// hijacks the connection, opens a TCP pipe, and relays bytes. It never
// terminates TLS, so there is no certificate and no SNI to validate — the only
// thing that identifies the destination is the target string in the request
// itself. Validation therefore has to happen on that parsed target, before
// connectDialTarget is called.
//
// This is also why the check cannot be folded into the ECH and SNI dialers.
// Those are on the reverse-proxy path (proxyRoundTrip), which a CONNECT request
// never reaches: a tunnel dials with plain net.Dialer and no TLS at all.
// Routing the check through them would cover neither the tunnel nor anything
// else that dials independently.
//
// Scope: this validates the literal address in the request. It deliberately
// does not resolve hostnames, because
//   - resolving here adds a blocking network round trip to every request, and
//   - a name that resolves to a private address is still attackable via DNS
//     rebinding between this check and the dial.
//
// Neither is a claim that hostname-based SSRF is impossible. It is a claim that
// this layer handles the case it can see honestly, and that the residual risk is
// named rather than papered over. See the design notes in the PR.

// DestinationChecker decides whether a CONNECT target may be reached.
type DestinationChecker interface {
	Check(target connectTarget) error
}

// DestinationGuardConfig configures the guard. The zero value blocks loopback,
// private, link-local and unspecified addresses, which is what a local-only
// proxy wants by default.
type DestinationGuardConfig struct {
	// AllowLoopback permits 127.0.0.0/8 and ::1. Off by default.
	AllowLoopback bool
	// AllowPrivate permits RFC1918 and unique-local ranges. Off by default:
	// a proxy that can reach 10/8 can reach internal infrastructure.
	AllowPrivate bool
	// AllowHostnames permits destinations that are DNS names rather than
	// literal IPs. Defaults to true, because refusing every name would break
	// the ordinary case of CONNECT example.com:443.
	AllowHostnames *bool
	// ExtraBlockedCIDRs adds operator-specific ranges.
	ExtraBlockedCIDRs []string
	// AllowPorts, when non-empty, restricts destinations to this set.
	AllowPorts []int
}

func (c DestinationGuardConfig) allowHostnames() bool {
	if c.AllowHostnames == nil {
		return true
	}
	return *c.AllowHostnames
}

// DestinationGuard is the default DestinationChecker.
type DestinationGuard struct {
	allowLoopback bool
	allowPrivate  bool
	allowHosts    bool
	blocked       []netip.Prefix
	allowPorts    map[int]bool
}

// cloud metadata and other services reachable only from inside a network.
var alwaysBlockedCIDRs = []string{
	// AWS / GCP / Azure instance metadata
	"169.254.169.254/32",
	"fd00:ec2::254/128",
	// Alibaba / Tencent instance metadata
	"100.100.100.200/32",
}

// NewDestinationGuard builds a guard from cfg.
func NewDestinationGuard(cfg DestinationGuardConfig) *DestinationGuard {
	g := &DestinationGuard{
		allowLoopback: cfg.AllowLoopback,
		allowPrivate:  cfg.AllowPrivate,
		allowHosts:    cfg.allowHostnames(),
	}
	for _, c := range alwaysBlockedCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			g.blocked = append(g.blocked, p)
		}
	}
	for _, c := range cfg.ExtraBlockedCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			g.blocked = append(g.blocked, p)
		}
	}
	if len(cfg.AllowPorts) > 0 {
		g.allowPorts = make(map[int]bool, len(cfg.AllowPorts))
		for _, p := range cfg.AllowPorts {
			g.allowPorts[p] = true
		}
	}
	return g
}

// blocklistHosts are names that always mean "this machine" or "the metadata
// service", regardless of what a resolver would return. They are refused as
// names rather than resolved, which closes the most obvious bypass: the guard
// accepts hostnames without resolving them, so "localhost" would otherwise sail
// through the literal-address rules.
var blocklistHosts = []string{
	"localhost",
	"localhost.localdomain",
	"ip6-localhost",
	"ip6-loopback",
	"metadata",
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
}

// isBlockedHostName reports whether a DNS name is on the blocklist.
func isBlockedHostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, bad := range blocklistHosts {
		if h == bad {
			return true
		}
	}
	return false
}

// Check reports whether target may be dialed.
func (g *DestinationGuard) Check(target connectTarget) error {
	if g.allowPorts != nil && !g.allowPorts[target.port] {
		return &GuardError{
			Target:  target,
			Reason:  fmt.Sprintf("port %d is not in the allowed set", target.port),
			Allowed: true,
		}
	}

	// Blocked names are refused before the hostname/literal split, so they are
	// refused whether or not hostnames are otherwise permitted.
	if isBlockedHostName(target.host) {
		return &GuardError{
			Target: target,
			Reason: fmt.Sprintf("host %q always denotes a local or metadata address", target.host),
		}
	}

	// A DNS name is accepted here without resolution; see the type comment.
	addr, err := netip.ParseAddr(target.host)
	if err != nil {
		if g.allowHosts {
			return nil
		}
		return &GuardError{
			Target: target,
			Reason: "destination is a hostname and hostnames are not permitted",
		}
	}

	if err := g.checkAddr(addr, target); err != nil {
		return err
	}
	return nil
}

func (g *DestinationGuard) checkAddr(addr netip.Addr, target connectTarget) error {
	// No Is4In6/Unmap here on purpose. netip already reports ::ffff:127.0.0.1
	// as IsLoopback and ::ffff:10.0.0.1 as IsPrivate, so an explicit unmap was
	// redundant: a mutation removing it survived the suite, which is the
	// evidence the line did nothing. Removing untested defence-in-depth beats
	// keeping it and pretending it is load bearing.

	deny := func(reason string) error {
		return &GuardError{Target: target, Reason: reason}
	}

	// The explicit metadata prefixes stay in g.blocked. The IPv4 entry
	// (169.254.169.254) is also caught by the link-local rule below, but the
	// IPv6 one (fd00:ec2::254) is not: it sits inside the unique-local range,
	// so only the blocklist catches it. Keeping both documents intent.
	for _, p := range g.blocked {
		if p.Contains(addr) {
			return deny(fmt.Sprintf("%s is in the always-blocked list (%s)", addr, p))
		}
	}

	switch {
	case addr.IsLoopback():
		if !g.allowLoopback {
			return deny(fmt.Sprintf("%s is a loopback address and loopback is not allowed", addr))
		}
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return deny(fmt.Sprintf("%s is link-local", addr))
	case addr.IsInterfaceLocalMulticast():
		return deny(fmt.Sprintf("%s is interface-local multicast", addr))
	case addr.IsUnspecified():
		return deny(fmt.Sprintf("%s is the unspecified address", addr))
	case addr.IsPrivate() && !g.allowPrivate:
		// Covers RFC1918 and IPv6 unique-local.
		return deny(fmt.Sprintf("%s is a private address and private ranges are not allowed", addr))
	}

	// A few blocks outside the Is* helpers: carrier-grade NAT and the
	// benchmarking range are routable but never legitimate proxy targets.
	if p, _ := netip.ParsePrefix("100.64.0.0/10"); p.Contains(addr) {
		return deny(fmt.Sprintf("%s is carrier-grade NAT space", addr))
	}
	if p, _ := netip.ParsePrefix("192.0.0.0/24"); p.Contains(addr) {
		return deny(fmt.Sprintf("%s is IETF protocol assignment space", addr))
	}

	return nil
}

// GuardError explains why a target was refused.
type GuardError struct {
	Target  connectTarget
	Reason  string
	Allowed bool
}

func (e *GuardError) Error() string {
	return fmt.Sprintf("destination %s refused: %s", e.Target.String(), e.Reason)
}

// StatusCode is what the tunnel should answer with. 403 rather than 502: the
// request was understood and deliberately refused, not attempted and failed.
func (e *GuardError) StatusCode() int { return 403 }

// portListString renders AllowPorts for log output.
func portListString(ports []int) string {
	if len(ports) == 0 {
		return "any"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return joinComma(parts)
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

// hostPortString is a small helper used in tests and logs.
func hostPortString(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

var _ = hostPortString
