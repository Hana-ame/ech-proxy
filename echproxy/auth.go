package echproxy

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Proxy authentication.
//
// The CONNECT tunnel is an open forward proxy: without a check, any process
// that can reach the listener can use it to reach anything the host can reach.
// A reverse proxy restricted to a configured upstream list does not have that
// exposure, which is why this exists for the tunnel rather than for the whole
// server.
//
// Why a shared bearer token rather than per-client basic auth:
//
//   - Basic auth over plain HTTP sends base64, which is encoding, not
//     encryption. It protects against a casual or accidental user, not against
//     anyone who can read the wire. A bearer token has exactly the same
//     exposure, so basic auth buys no additional protection here.
//   - Basic auth implies an identity, which implies per-client credential
//     storage, rotation and revocation. Nothing in this proxy needs to know
//     *who* is calling; it only needs to know whether the caller is allowed.
//   - A single token is one secret to rotate instead of N.
//
// The comparison is constant-time so a caller cannot learn the token by timing
// successive requests.

// AuthConfig configures proxy authentication.
type AuthConfig struct {
	// Token is a bearer token. When set, requests must present
	// "Authorization: Bearer <token>".
	Token string
	// Username and Password enable HTTP basic auth. Ignored when Token is set.
	Username string
	Password string
	// AllowAnonymous keeps the proxy open when no credential is configured.
	// This exists so a fresh install works, and it is why the CLI should warn.
	AllowAnonymous bool
}

// ProxyAuth verifies credentials.
type ProxyAuth struct {
	token     string
	username  string
	password  string
	anonymous bool
}

// NewProxyAuth builds an authenticator from cfg.
func NewProxyAuth(cfg AuthConfig) *ProxyAuth {
	return &ProxyAuth{
		token:     cfg.Token,
		username:  cfg.Username,
		password:  cfg.Password,
		anonymous: cfg.AllowAnonymous,
	}
}

// Enabled reports whether any credential is configured.
func (a *ProxyAuth) Enabled() bool {
	return a != nil && (a.token != "" || a.username != "")
}

// Require reports whether requests must carry a credential.
func (a *ProxyAuth) Require() bool {
	return a.Enabled() && !a.anonymous
}

// Check verifies a request's Authorization header.
func (a *ProxyAuth) Check(r *http.Request) error {
	if !a.Require() {
		return nil
	}
	header := r.Header.Get("Authorization")
	if header == "" {
		return &AuthError{Reason: "missing Authorization header"}
	}

	if a.token != "" {
		const prefix = "Bearer "
		if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
			return &AuthError{Reason: `expected "Authorization: Bearer <token>"`}
		}
		got := strings.TrimSpace(header[len(prefix):])
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
			return &AuthError{Reason: "invalid token"}
		}
		return nil
	}

	if !strings.HasPrefix(strings.ToLower(header), "basic ") {
		return &AuthError{Reason: `expected "Authorization: Basic <credentials>"`}
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[6:]))
	if err != nil {
		return &AuthError{Reason: "malformed basic credentials"}
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return &AuthError{Reason: "malformed basic credentials"}
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(a.password)) == 1
	if !userOK || !passOK {
		return &AuthError{Reason: "invalid username or password"}
	}
	return nil
}

// AuthError explains an authentication failure.
type AuthError struct{ Reason string }

func (e *AuthError) Error() string { return "proxy authentication failed: " + e.Reason }

// StatusCode is 401 with a challenge, which is what a client needs in order to
// retry with credentials.
func (e *AuthError) StatusCode() int { return http.StatusUnauthorized }

// Challenge is the WWW-Authenticate value to return.
func (a *ProxyAuth) Challenge() string {
	if a.token != "" {
		return `Bearer realm="ech-proxy"`
	}
	return `Basic realm="ech-proxy"`
}

// RateLimiter throttles failed authentication attempts so a token cannot be
// brute-forced through the tunnel.
type RateLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter allows limit failures per window for any single peer.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		failures: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow reports whether key may try again, recording a failure when it may not.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.window)
	kept := r.failures[key][:0]
	for _, t := range r.failures[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.limit {
		r.failures[key] = kept
		return false
	}
	r.failures[key] = append(kept, time.Now())
	return true
}

// Reset clears the failure record for key, called after a success.
func (r *RateLimiter) Reset(key string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, key)
}

// TunnelAuth and TunnelRateLimiter expose the process-wide instances to the
// router. They are set once at startup by ConfigureTunnelAuth so the router
// does not need to thread them through every call site.
var (
	tunnelAuth      atomic.Pointer[ProxyAuth]
	tunnelRateLimit atomic.Pointer[RateLimiter]
)

func TunnelAuth() *ProxyAuth {
	if a := tunnelAuth.Load(); a != nil {
		return a
	}
	return NewProxyAuth(AuthConfig{AllowAnonymous: true})
}

func TunnelRateLimiter() *RateLimiter {
	return tunnelRateLimit.Load()
}

// ConfigureTunnelAuth installs the authenticator and rate limiter.
func ConfigureTunnelAuth(a *ProxyAuth, r *RateLimiter) {
	if a == nil {
		a = NewProxyAuth(AuthConfig{AllowAnonymous: true})
	}
	tunnelAuth.Store(a)
	tunnelRateLimit.Store(r)
}
