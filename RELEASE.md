## v3.2.0

### Changes & Features

- **New upstream transport — Mode 3: TLS ClientHello fragmentation** (`echproxy/ech/fragment.go`) — For origins not hosted on Cloudflare (no ECH available) that strictly verify TLS SNI (rejecting SNI-camouflage's fake SNI): a single-packet plaintext ClientHello gets RST/dropped by GFW DPI. Mode 3 resolves the real origin IP via DoH, then splits the first TLS handshake record (ClientHello) into many tiny TLS-record fragments written with `TCP_NODELAY`, breaking the plaintext-SNI DPI signature. After the handshake, the returned cert is validated with the same `validateUpstreamCert` (hostname vs the real domain, time validity, chain trust).
  - Upstream config `mode: "fragment"` (aliases `"bypass"` / `"gfw"`); `echproxy/config/config.go:normalizeMode` and `echproxy/config/validate.go:validModes` updated; auto-passthrough (unlisted hosts) now probes SNI/ECH/Fragment.
- **Warning-page code refactored** out of `proxy.go` into `echproxy/certwarn.go` (`serveCertWarningPage` / `buildCertWarningHTML` / `forceAccessURL`). Behavior unchanged: distinct 过期 / 不一致 / 不可信 pages + one-time force-access token.
- **Windows tray & system-proxy 32/64-bit correctness** — `win/tray_windows.go`: `NOTIFYICONDATAW` now uses the complete struct (incl. `winGUID`) for Windows 7~11 32/64-bit; `win/sysproxy_windows.go`: `INTERNET_PER_CONN_OPTIONW` `Value` union is pointer-width aware (386 = 4 bytes, amd64 = 8).
- Snapshot also updates README and config docs.

### Notes

- Carries over all v3.0.0–v3.1.1 work (logger startup-truncate, upstream cert validation incl. chain/trust, force-access one-time token + rate limit, goreleaser/release asset-collision fix).
- Verified: `go vet ./...` OK, `go build ./...` OK, `go test ./... -race` 11/11 PASS.

## v3.1.1

### Changes & Features

- **Fix: goreleaser.yml / release.yml release-asset collision on plain tags** — On `v3.1.0` the `goreleaser` workflow failed (`422 already_exists`) because both `release.yml` and `goreleaser.yml` triggered on the same `v*` tag push and both uploaded same-named desktop binaries (`ech-proxy-{linux,windows}-{amd64,386}`) + `checksums.txt` to the same GitHub release. `release.yml`'s upload was non-fatal (warn-and-keep), `goreleaser`'s was fatal → flaky by timing (v3.0.0 happened to not interleave, v3.1.0 did).
  - Fix: removed the desktop `build` matrix job from `release.yml` (it built `ech-proxy-{linux,windows}-{amd64,aarch64,386}`, all of which `goreleaser.yml` already builds as a superset — goreleaser also adds `darwin` + `ech-proxy.443.exe`). `release.yml` now owns **only the Android APKs + the release notes body**, restoring the documented design (see the `goreleaser.yml` header comment: "release.yml builds the Android APKs, GoReleaser builds the desktop binaries plus checksums. Their asset names do not collide."). No published artifact is lost; the arm64 naming becomes consistent (`arm64` across all platforms, previously `release.yml` used `aarch64` only for linux).
  - Net effect: plain `v*` tags now publish cleanly through both workflows with no asset-name overlap.

### Notes

- No Go source changes this release; behavior identical to v3.1.0. `go test ./... -race` remains 11/11 green (verified locally; Go CI run `39571344307` on `merge/ech-proxy-20261021` was green).

## v3.1.0

### Changes & Features

- **ECH & Direct paths now share the same upstream-cert validation + warning pages as the SNI path** — Previously only the SNI-camouflage path validated the upstream cert; ECH (`ech/client.go:newTransport`) and Direct (`netdial` via new `directDo`) cert failures surfaced as a bare `502 upstream: ...`. Now all three paths run `validateUpstreamCert` after the TLS handshake, so any cert failure renders the distinct HTML warning page:
  - ECH path: switched to `InsecureSkipVerify` + manual check (ECH disguise — outer SNI = shell, inner encrypted real SNI — is untouched); the Cloudflare-served cert for the real host passes hostname + chain.
  - Direct path: new `directDo` (`ech/sni.go`) uses `netdial.TransportWithIPModeAndCertCheck`, a dedicated transport that does `InsecureSkipVerify` + manual check (the shared `netdial.Transport` used by DoH/fetches is untouched).
  - `RoundTrip`'s fallback chain propagates cert errors from the direct fallback too.
- **Certificate chain / trust-root verification (third category)** — `validateUpstreamCert` now also runs `leaf.Verify({Roots: netdial.RootPool(), Intermediates: <peer chain>})` (after time + `VerifyHostname`). A self-signed / unknown-CA / missing-intermediate cert yields `ErrCertUntrusted` → a third, distinct warning page: 「上游证书链未被系统根信任」. Order: time → hostname → chain.
- **「强行访问」session-level memory + one-time token + rate-limiting (anti silent-bypass)** — Replaces the trivial `?__ech_proxy_force_cert__=1` bypass, which any page could embed to silently skip cert checks:
  - Each warning page issues a one-time random token (16 bytes, hex) bound to the upstream host, embedded only in ech-proxy's own warning-page HTML (cross-origin scripts can't read it). Force-access now requires `?__ech_proxy_force_cert__=<token>` matching (constant-time compare); the bare `=1` no longer bypasses.
  - Consuming a valid token marks that host **approved for the session** (in-memory `approved` set), so subsequent subresource requests to it load without re-warning (usable UX) — and without needing the token.
  - Rate-limit: max 6 tokens/min per host (sliding window); over-limit returns no button (shows a 「稍后刷新重试」 note). Approved-set capped at 256 hosts (session-level eviction).
  - Net effect: an attacker-embedded `?__ech_proxy_force_cert__=1` link on a non-approved host is ignored → the request still runs the cert check → renders a warning, never silently bypassing.

### Tests

- `ech/certcheck_test.go` rewritten with a test CA: covers expired / not-yet-valid / mismatch / untrusted-chain / trusted-chain-pass / wildcard / force-bypass / no-cert / time-first / classify-non-cert-error (chain pass/fail are hermetic via `SetRootPoolOverride`).
- `proxy_test.go:TestCertWarningPage`: distinct expired/mismatch/**chain** pages; one-time-token force flow (extract token → consume → approved → session memory loads subresources); anti-embed (a second host carrying `=1` is NOT bypassed → warning).
- Verified: `go vet ./...` OK, `go build ./...` OK, `go test ./... -race` (CI's exact command) 11/11 PASS.

### Notes

- The MITM client-facing cert override (`certstore`) is unchanged. Disguise (fake SNI + `InsecureSkipVerify`) preserved on all paths — verification is always against the real domain, never the disguised SNI.
- Force-access approval is session-level (process memory, not persisted); a host approved once stays approved until process restart. If you want stricter per-request re-approval, that's a follow-up.

## v3.0.0

### Changes & Features

- **Upstream certificate validation in the SNI-camouflage path (MITM cert-override gap)** — Because ech-proxy in MITM mode presents its own locally-trusted CA leaf to the client, the client can no longer see or judge the *real* upstream certificate. The proxy now validates the upstream cert itself on the SNI-front dial (`ech/sni.go:dialUTLS`), **right after the TLS handshake**, without touching the disguise:
  - Reads the peer certificate the server returns, then checks **(1) time validity** (`NotBefore`/`NotAfter`) and **(2) hostname coverage of the *real* requested domain** (`leaf.VerifyHostname(realDomain)`).
  - The fake SNI (`cloudflare-ech.com` by default) and `InsecureSkipVerify` are **kept intact** — verification is against the real domain, never against the disguised SNI (the sent fake domain and the returned cert's domain are necessarily different, so SNI-matching is semantically wrong here). Disguise is not sacrificed.
  - Two **distinctly-worded** HTML warning pages (HTTP 502 + `text/html`):
    - **Expired / not yet valid** → 「上游证书已过期或尚未生效」(amber).
    - **Hostname mismatch** (cert not valid for the requested domain — possible MITM or wrong server) → 「上游证书与请求域名不一致」(red).
  - **「强行访问」(Force Access) button** on each warning page. Clicking re-requests the same URL with `?__ech_proxy_force_cert__=1`; the proxy injects a `WithAllowBadCert` context flag (stripping the param before it reaches upstream), so the cert check is skipped and the upstream is served — an explicit user opt-in, like a browser's "proceed anyway".
  - `RoundTrip`'s auto fallback chain (ECH ↔ SNI ↔ direct) now **propagates cert errors immediately** instead of masking them behind a fallback attempt, so the warning page always surfaces.
- **Tests** — `ech/certcheck_test.go` covers expired / not-yet-valid / mismatch / valid / wildcard / force-bypass / no-cert / time-first-precedence / classify-non-cert-error. `proxy_test.go:TestCertWarningPage` asserts the distinct expired vs mismatch pages render with the force-access button and that `?__ech_proxy_force_cert__=1` bypasses the check end-to-end.

### Notes

- Only the SNI-camouflage path performs this manual check this release (it is the one that previously used `InsecureSkipVerify:true`). The ECH (`ech/client.go:newTransport`) and plain-Direct (`netdial`) paths already verify normally and were left unchanged. Chain/trust-root verification is not added (only hostname + time, per the two failure categories); self-signed-but-correct-hostname is a known gap to be addressed in a follow-up if needed.

## v2.2.0

### Changes & Features

- **32-bit x86 (386) desktop builds** — Every release now also ships `ech-proxy-windows-386.exe` and `ech-proxy-linux-386` for 32-bit computers (e.g. legacy 32-bit Windows PCs). Previously only amd64/arm64 binaries were published, and an amd64 PE executable cannot start on a 32-bit OS at all — the binary simply refused to open. On a 32-bit Windows machine, download **`ech-proxy-windows-386.exe`** (rename it to `ech-proxy.443.exe` if you want the port-443 local transparent proxy mode to auto-start, same rule as the Linux/macOS rename note).

---

## v1.2.1

### Changes & Features

- **Full CORS headers across all proxy and service responses** — All responses served by the proxy (including media streaming, index portal, service worker fallback, API routes, and error pages) now include comprehensive CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Expose-Headers`, `Access-Control-Max-Age`, `Access-Control-Allow-Private-Network`, `Cross-Origin-Resource-Policy: cross-origin`, and `Timing-Allow-Origin: *`).
- **Strict CORS override over upstream & original headers** — Upstream responses with restrictive CORS headers (such as `Access-Control-Allow-Origin: https://twitter.com`, `Cross-Origin-Resource-Policy: same-origin`, or restrictive `Timing-Allow-Origin`) are now stripped and overridden by the proxy's full CORS policy, allowing any website to embed, stream, or inspect media assets (e.g. `video-cf.twimg.com` and `pbs.twimg.com`).
- **Support for HTTP 200 & 206 Partial Content Range streaming** — Exposes `Content-Range`, `Content-Length`, and `Accept-Ranges` via `Access-Control-Expose-Headers`, allowing web video players and clients to seek and stream large media without CORS or Range header restrictions.
- **Unit & Integration tests for Twitter/twimg media proxying** — Verified media proxying to `twimg.l.moonchan.xyz` (`video-cf.twimg.com`) with arbitrary or no client referer (guaranteeing upstream referer override to `https://x.com` to prevent 403 Forbidden anti-hotlink blocks), 200 / 206 response status, true image loading, and full CORS headers.

---

## v1.1.4

### Fixes & Improvements

- **Zero-loss Raw URI transparent forwarding** — Requests to upstream servers now directly preserve the raw `RequestURI` from the client's HTTP request line. Fixes an issue where URL-encoded slashes (`%2F`) inside tag search paths (e.g. `/api/search/%20%24tag%3A%E4%BA%B2%E7%83%AD%2F%E7%94%9C%E8%9C%9C%24`) were prematurely unescaped by Go's URL re-encoder into literal slashes (`/`), causing upstream Express routing to fail with 404 `Cannot GET /api/search/...`.
- **Android cold-start crash fix (ANR watchdog elimination)** — `StartProxy` and bootstrap IP resolution are now executed asynchronously on a background worker thread instead of blocking the Android UI thread. Eliminates the startup timeout kill / ANR crash that caused the app to crash twice before opening on the third attempt.
- **Android verbose logging enabled by default** — Enabled `echproxy.Debug = true` in the Android native entrypoint, so all per-request routing logs and upstream response statuses are streamed in real-time to the fullscreen log UI.
- **Android `IP_MODE` environment variable support** — Pinned upstream egress family support (`IP_MODE`) is now wired into the Android build, bringing it to feature parity with the desktop flags.
- **Android background freeze & kill prevention (Foreground Service + WakeLock)** — Transitioned the Android proxy runtime into an Android Foreground Service (`ProxyService`) with persistent status notification, preventing Android 11+ Linux cgroup freezer (Cached Apps Freezer) and LMKD from suspending/killing the proxy process when switching to a browser. Acquired a partial WakeLock to sustain network operations during screen-off/standby, and added automatic battery optimization exemption prompt (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) to bypass OEM aggressive power killers.
- **Android UI & control enhancement** — Added top control bar with "Start/Stop Proxy" toggle, "Open Browser" direct launch button, and live status indicator ("Running on port 8443 (Foreground Service active)") above the real-time log terminal.
- **Android JNI string safety & panic protection** — Added panic recovery around all Go exported C entrypoints, and converted non-BMP UTF-8 characters to CESU-8 surrogate pairs in `GetLogs()` to prevent Dalvik/ART `NewStringUTF` aborts.
- **Upstream 302 redirect interception & Location rewriting** — Disabled Go's default internal redirect-following policy (`http.ErrUseLastResponse`) across ECH and Direct clients. 301/302 responses are now preserved and returned to the browser with fully rewritten `Location` domains and ports, fixing auth subdomain handoffs (e.g. Pixiv `/login.php` -> `pixiv-accounts.l.moonchan.xyz:8443/login`) and preventing broken relative calls like `/ajax/login`.
- **Declarative per-upstream `ip_mode` (`upstream.json`)** — Upstreams and wildcards can now specify `"ip_mode": "v4"`, `"v6"`, or `"auto"`. The ECH client isolates connection pools per IP mode to prevent connection sharing between families. Pixiv services are pinned to `v4` in `upstream.json`, resolving the IPv6 403 block on Android out of the box.
- **Declarative `cookie_priority` strategy (`upstream.json`)** — Added declarative cookie precedence configuration (`"seed"` vs `"browser"`) to upstream configs and wildcard rules. In `"seed"` mode (configured for Pixiv), server-side authenticated sessions (`PHPSESSID`, `device_token`, etc.) are protected from being clobbered by stale/guest client browser cookies, while client preference tokens are seamlessly merged.
- **Control plane cookie switcher & trigger** — The upstream portal page (`https://l.moonchan.xyz:8443/`) now provides interactive control buttons (`[ 🍪 使用公用 Cookie ]` / `[ 👤 使用本地 Cookie ]`) and live status pills for configured upstreams. Users can switch between public delegated login and private browser autonomy in one click. Also supports URL trigger (`?_cookie_mode=seed|browser`) with automatic clean-URL 302 redirects, and dedicated control API endpoints (`/control/cookie` and `/_ech/cookie`).
- **Fixed cookie auto-injection & browser cookie seeding** — `parseCookieString` now parses both standard semicolon format and Netscape HTTP Cookie File format (curl/cookies.txt). Configured upstream cookies are not only merged into all outgoing upstream requests, but also automatically seeded via `Set-Cookie` (`Domain=l.moonchan.xyz`) on initial browser responses, allowing client-side JavaScript (`document.cookie`) and sibling subdomains to stay permanently authenticated without manual login. Pixiv session cookies are now pre-configured in `upstream.json`.
- **Dual Android release flavors: Standard vs Lite (Zero-Permissions)** — Added Gradle flavor separation to produce two distinct Android APKs in every release:
  - **Standard (`ech-proxy-android-<version>.apk`)**: Background-safe edition with Foreground Service, WakeLock, and battery optimization whitelist prompt to prevent Android 11+ Cached Apps Freezer and LMK kills.
  - **Lite (`ech-proxy-android-lite-<version>.apk`)**: Permissionless edition with zero runtime permissions (no notification permission, no battery optimization dialog, no ongoing notification). Runs the proxy directly on a background thread.
- **Anti-hotlinking Referer override restoration & wildcard propagation** — Restored unconditional explicit `Referer` override in `buildUpstreamRequest` and synchronized `w.Referer` into wildcard headers maps, preventing client request referers from passing through and triggering upstream 403 Forbidden errors on anti-hotlinked CDNs (e.g. `video-cf.twimg.com` and `twimg-*.l.moonchan.xyz`).

---

## v1.1.3

### Fixes & Improvements

- **`-ip-mode` and `-local-ip` CLI flags** — The upstream egress IP family and DoH bootstrap IP were previously reachable only through the undocumented `IP_MODE` / `LOCALIP` environment variables. Both are now desktop flags (`win/main.go`); the env vars survive as their defaults, so a flag always wins when both are set. Android has no CLI and keeps reading the env vars.
- **Pixiv 403 root cause and fix** — An instance egressing over IPv6 received a static 403 "Access blocked" from `www.pixiv.net` while the same build over IPv4 received 200. `www.pixiv.net` publishes no AAAA record, but the ECH shell domain `cloudflare-ech.com` does, so in `auto` mode the TCP leg follows whatever family the OS resolves. Fix: `-ip-mode v4`.
- **Egress family is now observable** — In `auto` mode the first upstream dial logs `Upstream egress: IPv4 via <addr> (IP_MODE unset, family chosen by the OS)`, and the startup banner reports `IP Mode: auto | v4 (pinned)`. Previously the chosen family was invisible, which is what made the above take hours to diagnose.
- **`CheckDualStack` misnaming corrected** — Its doc said "detects local IPv4/IPv6 connectivity" but it only inspects `moonchan.xyz`'s A/AAAA records, so it returned the same result on every machine (always `IPv6=false` today). Doc comment fixed and the log line renamed from `IP stack check: IPv4= IPv6=` to `Upstream DNS records (moonchan.xyz): A= AAAA=` so it cannot be misread as a local-stack probe again.

---

## v1.1.2

### Fixes & Improvements

- **Cross-subdomain cookie sharing** — Server-side CookieJar now associates domain cookies (e.g. `.pixiv.net`) with parent domain keys, automatically sharing session cookies (`PHPSESSID`) between SSO/auth endpoints (`accounts.pixiv.net`) and portal/subdomain services (`www.pixiv.net`, `comic.pixiv.net`, etc.).
- **Browser-side `cookie_domain` rewriting** — Added declarative `cookie_domain` support to `UpstreamConfig` and `WildcardRule`. Upstream Set-Cookie headers can now be rewritten to a shared parent domain (such as `l.moonchan.xyz`), preserving login sessions across sibling subdomains in the browser.
- **Android dynamic versioning** — Android builds now dynamically track release git tags for `versionName` and `versionCode`, display version in UI startup logs, and produce versioned APK packages (`ech-proxy-android-<version>.apk`).
- **Local config file support** — `LoadConfig` and `FetchBytes` now support local file paths and `file://` URIs, enabling seamless local testing via `-config`.

---

## v1.1.1

### Changes & Features

- **Pixiv upstream configuration** — Added upstream rules for `pixiv.l.moonchan.xyz` (wildcard `*.pixiv.net`), `pximg.l.moonchan.xyz` (i.pximg.net image CDN), and `pximg-s.l.moonchan.xyz` (s.pximg.net static assets).
- **Custom upstream config CLI flag** — Added `-config` flag to desktop binary for specifying local or custom `upstream.json` URLs for testing and debugging.

---

## v1.1.0

### Fixes & Improvements

- **ECH TLS fingerprint** — ECH mode now uses `utls` with `HelloChrome_120` instead of Go's stdlib `crypto/tls`. Cloudflare JA3/JA4 detection now sees a real Chrome fingerprint, matching SNI mode behaviour.
- **SNI transport memory leak** — `sniTransports` cache is now bounded (max 256 entries, 30-min TTL) with a background reaper goroutine. Previously it grew unbounded.
- **Response re-compression** — After rewriting a gzip-encoded response body, the proxy now re-compresses with gzip if the client's `Accept-Encoding` supports it, restoring wire efficiency.
- **Error logging** — Body read errors and decompression failures now emit `log.Printf` instead of silently writing partial data.
- **Magic string constants** — `defaultPort`, `defaultListenAddr`, `dohHost`, `indexHost` are now named constants; no more scattered hardcoded strings.
- **Android JNI memory leak** — `GetLogs()` returns `*C.char` allocated via `C.CString`; a companion `FreeCString()` export is now provided so callers can free it. Adds `#include <stdlib.h>` preamble.
- **`--no-browser` flag** — Desktop binary no longer force-opens a browser in headless/server environments when this flag is set.
- **`ProxyHandler` refactored** — Split the 190-line closure into three named pipeline helpers: `buildUpstreamRequest`, `handleSWFallback`, `rewriteAndSendBody`.

---

### ech-proxy (Windows / Linux Desktop)

ECH (Encrypted Client Hello) domain fronting reverse proxy with multi-upstream routing:

- TLS mode listens on 127.0.0.1:8443 by default; automatically opens the browser to the entry index at https://l.moonchan.xyz:8443 upon startup
- Startup banner displays entry domains with listening ports, matching the exact browser URLs
- Entry examples: twimg.l.moonchan.xyz:8443 (Twitter CDN), asmr.l.moonchan.xyz:8443 (ASMR Online), iwara.l.moonchan.xyz:8443 (Iwara), dlsite.l.moonchan.xyz:8443 (DLsite), etc. Full list in startup banner and portal index
- Wildcard subdomain entries: iwara-* / dlsite-* / asmr-* map to corresponding upstream subdomains
- `--http` enables local HTTP proxy mode (no TLS), `-addr` customizes listening address, `-v` enables verbose per-request logging
