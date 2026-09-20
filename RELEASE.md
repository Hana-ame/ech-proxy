## v1.1.6

### Fixes & Improvements

- **Restore native `http2.Transport` for ECH & SNI Fronting** — Restored `golang.org/x/net/http2.Transport` as the core transport for Cloudflare ECH and SNI camouflaged egress. In v1.1.5, substituting standard library `http.Transport` with custom `DialTLSContext` caused Go's transport layer to fail internal HTTP/2 type assertions on `uTLS` connections (`*tls.Conn`), silently downgrading to plaintext HTTP/1.1 on ALPN `h2` negotiated streams. This triggered immediate protocol resets from Cloudflare edge nodes across all proxied websites. Restoring `http2.Transport` guarantees strict HTTP/2 framing, reliable multiplexing, and full uTLS Chrome JA3/JA4 fingerprint compatibility across all platforms and Go versions.
- **Upstream Portal Synchronization** — Updated banner ordering test expectations to reflect the addition of `xx.l.moonchan.xyz` (Twitter pic gallery) in `upstream.json`.

---

## v1.1.5

### Fixes & Improvements

- **HTTP outbound connection reuse & keep-alive pooling** — Replaced rigid `http2.Transport` instances with Go standard library `http.Transport` instances configured with `MaxIdleConns: 200`, `MaxIdleConnsPerHost: 50`, and `IdleConnTimeout: netdial.OpTimeout`. Outbound connections to upstream servers are now properly retained and reused across consecutive requests.
- **Full HTTP/1.1 and HTTP/2 dual-protocol compatibility** — Eliminated errors where upstream servers negotiating HTTP/1.1 (e.g. `token.sensenova.cn`) failed with `upstream did not negotiate h2`. The proxy transparently negotiates either HTTP/2 or HTTP/1.1 based on ALPN while maintaining persistent connection pooling for both protocols.
- **UTLS connection state adapter (`UTLSConnWrapper`)** — Implemented `UTLSConnWrapper` and `WrapUTLSConn` to bridge `utls.UConn`'s `ConnectionState` to standard `crypto/tls.ConnectionState`. This allows `http.Transport` to detect negotiated ALPN protocols (`h2`, `http/1.1`) while preserving the Chrome JA3/JA4 TLS fingerprint and ECH encapsulation.
- **Response body draining & large body streaming** — Ensured all response bodies (including SW fallback and non-2xx responses) are drained before closing, preventing TCP sockets from being prematurely terminated by the transport pool. Fixed body streaming when response sizes exceed `maxRewriteSize` by streaming remaining bytes to EOF without truncation.
- **Blocked domain updates** — Added `micro.rubiconproject.com`, `stats.g.doubleclick.net`, and `service.iwara.shop` to `blocked_hosts` in `upstream.json`. Enhanced HTML body stripping and Service Worker request interception to handle bare domains, subdomains, and varied URL schemes.
- **Comprehensive upstream verification** — Successfully validated all 19 upstream services in `upstream.json` across `direct`, `sni`, and `ech` egress modes, verifying 100% connectivity and connection reuse.

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
