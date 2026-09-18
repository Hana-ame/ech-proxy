## v1.1.4

### Fixes & Improvements

- **Zero-loss Raw URI transparent forwarding** — Requests to upstream servers now directly preserve the raw `RequestURI` from the client's HTTP request line. Fixes an issue where URL-encoded slashes (`%2F`) inside tag search paths (e.g. `/api/search/%20%24tag%3A%E4%BA%B2%E7%83%AD%2F%E7%94%9C%E8%9C%9C%24`) were prematurely unescaped by Go's URL re-encoder into literal slashes (`/`), causing upstream Express routing to fail with 404 `Cannot GET /api/search/...`.
- **Android cold-start crash fix (ANR watchdog elimination)** — `StartProxy` and bootstrap IP resolution are now executed asynchronously on a background worker thread instead of blocking the Android UI thread. Eliminates the startup timeout kill / ANR crash that caused the app to crash twice before opening on the third attempt.
- **Android verbose logging enabled by default** — Enabled `echproxy.Debug = true` in the Android native entrypoint, so all per-request routing logs and upstream response statuses are streamed in real-time to the fullscreen log UI.
- **Android `IP_MODE` environment variable support** — Pinned upstream egress family support (`IP_MODE`) is now wired into the Android build, bringing it to feature parity with the desktop flags.
- **Upstream 302 redirect interception & Location rewriting** — Disabled Go's default internal redirect-following policy (`http.ErrUseLastResponse`) across ECH and Direct clients. 301/302 responses are now preserved and returned to the browser with fully rewritten `Location` domains and ports, fixing auth subdomain handoffs (e.g. Pixiv `/login.php` -> `pixiv-accounts.l.moonchan.xyz:8443/login`) and preventing broken relative calls like `/ajax/login`.
- **Declarative per-upstream `ip_mode` (`upstream.json`)** — Upstreams and wildcards can now specify `"ip_mode": "v4"`, `"v6"`, or `"auto"`. The ECH client isolates connection pools per IP mode to prevent connection sharing between families. Pixiv services are pinned to `v4` in `upstream.json`, resolving the IPv6 403 block on Android out of the box.

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
