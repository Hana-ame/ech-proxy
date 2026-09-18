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
