# ech-proxy

ECH (Encrypted Client Hello) reverse proxy supporting multi-upstream routing and Android APK deployment.

## Features

- **Multi-Upstream Routing**: twimg, exhentai, iwara, dlsite, sukebei, ao3, etc.
- **Multiple Modes**: Cloudflare ECH domain fronting, SNI camouflage direct connect.
- **Android APK**: Compiled as a `c-shared` library integrated into an Android app.
- **Wildcard Subdomains**: e.g., `iwara-xxx.l.moonchan.xyz` → `xxx.iwara.tv`.
- **Cookie Injection**: Supports persistent and fixed cookies (e.g., exhentai session cookies).
- **Response Rewriting**: URL rewriting and Service Worker injection.

## Build

### Go Binaries (Windows / Linux)

```bash
go build -o ech-proxy ./win/
```

### Android APK

```bash
# 1. Compile Go shared library (requires Android NDK r27)
cd android
GOOS=android GOARCH=arm64 CC=aarch64-linux-android21-clang \
  go build -buildmode=c-shared -o app/src/main/jniLibs/arm64-v8a/libechproxy.so .

# 2. Package APK
./gradlew assembleRelease
```

## Configuration

Upstream configurations reside in `certs/l.moonchan.xyz/upstream.json` and are dynamically fetched at runtime from the GitHub `main` branch (forwarded via `proxy.moonchan.xyz` to `raw.githubusercontent.com`).
Changes pushed to the `main` branch immediately affect running proxies without pinning to specific commits/tags.

### Runtime Options: CLI Flags (Desktop) and Environment Variables (Desktop / Android)

Both set the same two fields of `echproxy.ServerOptions`. The flags live in `win/main.go`; the env vars are the flags' defaults, so a flag always wins when both are given. Android has no CLI, so `android/main.go` reads the env vars only.

| Meaning | CLI flag (desktop) | Env var | Default |
| :--- | :--- | :--- | :--- |
| Upstream egress IP family | `-ip-mode v4` | `IP_MODE=v4` | *(unset)* = `auto` |
| DoH bootstrap IP | `-local-ip 1.1.1.1` | `LOCALIP=1.1.1.1` | *(unset)* |

**`-ip-mode` / `IP_MODE`.** `v4` or `v6` forces the IP family of the **upstream egress** dial; unset = `auto`, where the shell hostname (`cloudflare-ech.com`) is handed to the OS resolver and the OS picks the family.

**Being unset is a live trap.** In `auto` the egress family is silently OS-decided. Observed 2026-09-18: an instance egressing over IPv6 received a static **403 "Access blocked"** from `www.pixiv.net`, while the same build over IPv4 received **200** — `www.pixiv.net` publishes no AAAA record, but the ECH shell domain `cloudflare-ech.com` does (`2606:4700::6812:a76` / `2606:4700::6812:b76`), so the TCP leg follows whatever family the OS resolves. Easy to miss because other upstreams on the same IPv6 egress (`archiveofourown.org`, `f95zone.to`, `i.pximg.net`) all returned 200. Fix: `-ip-mode v4`.

To confirm which family an instance is actually using: with no `-ip-mode`, the first upstream dial logs `Upstream egress: IPv4 via <addr> (IP_MODE unset, family chosen by the OS)`; and `https://<entry>.l.moonchan.xyz:8443/cdn-cgi/trace` reports the egress address in `ip=` and the attributed country in `loc=`.

### Core Mechanisms: `rewrites` vs `body_replace` vs `sw_inject`

To prevent configuration ambiguity, response rewriting and Service Worker responsibilities are partitioned as follows:

| Directive | Format | Scope | Core Mechanism & Use Cases |
| :--- | :--- | :--- | :--- |
| **`rewrites`** | `{"target.com": "local.proxy"}` | **Body + sw.js (Dual Effect)** | **Domain-Level Mapping**.<br>1. **Static Body Replacement**: Replaces `target.com` with the local proxy entry (with active port attached) across HTML, JS, JSON, XML, and response headers (`Location`/`Refresh`).<br>2. **Service Worker Dynamic Interception**: When `sw_inject` is enabled, all `rewrites` pairs are automatically injected into `__swMap` inside `sw.js`, intercepting runtime requests assembled dynamically by client scripts in the browser network layer (handling dynamic URLs that static replacements cannot reach, such as DLsite image CDNs). |
| **`body_replace`** | `[["old", "new"]]`<br>`[{"replace": ["old", "new"]}]` | **Body Only (Single Direction)** | **General Text & Regex Replacement**.<br>Dedicated to precise text replacements or regex matches within response bodies (e.g., specific script URLs, version tags, or inline code adjustments).<br>**Note**: Rules in `body_replace` **never** enter `sw.js`, preventing regex or non-domain text from polluting Service Worker routing logic. |
| **`sw_inject`** | `true` / `false` | **HTML Registration + sw.js** | **Service Worker Injection Toggle**.<br>For sites without a native Service Worker (such as DLsite). When enabled, the proxy injects `/sw.js` registration code into served HTML, and dynamically serves a script with `rewrites` mappings and `blocked_hosts` blocklists on `/sw.js`.<br>(**Warning**: Never enable for sites with built-in Service Workers like Iwara/Workbox, to avoid conflicts or overwrites). |

### Example

```json
{
    "upstreams": {
        "dlsite.l.moonchan.xyz": {
            "host": "www.dlsite.com",
            "referer": "https://www.dlsite.com/",
            "sw_inject": true,
            "rewrites": {
                "www.dlsite.com": "dlsite.l.moonchan.xyz",
                "img.dlsite.jp": "dlsite-img.l.moonchan.xyz"
            },
            "body_replace": [
                ["https://old-cdn.com/lib.js", "https://new-cdn.com/lib.js"],
                {"replace": ["v[0-9]+\\.[0-9]+", "v2.0"]}
            ]
        }
    }
}
```

**Public SSL Certificates**: Both `certs/l.moonchan.xyz/fullchain.cer` and `privkey.pem` are tracked in the repository (and mirrored in the `wintools` repository, both public). Desktop editions fetch certs and private keys directly from public locations. Because Let's Encrypt certificates are natively trusted by browsers, anyone holding this private key can terminate browser-trusted TLS for `*.l.moonchan.xyz` — this is deliberate (see commit `d23da9b`), not a leak.

The only secret is the Android APK signing keystore (`release.keystore`), managed via GitHub Secrets.

## GitHub Actions

- `go.yml`: Go unit tests
- `ech-proxy.yml`: Go binary builds
- `ech-proxy-android.yml`: Android APK builds
- `release.yml`: Release publishing
