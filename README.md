# ech-proxy

ECH (Encrypted Client Hello) reverse proxy supporting multi-upstream routing and Android APK deployment.

## Features

- **Multi-Upstream Routing**: twimg, exhentai, iwara, dlsite, sukebei, ao3, etc.
- **Multiple Modes**: Cloudflare ECH domain fronting, SNI camouflage direct connect.
- **Android APK**: Compiled as a `c-shared` library integrated into an Android app.
- **Wildcard Subdomains**: e.g., `iwara-xxx.l.moonchan.xyz` → `xxx.iwara.tv`.
- **Cookie Injection**: Supports persistent and fixed cookies (e.g., exhentai session cookies).
- **Response Rewriting**: URL rewriting and Service Worker injection.

## Local reverse proxy mode (Pixiv)

`ech-proxy` normally listens on `127.0.0.1:8443` and uses the public cert on `l.moonchan.xyz`.
The **local proxy mode** (flag `-local`, and the default when the executable filename ends in
`.443.exe`) instead:

1. Listens on **`127.0.0.1:443`** (so you can point `pixiv.net`, `account.pixiv.net`, and
   subdomains at `127.0.0.1` in your hosts file).
2. Serves TLS using **self-generated certificates**: a local self-signed CA plus a per-domain
   leaf, issued on demand by the TLS `GetCertificate` callback. Nothing is ever downloaded —
   the CA and leaves are created by `ech-proxy` itself.
3. Caches everything next to the executable:
   - **The directory holding the executable** by default. The CA is the file you have to
     install into the trust store, so it sits beside the binary you downloaded and renamed,
     instead of being buried under `%AppData%`. This also keeps the proxy self-contained when
     it is run from a single folder or a USB stick.
   - If that directory is not writable (the binary may live in `C:\Windows\System32` or a
     read-only extraction folder) it falls back to the platform user config dir:
     Windows `%AppData%\ech-proxy\`, Linux `~/.config/ech-proxy/`,
     macOS `~/Library/Application Support/ech-proxy/`
   - Overridable with `-data-dir PATH` or the env var `ECH_PROXY_DATA_DIR`
   - Layout: `ca/ca.pem` (the cert to install into the system/browser trust store) and
     `ca/ca.key` (the CA private key — never leaves the machine), plus
     `certs/<registrable-domain>/fullchain.pem` and `privkey.pem` for each domain seen.
   - Dirs are `0700`, files `0600`.
4. Forwards each incoming host through the same **sni / ech** tunneling the remote deployment
   uses — with one exception: `l.moonchan.xyz` itself keeps its original direct path.
   `pixiv.net` is configured with **IPv4-only egress** (`ip_mode: v4`), because pixiv returns
   HTTP 403 on IPv6 clients.
5. Skips the browser auto-open.

### Why

Pixiv returns a static **403 "Access blocked"** for clients that egress over IPv6. A local proxy
on port 443 with forced IPv4 egress eliminates the problem: the browser connects to
`127.0.0.1:443`, `ech-proxy` terminates TLS with a locally trusted CA, and forwards the request
through the **ech** tunnel with `ip_mode: v4`, so the upstream leg always egresses over IPv4.

Local mode follows the same routing rule as the remote deployment:

| Incoming host | TLS termination | Upstream forwarding |
| :--- | :--- | :--- |
| `l.moonchan.xyz` (the portal) | existing public cert | unchanged original path (`direct`) |
| anything else (`pixiv.net`, `account.pixiv.net`, …) | self-generated CA + per-domain leaf | **sni / ech** tunnel, same as remote mode |

### Prerequisites

- **Administrator / root privileges** (binding port 443 requires it on all platforms).
- **Go is not required** — the binary ships in the release assets.

### Step 1 — Rename the binary

Rename the downloaded binary so that its filename **ends with `.443.exe`**:

```
ech-proxy-windows-amd64.exe  →  ech-proxy.443.exe
```

**The `.443.exe` convention — exact suffix, not substring.** The check is
`strings.HasSuffix(filename, ".443.exe")`, so the filename must *end* with `.443.exe`:

| Filename | 443 mode? |
| :--- | :--- |
| `ech-proxy.443.exe` | ✅ yes |
| `foo.443.exe` | ✅ yes |
| `ech-proxy.443.EXE` | ✅ yes (case-insensitive) |
| `ech-proxy.exe` | ❌ no — keeps port 8443 |
| `ech-proxy.443-windows-amd64.exe` | ❌ no — ends in `-amd64.exe` |
| `ech-proxy.443.beta.exe` | ❌ no — ends in `.beta.exe` |
| `ech-proxy.443` | ❌ no — no `.exe` |

A substring match would be dangerous: a renamed intermediate build such as
`ech-proxy.443.beta.exe` would silently bind a privileged port. Only a filename that genuinely
*ends* in `.443.exe` triggers the 443 build.

The release ships the Windows amd64 build already named **`ech-proxy.443.exe`**, so you can run
it straight from the download. Alternatively, any filename works if you pass `-local` and
`-addr 127.0.0.1:443` explicitly.

### Step 2 — Edit the hosts file

Add these entries to your system hosts file (`C:\Windows\System32\drivers\etc\hosts` on Windows):

```
127.0.0.1 pixiv.net
127.0.0.1 www.pixiv.net
127.0.0.1 account.pixiv.net
127.0.0.1 api.sec.pixiv.net
127.0.0.1 manga.pixiv.net
```

The leaf certificate is issued for the registrable domain `pixiv.net` with a `*.pixiv.net`
wildcard SAN, so **all subdomains are covered** by the single `pixiv.net` entry in your hosts
file. The explicit entries above are provided for clarity; you can safely drop the subdomain
lines and keep only:

```
127.0.0.1 pixiv.net
```

**Note:** `pximg.net` (Pixiv's image CDN) is **not** covered by the `pixiv.net` subdomain
entry — it needs its own hosts line and upstream config entry if you want it proxied.

### Step 3 — Run

Open an **elevated** terminal (Command Prompt / PowerShell as Administrator on Windows) and run:

```
ech-proxy.443.exe
```

That's it. The `.443.exe` filename suffix enables local mode and port 443 automatically.

Available flags:

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-local` | *from filename* | Enable local reverse proxy mode (auto-enabled by a `.443.exe` filename suffix) |
| `-http` | `false` | Run in HTTP mode (no TLS) — **mutually exclusive** with `-local` |
| `-data-dir` | `$ECH_PROXY_DATA_DIR` or the executable's own directory | Directory for the local CA and issued certificates |
| `-config` | *(default remote URL)* | Upstream config URL or local path |
| `-addr` | `127.0.0.1:443` (when `.443.exe`) or `127.0.0.1:8443` | Listen address |
| `-ip-mode` | `$IP_MODE` | Pin the upstream egress family to `v4` or `v6`; empty lets the OS decide |

Example with explicit flags (no rename needed):

```
ech-proxy-windows-amd64.exe -local -addr 127.0.0.1:443
```

### Step 4 — Install the CA certificate

After the first run, `ech-proxy` generates a local self-signed CA and stores it under your
data directory. You **must** install the CA certificate into your system's trust store for the
browser to accept the leaf certificates.

**CA certificate path:**

**The default data dir is the folder that holds the executable** (it falls back to the
platform user config dir only if that folder is not writable), so for a binary at
`C:\Users\lumin\Downloads\ech-proxy.443.exe` the CA is at
`C:\Users\lumin\Downloads\ca\ca.pem`:

| Executable location | Default CA path | Override |
| :--- | :--- | :--- |
| `%CD%\ech-proxy.443.exe` (Windows) | `%CD%\ca\ca.pem` | `-data-dir` or `$ECH_PROXY_DATA_DIR` |
| `/opt/ech-proxy/ech-proxy.443` (Linux) | `/opt/ech-proxy/ca/ca.pem` | `-data-dir` or `$ECH_PROXY_DATA_DIR` |
| `~/ech-proxy.443` (macOS) | `~/ca/ca.pem` | `-data-dir` or `$ECH_PROXY_DATA_DIR` |
| exe dir not writable (fallback) | `<user config dir>/ech-proxy/ca/ca.pem` | `-data-dir` or `$ECH_PROXY_DATA_DIR` |

The startup banner prints the resolved path on the `Data dir:` line — that is the folder whose
`ca\ca.pem` (Windows) or `ca/ca.pem` (POSIX) to install.

**Install the CA:**

- **Windows**: Right-click `ca.pem` → "Install Certificate" → Local Machine → "Place all
  certificates in the following store" → "Trusted Root Certification Authorities" → Finish.
- **Linux**: Copy `ca.pem` to `/usr/local/share/ca-certificates/ech-proxy-ca.crt` and run
  `sudo update-ca-certificates`.
- **macOS**: Open Keychain Access → drag `ca.pem` into "System" → open the cert → expand
  "Trust" → set "When using this certificate" to "Always Trust".

Browsers may need to be **restarted** after installing the CA (Chrome reads the store at
startup; Firefox may need `certs.p12` installation separately).

### Security rationale

**`ech-proxy` generates the CA and leaf certificates itself and never downloads any certificate
from a third party.** This is a deliberate design decision, not an oversight.

Downloading a certificate from a remote host would be a **MITM / supply-chain poisoning
vector**: if the cert server were compromised, an attacker could serve a malicious CA, and
every "encrypted" connection through the proxy would be terminated by that attacker's
certificate — the browser would trust it, and the user would never see a warning. That is a
worse failure mode than not having the feature at all.

Self-generation eliminates this vector entirely:

- The CA private key (`ca.key`) is **created on your machine** and **never transmitted**.
- It is stored at `0600` inside a `0700` directory, so only your user account (or root) can
  read it.
- Every leaf certificate is signed by your local CA and persisted at `0600`.

**You must still protect your data directory.** Anyone who steals `ca.key` can forge
certificates for any hostname and MITM your traffic. On Windows, `%AppData%\ech-proxy\` is
inside your user profile — anyone with access to your account can read it. On shared machines,
restrict access to the data directory (e.g., `-data-dir /root/ech-proxy` with `chmod 700`).

### Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Browser shows "certificate not trusted" / "your connection is not private" | CA not installed in the system trust store | Install `ca.pem` (Step 4) and restart the browser |
| Still getting 403 from Pixiv | `pximg.net` is not covered by the `pixiv.net` wildcard | Add `127.0.0.1 pximg.net` to hosts and add an upstream entry for `pximg.net` in the config |
| Port 443 already in use | Another process is bound to port 443 (e.g., HTTPS proxy, IIS) | Stop the other process, or use `-addr 127.0.0.1:8443` and point hosts at that port instead |
| IPv6 still leaking | the config entry for `pixiv.net` lacks `ip_mode` | The shipped config sets `"ip_mode": "v4"` on `pixiv.net`; verify with `-check-config`, or add `"mode": "ech", "ip_mode": "v4"` |
| `ech-proxy` exits with "address already in use" | Not running as admin/root (cannot bind port 443) | Run from an elevated terminal (Windows) or `sudo` (Linux/macOS) |
| Browser still shows cert error after installing CA | Browser cached the old chain | Clear the browser cache, or restart the browser process entirely |
| Requests hang / time out and logs say `ECH initialization failed` | Local mode still needs the ECH tunnel for non-`l.moonchan.xyz` hosts, and `moonchan.xyz` was unreachable at startup | It retries in the background (10s, 30s, 2m, 10m); wait, or set `-local-ip` to a reachable bootstrap IP |
| `ech-proxy` refuses to start, `cannot load CA from ... and will not overwrite it` | A previous data dir is corrupt | Inspect it by hand; do **not** delete it silently, since the browser already trusts that CA |

## Build

### Go Binaries (Windows / Linux)

```bash
go build -o ech-proxy ./win/
```

For the local reverse proxy variant, name the output so it ends in `.443.exe` — that is what
`win/main.go` matches, so it starts on `127.0.0.1:443` with local proxy mode and no flags:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ech-proxy.443.exe ./win/
```

The release builds both (`ech-proxy-windows-amd64.exe` and `ech-proxy.443.exe`) via
`.goreleaser.yaml`.

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
