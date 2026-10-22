## v3.5.17

### Fixes & Improvements

- **国内引导 DoH 高速解析与更新超时优化**:
  - **阿里云引导 DoH 集成**：在 `resolveViaBootstrapDoH` 中加入国内高可用 DoH 端点（`223.5.5.5` 与 `223.6.6.6`），解决国内网络环境下因直连 `1.1.1.1` 握手丢包或延迟高导致域名解析阻塞的问题，实现 5ms 级秒解；
  - **放宽更新检查超时并扩充镜像源**：将 `FetchBytes` 镜像单源超时调整为 25s，总超时由 25s 放宽至 45s（二进制文件下载放宽至 150s），并扩充 `https://github.moeyy.xyz/` 高速镜像源，彻底根除 25s context deadline exceeded 更新超时；
  - **完善 TLS 握手异常解包**：修复深层包装证书错误的分类短路逻辑，保障单连接探测准确高效。

## v3.5.16

### Fixes & Improvements

- **彻底根治并发连接风暴与 1GB 内存/套接字耗尽（`ERR_NO_BUFFER_SPACE`）**:
  - **单连接优先探测，根除 18 倍连接乘数**：未缓存路由时优先以单连接尝试 `fragment`（真实 SNI 分片），成功后直接缓存并复用，绝不再盲目向源站同时发起 ECH/SNI/Fragment 3 方案 × 2 IP × 3 指纹降级共 18 条并发连接；
  - **客户端取消流时不销毁 H2 连接池**：在用户划走、中止视频预加载或页面导航产生 `context.Canceled` 时，严格保留底层 `http2.Transport` 连接池与路由缓存，杜绝反复销毁与重建传输池造成的内核套接字及非分页内存泄漏；
  - **增强包装证书错误识别**：优化 `IsCertError` 支持深层解包分类，使假 SNI 证书不匹配立即短路跳出，防止冗余 TCP 重连。

## v3.5.15

### Fixes & Improvements

- **彻底修复国内直连 GitHub 检查更新卡死 5 分钟的问题**:
  - **TLS 分片免翻墙绕过 GFW**：在 `netdial.FetchBytes` 中将直连 GitHub（含 `github.com` 及重定向资产源 `objects.githubusercontent.com`）注入 `GitHubRoundTripper`，利用 DoH 解析真实 IP + TLS ClientHello 分片（`FragmentDo`）彻底绕过 GFW 对 GitHub SNI 的黑洞丢包与重置。
  - **Transport 握手超时兜底**：在底层 `TransportWithIPMode` 中显式设置 `TLSHandshakeTimeout: 10s`、`ResponseHeaderTimeout: 30s`，杜绝未设握手超时导致 GFW 丢包时 Go 原生标准库死等 5 分钟（`OpTimeout`）的严重缺陷。
  - **多源智能竞速与独立超时**：并发竞速直连分片与 4 大国内高速镜像源（`gh-proxy.com`、`ghfast.top`、`ghproxy.net`、`ghproxy.cn`），单源超时 15 秒（二进制下载 90 秒），首个成功结果立即返回并取消其他请求，秒级完成版本检测与更新包下载。

## v3.5.6

### Fixes & Improvements

- **彻底修复 `serveMITMConnect` 崩溃（`close of closed channel`）**:
  - 修复 `singleConnListener` 与 `closeNotifyConn` 之间因独立 `sync.Once` 重复关闭 `done` channel 导致的 panic，统一收拢至 listener 的单例关闭逻辑。
- **TLS ClientHello 采用 TCP 记录分节（TCP Segmentation，完美支持 nyaa.si / DDoS-Guard）**:
  - `fragment` 模式由原先拆分出 40+ 个微小 TLS Record 改为基于 TCP 层分节（保持合法单一 ClientHello 记录，配合 `TCP_NODELAY` 拆为多段 TCP 报文发出）。
  - 既能彻底打破 GFW DPI 的单包明文 SNI 匹配，又能完美兼容 DDoS-Guard / WAF，不再回退到泛域名证书导致握手异常。
- **自动检查更新全面支持 302 重定向与 GitHub 镜像加速兜底**:
  - 修复 `FetchBytes` 因 `ErrUseLastResponse` 导致 GitHub Releases `latest/download/checksums.txt`（302 跳转）检查更新直接报错失败的问题。
  - 为 GitHub Releases 与文件下载增加了国内镜像（`gh-proxy.com` / `ghproxy.net`）自动故障转移兜底。

## v3.5.5

### Changes & Features

- **SNI 伪装默认域名轮换（高信誉主流服务白名单，绝不留空）**:
  - 移除了假 SNI 留空的逻辑，配置默认伪装 SNI 轮询列表（`apple.com`、`icloud.com`、`msa.apple.com`、`microsoft.com`、`azure.microsoft.com` 与 `*.windowsupdate.com` 合法子域名）。
  - 在未显式指定自定义 SNI 时，按 Round-Robin 线程安全轮换上述不受干扰的大型主流服务域名，避免单域名流量特征与空 SNI 导致的握手异常。

## v3.5.1

### Changes & Features

- **全面移除广告拦截与广告插入 (Zero Ad Tampering)**:
  - 彻底停用并移除 HTML 广告注入（`ads.js`）与拦截逻辑，代理对所有网页 HTML 内容零修改、零注入。
  - 所有网站流量均通过原生 32KB 分块实时流式传输（Direct Streaming），零内存缓存等待。
- **PAC 规则统一使用单一信源 (pac.txt Only)**:
  - PAC 系统代理规则统一且仅使用 `https://4545810.xyz/pac.txt`，不再维护或依赖其他清单。

## v3.5.0

### Changes & Features

- **全链路直接流式传输 (Full-Pipeline Direct Streaming)**:
  - 移除了由于 AdBlock 需求而导致的响应体全量读入内存缓存机制 (`io.ReadAll`)。
  - 所有无需改写的请求（普通站点如 Pixiv 的 HTML、API JSON、JavaScript、CSS、图片、音视频等），一律直接流式分块实时写出给客户端，首包即达（TTFB 趋近直连），彻底消除内存等待延迟。
- **官方讨论区链接更新 (Feedback URL Update)**:
  - 托盘右键菜单中的反馈链接与文档更新为 `https://chatto.4545810.xyz`。

## v3.4.3

### Fixes & Improvements

- **彻底移除 EasyList 与代理层 204 请求中断 (Complete Removal of EasyList AdBlock)**:
  - 彻底移除 EasyList 清单拉取、规则解析与代理层网络拦截逻辑。
  - 删除代理网关处对目标 URL 的 `204 No Content` 阻断，彻底消除因规则通配导致的 `pixiv.net`、`e-hentai.org` 等正常站点根路径与页面资源被误拦截为空响应的问题。
  - 代理层回归纯净反向代理与隧道转发职责，所有流量 100% 直连上游正常加载。

## v3.4.2

### Fixes & Improvements

- **EasyList 过滤引擎纯净化 (Network-Only Domain+Path Filter)**:
  - 彻底移除 EasyList 对网页 HTML 的破坏性篡改：彻底删除 HTML URL 剥离 (`StripMatchedURLs`)、元素隐藏样式 (`##` Cosmetic `<style id="ech-proxy-easylist-style">` 注入)、`$csp` 响应头篡改与 `$removeparam` 参数过滤。
  - 严格遵循设计原则：**EasyList 仅在网络请求层对 `domain` 与 `domain + path` 进行匹配与 204 拦截**，绝不修改、隐藏或删除网页本身的 DOM 元素及静态资源，确保页面完整正常渲染。

## v3.4.1

### Fixes & Improvements

- **CI/CD 流水线与平台设计边界对齐 (CI Calibration)**:
  - 依照架构设计意图（ECH 核心运行模式专门针对 Windows 系统设计，非 Windows 平台无需常驻代理服务），移除 Linux CI 容器中启动后台代理服务与探测的冗余测试步骤，收敛为严格的 CLI 工具链断言（`version`、`check` 校验上游 JSON、`pac` 生成与 `help` 校验）及全架构交叉编译。
  - 消除 Linux 容器中因冷启动阶段远端 `ads.js` 尚未完成异步拉取而导致的 smoke test 偶发失败，确保发布流水线清洁稳定。

## v3.4.0

### Changes & Features

- **AdScript 注入引擎重构 (Remote-Only Dynamic Injection)**:
  - 彻底移除内置默认脚本 (`BuiltInAdScript`) 与 `on.txt` 远端轮询及状态开关，全面改为远端 `ads.js` 原样直插模式。
  - 仅在拉取到远端有效脚本（或读取本地磁盘缓存 `<dataDir>/ads.js`）时插入代码；初次无脚本或未拉取到时不注入任何内容。
  - 注入锚点严格限定在 HTML 的 `</body>` 标签前（页面无 `</body>` 时追加末尾），确保符合页面 DOM 渲染时序，不再插入 `</head>` 标签前。
- **文档与托盘交互指南 (Tray UI & Quickstart)**:
  - `README.md` 增加 Windows 任务栏系统托盘（System Tray）各项右键菜单功能对照表。
  - 增加新用户初次使用流程指南（6 步新手安装、导入证书与启动配置）。
  - 文档与 CLI 选项严格脱敏，不外露任何内部广告相关参数。
- **预发布加固与跨平台校验 (Hardening & CI)**:
  - 统一全局 DoH 域名单一信源。
  - 修复 Windows `copylocks` 与 HTTP/1.1 MITM 阻塞问题，完善 Windows/Linux/macOS 多架构交叉编译与 smoke test 验证。

## v3.3.1

### Pre-Release Fixes (hardening pass)

- **Data races removed** — `config.ReplaceFrom` writing `UpstreamOrder` while the portal read it unlocked (8443 silent-compat loader) is fixed by a locked `OrderSnapshot()`; `BuildEntryRewriterForHost` no longer rewrites `Compiled`/`CompiledReplace` into the shared `BodyReplace` backing array on every request (compile-once, only when nil). `go test -race` is clean under concurrent requests.
- **CONNECT/MITM TLS state & HEAD/204 body handling** — The `closeNotifyConn` wrapper hides `*tls.Conn` from `http.Server`, leaving `req.TLS == nil`; this stripped `; Secure` from HTTPS `Set-Cookie` headers (breaking `SameSite=None; Secure` sessions). `req.TLS` is now restored from `tlsConn.ConnectionState()` in the handler. `HEAD`, `204` and `304` responses are no longer rewritten or re-injected, and the upstream `Content-Length` is preserved.
- **Windows `go vet` & clipboard** — `copyToClipboardOnPlatform` no longer converts `uintptr` to `unsafe.Pointer` (uses `kernel32!RtlMoveMemory`) and frees `hMem` with `GlobalFree` on failure. CI now runs `go vet` for `windows/amd64` and `windows/386` (previously Linux only) and verifies all 12 Flutter FFI exports (`ECHInit`, `GetProxyPort`, `IsEchReady` were previously unchecked).
- **Docs & observability** — CLI help and `README.md` now describe the IPv4 (`-4`) default (previously a dual-stack default).

## v3.3.0

### Changes & Features

- **Unified PAC Proxy Architecture (`127.0.0.1:8443`) & Strict `.443.exe` Isolation** —
  - By default (`ech-proxy.exe`), the proxy runs strictly as a unified HTTP/HTTPS PAC proxy on `127.0.0.1:8443`, automatically configuring the Windows system PAC (`http://127.0.0.1:8443/proxy.pac?t=<ts>`) without opening `l.moonchan.xyz:8443` on startup (`l.moonchan.xyz` portal remains independently accessible via `ech-proxy.8443.exe portal` or the tray menu).
  - When the executable filename does **not** end with `.443.exe` (and `-local` is not explicitly passed), port 443 is never bound and the local 443 transparent proxy code path is strictly not executed.
- **Seamless HTTP & HTTPS Proxy Handling + 3 GFW-Bypass Transports** —
  - **HTTPS (`CONNECT host:443`)**: Local CA (`CertStore`) dynamically signs leaf certificates with full chain, decrypts HTTP/1.1 & HTTP/2, and routes upstream via **(1) DoH + SNI Camouflage**, **(2) DoH + Cloudflare ECH**, or **(3) DoH + TLS ClientHello Fragment** (`DialFragmentedTLS`), with strict upstream certificate verification (`truedomain.com` hostname, expiration, and trust chain) and one-time token force-access (`?__ech_proxy_force_cert__=<token>`).
  - **Plain HTTP (`http://`) & WebSocket**: Automatically strips `Proxy-*` hop-by-hop headers, upgrades standard port-80 requests to HTTPS via the 3 GFW-bypass modes when supported, and seamlessly falls back to DoH-resolved plain HTTP (`PlainHTTPDo`, preserving request bodies) for HTTP-only origins or custom HTTP ports. Also supports plaintext HTTP inside `CONNECT` tunnels via first-byte sniffing.
- **IPv4 Default (`-4`) with Dual-Stack (`-dual`) / IPv6 (`-6`) & Built-in DoH Failover** —
  - Defaults to IPv4-only (`-4` / `v4`), with `-dual` (dual-stack IPv4 + IPv6) and `-6` (IPv6 only) flags and runtime tray switching.
  - Built-in DoH endpoints: primary `https://4545810.xyz/doh` and secondary `https://1.1.1.1/dns-query` with automatic failover.
- **Decoupled Remote PAC Whitelist (`pac.txt`)** —
  - Default PAC whitelist fetched from `https://4545810.xyz/pac.txt` (line-delimited domains, fallback to `[]` on failure; `-all` routes all domains through the proxy).
- **One-Click CA Uninstall & GitHub Releases Auto-Updater (`win/updater.go`)** —
  - Added `ech-proxy ca uninstall` (`-ca-uninstall`) and tray menu item to remove the local CA from Windows User Root store (`certutil -user -delstore Root`) and macOS keychain.
  - Added automatic update checking and background downloading from `https://github.com/Hana-ame/ech-proxy/releases` with SHA-256 verification against `checksums.txt`, staging `.update.new` and applying atomic self-replacement on exit/restart (`ech-proxy update`, tray menu, or `--no-auto-update`).
- **Fix: `SysProxyManager.AllMode()` getter & Gin proxied-host route isolation** —
  - Added `SysProxyManager.AllMode()` in `win/sysproxy.go` for cross-platform compilation with `win/tray.go`.
  - Added top-level Gin middleware in `echproxy/portal.go` so non-portal/non-loopback proxied requests across all HTTP methods (`POST /`, `HEAD /`, etc.) route directly to `proxyHandler`.

---

## v3.2.0

### Changes & Features

- **System Tray, Windows Auto-PAC, Local Rotating Logger & Multi-Arch Release Matrix** —
  - Pure-Go Win32 system tray (`win/tray_windows.go`) with console show/hide toggle, PAC / Global / Direct mode switching, CA install, and log folder quick-open.
  - Rotating file logger (`echproxy/logger`) with panic recovery and `crash-latest.log` dump.
  - Expanded cross-compile matrix covering `386`, `amd64`, and `arm64` for Windows, Linux, macOS, and Android APKs.

---

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
