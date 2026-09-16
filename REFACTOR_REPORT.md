# ECH-Proxy 架构重构、通用规则引擎与 CI/CD 治理工程报告

**版本标识**: `v1.0.3`  
**报告时间**: 2026-09-16  
**涉及代码库**: `Hana-ame/ech-proxy`  
**核心交付**: Linux CLI (amd64 / aarch64), Windows CLI (amd64), Android APK (`app-release.apk`)

---

## 目录
1. [项目背景与问题根因](#一-项目背景与问题根因)
2. [代码架构重构与模块解耦](#二-代码架构重构与模块解耦)
3. [通用声明式 Headers 与 Cookie 闭环引擎](#三-通用声明式-headers-与-cookie-闭环引擎)
4. [通配符模型辨析与配置精简](#四-通配符模型辨析与配置精简)
5. [向后兼容性保障与生产实测验证](#五-向后兼容性保障与生产实测验证)
6. [CI/CD 工作流缺陷修复与 v1.0.3 交付](#六-cicd-工作流缺陷修复与-v103-交付)
7. [后续维护与配置规范指南](#七-后续维护与配置规范指南)

---

## 一、 项目背景与问题根因

### 1. Iwara 登录 400 Bad Request 根因定位
用户在使用反代访问 Iwara 进行登录鉴权时遭遇 `400 Bad Request`，排查确认为反向代理的请求头特征泄露所致：
- **Origin 泄露**：前端单页面应用（SPA）通过 Fetch 向 API 发送 POST 登录请求时，浏览器自带的反代域名（如 `Origin: https://iwara.l.moonchan.xyz`）被代理原封不动上送到后端。Iwara 后端进行了跨源防护校验，检测到 Origin 非 `https://www.iwara.tv` 即刻拒收抛出 400；
- **X-Site 缺失**：Iwara 前端交互要求携带 `X-Site: www.iwara.tv`，反代未做回写和规范化；
- **X-Forwarded-For 污染**：传统反代默认注入客户端真实 IP，极易在 Cloudflare 层触发 WAF 机器人指纹判定。

### 2. 代码混杂（Mazar 混ざる）与层次不分
重构前的 `echproxy/proxy.go` 超过 1500 行，将以下异构业务逻辑揉杂在单个文件与请求循环中：
- 证书/密钥的 DoH 探测与加载；
- SNI 伪装连接池与 uTLS Chrome 握手；
- 内存 CookieJar 的存取、过期判定与域名重写；
- 正文 Brotli/Gzip 解压与文本绝对路径替换；
- 通配符字符串截断与子域路由；
- ServiceWorker 脚本拦截。

### 3. CI 自动化无脑构建与 Release 污染
- **触发源失控**：`.github/workflows/ech-proxy-android.yml` 和 `ech-proxy.yml` 的触发路径配置了 `"certs/**"`。作为远端动态配置的 `upstream.json` 每次哪怕修改一个字母，都会触发下载 1GB NDK 全量编译打包 APK；
- **版本硬编码覆盖**：构建脚本中硬编码执行 `gh release upload v1.0.0 app-release.apk --clobber`，导致任何 commit 都会无脑将正在开发中的 APK 强制推翻覆盖到历史里程碑 `v1.0.0` 上。

---

## 二、 代码架构重构与模块解耦

将原本臃肿的 `echproxy/proxy.go` 拆分为职责严格单一的 9 个核心组件，杜绝交叉依赖：

| 模块文件 | 核心职责 | 设计考量 |
| :--- | :--- | :--- |
| [`config.go`](echproxy/config.go) | 配置加载、标准化解析、多态反序列化 | 统筹 `string \| Object` 请求头规则与向后兼容映射 |
| [`cookie.go`](echproxy/cookie.go) | 客户端 Cookie 捕获、内存 Jar 管理、Set-Cookie 域名重写 | 解决前端 JS `document.cookie` 丢失与跨域 Cookie 注入 |
| [`cors.go`](echproxy/cors.go) | 跨域中间件 | 动态回显客户端 Origin，支持携带凭据与放行自定义 Header |
| [`wildcard.go`](echproxy/wildcard.go) | 通配路由解析、子域动态计算、规则继承 | 解决单层泛域名证书限制下的子域路由与 Headers 自动继承 |
| [`sni.go`](echproxy/sni.go) | SNI 伪装直连、DoH 解析、uTLS Chrome 指纹伪装 | 按目标 IP 复用 `http2.Transport` 连接池，降低握手开销 |
| [`rewriter.go`](echproxy/rewriter.go) | 响应体与 Header 相对/绝对链接闭环重写 | 保证页面跳转和静态资源全程留在反代隧道中 |
| [`compress.go`](echproxy/compress.go) | Brotli 与 Gzip 流式智能解压 | 为正文 URL 替换提供透明的解码层 |
| [`sw.go`](echproxy/sw.go) | PWA ServiceWorker 注册脚本拦截 | 避免 ServiceWorker 绕过代理直接请求源站 |
| [`proxy.go`](echproxy/proxy.go) | 核心反代管线串联 | 仅保留最精简的 HTTP 处理流，代码量缩减 80% |

---

## 三、 通用声明式 Headers 与 Cookie 闭环引擎

为了做到**“未来新增站点或规则修复只更新远程 JSON，不重新编译和分发二进制”**，实现了高度通用的规则引擎：

### 1. 通用 Headers 多态操作语法
在 `upstream.json` 中，每个 upstream 节点的 `headers`（发往源站）与 `response_headers`（返回客户端）的 key 支持 `string | Object`：

```json
"headers": {
    "Origin": "https://www.iwara.tv",
    "X-Site": "www.iwara.tv",
    "X-Custom-Token": "fixed-token-value",
    "X-Forwarded-For": { "delete": true },
    "Referer": { "replace": ["proxy.moonchan.xyz", "www.iwara.tv"] }
}
```

- **字符赋值**：直接设置或覆盖上游请求头；
- **`{"delete": true}`**：彻底剔除对应请求头；
- **`{"replace": ["before", "after"]}`**：支持正则或字面量文本替换；
- **智能 Origin 注入机制**：仅在客户端请求本身携带了 Origin，或者请求方法为非幂等动作（POST / PUT / PATCH / DELETE）时覆盖 Origin，避免普通浏览器 GET 页面导航被污染。
- **剥离代理特征**：默认不再向后端注入 `X-Forwarded-For`、`X-Forwarded-Proto`，防止被目标站 WAF 识别。

### 2. Cookie 全生命周期闭环
针对现代 SPA 站点的认证流程，构建了三层合流的 Cookie 体系：
1. **客户端 JS Cookie 捕获（`saveClientCookies`）**：浏览器客户端通过 `document.cookie` 写入的前端 Token，在到达代理的第一时间被截获并持久化到该上游域名的内存 `cookieJar` 中；
2. **多源合并优先级（`applyCookies`）**：
   - 优先级 1（最高）：服务端历史通过 `Set-Cookie` 下发并在 Jar 中维持有效期的 Cookie；
   - 优先级 2：当前请求客户端所携带的最新 Cookie；
   - 优先级 3：通过本地固定配置或 `cookie_file` 读取的持久凭据；
3. **域名与安全标志重写（`rewriteSetCookieDomains`）**：
   - 将服务端返回的 `Domain=.iwara.tv` 自动重写为代理入口域名（如 `Domain=iwara.l.moonchan.xyz`）；
   - 在 `--http` 本地代理模式下自动剔除 `Secure` 标记，确保浏览器能正确存储 Cookie。

---

## 四、 通配符模型辨析与配置精简

针对通配符子域名配置为何造成困扰，我们进行了根本性的技术辨析与极简重构：

### 1. 为什么最初代码要把 `suffix` 写成可配？
- **代码实现细节泄露（Leaky Abstraction）**：旧代码内部使用 `strings.TrimPrefix(host, prefix)` 和 `strings.TrimSuffix(sub, entry_suffix)` 进行切片，原作者直接把底层字符串操作用的变量暴露成了 JSON 字段；
- **`entry_suffix` 是纯冗余**：入口根域名（如 `.l.moonchan.xyz`）全局固定，且入口 key 自身就写着 `iwara.l.moonchan.xyz`；
- **`upstream_suffix` 是纯冗余**：目标站点 `host` 声明为 `iwara.tv`，其子域名后缀必然是 `.iwara.tv`（违背 DRY 原则）。

### 2. 为什么 `prefix` 必须显式存在？
- **单层泛域名证书限制**：反代证书是 `*.l.moonchan.xyz`，RFC 6125 规定通配符不能跨越点号（即无法匹配 `api.iwara.l.moonchan.xyz`），必须用中划线拍平成单层：`iwara-api.l.moonchan.xyz`；
- **多站点命名空间隔离**：Iwara 有 `api`，DLsite 也有 `api`，南+ 也有 `api`。若没有 `iwara-`、`dlsite-`、`f95-` 作为入口前缀，所有站点的二级子域将直接冲突。

### 3. 画蛇添足的消除：去除顶层 `wildcards` 列表
此前尝试在 JSON 顶层开辟独立的 `wildcards` 列表，导致同一个站点被割裂在两个地方维护（上面配主站，底下又配一遍通配）。  
**真相是：通配子域（`iwara-api`）在代码中天然就会自动继承主站（`iwara.l.moonchan.xyz`）的所有 `headers`。**  
因此，直接在主站节点配置 `headers` 即可，彻底删除了顶层多余的 `wildcards` 列表，实现单一可信源：

```json
        "iwara.l.moonchan.xyz": {
            "host": "iwara.tv",
            "referer": "https://www.iwara.tv/",
            "headers": {
                "Origin": "https://www.iwara.tv",
                "X-Site": "www.iwara.tv"
            },
            "describe": "Iwara 视频站（支持通配子域名）",
            "display": true,
            "wildcard": {
                "prefix": "iwara-",
                "entry_suffix": ".l.moonchan.xyz",
                "upstream_suffix": ".iwara.tv"
            }
        },
```

---

## 五、 向后兼容性保障与生产实测验证

### 1. `upstream.json` 真实改动范围
从基线版本到最终交付，`certs/l.moonchan.xyz/upstream.json` **仅仅增加了 4 行代码，现有字段无一删改**：

```diff
         "iwara.l.moonchan.xyz": {
             "host": "iwara.tv",
             "referer": "https://www.iwara.tv/",
+            "headers": {
+                "Origin": "https://www.iwara.tv",
+                "X-Site": "www.iwara.tv"
+            },
             "describe": "Iwara 视频站（支持通配子域名）",
             "display": true,
             "wildcard": {
                 "prefix": "iwara-",
                 "entry_suffix": ".l.moonchan.xyz",
                 "upstream_suffix": ".iwara.tv"
             }
         },
```

### 2. 生产环境旧版二进制（`v1.0.2`）实测
下载 GitHub Release 的正式版旧二进制 `/tmp/ech-proxy-v1.0.2`，直接以 `--http` 模式加载当前远程 GitHub 上的最新 `upstream.json`：

```text
2026/09/16 09:19:50 IP 栈检测: IPv4=true IPv6=false
2026/09/16 09:19:50 正在初始化 ECH 客户端...
2026/09/16 09:19:51 ECH 客户端就绪
2026/09/16 09:19:51 正在加载上游配置: https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/upstream.json?proxy_host=raw.githubusercontent.com
2026/09/16 09:19:51 上游配置加载成功: 16 条规则
=== ECH Proxy ===
  模式: HTTP (本地代理)
  监听: 127.0.0.1:28443
  域名: dlsite.l.moonchan.xyz:28443 -> www.dlsite.com (ECH) (referer: https://www.dlsite.com/) [+通配 dlsite-*.l.moonchan.xyz:28443 -> *.dlsite.com]
  域名: f95.l.moonchan.xyz:28443 -> f95zone.to (ECH) [+通配 f95-*.l.moonchan.xyz:28443 -> *.f95zone.to]
  域名: iwara.l.moonchan.xyz:28443 -> iwara.tv (ECH) (referer: https://www.iwara.tv/) [+通配 iwara-*.l.moonchan.xyz:28443 -> *.iwara.tv]
=================
```

- **验证结论**：全量 16 条规则与通配映射全部被旧版二进制完好解析；
- **机制解释**：Go 标准库 `json.Unmarshal` 对结构体未定义的未知字段（`headers`）采取静默忽略策略，旧版运行安全无虞。

### 3. 单元测试矩阵覆盖
自动化测试用例通过率 **100% (10/10 PASS)**：
- `TestMatchWildcardHeadersInheritance`：通配请求自动继承主站 Headers 验证；
- `TestCORSMiddleware`：CORS 预检与 X-Site 放行验证；
- `TestLoadUpstreamJSON`：新旧混合 JSON 配置解析验证；
- `TestBuildEntryRewriter`：正文绝对 URL 重写验证；
- `TestRewriteSetCookieDomains`：Set-Cookie 域名重写与安全标志剥离验证；
- `TestHeadersNormalization`：请求头删除、正则替换与 Origin 自动推导验证；
- `TestApplyHeaderRules`：请求头规则执行时机验证；
- `TestClientCookiesSavingAndFileCookie`：前端 JS Cookie 捕获与本地文件 Cookie 验证；
- `TestOldBinaryV102Compatibility`：模拟旧版结构体断言验证；
- `TestWildcardCleanKeysAndAutoDerivation`：通配规则极简语法兼容性验证。

---

## 六、 CI/CD 工作流缺陷修复与 v1.0.3 交付

### 1. CI 治理措施（Commit `7d83d5a`）
1. **剔除 `certs/**` 监听**：从所有工作流的 `paths` 列表中移除了 `"certs/**"`，后续修改 `upstream.json` 绝不触发任何 Action 构建任务；
2. **彻底删除 `v1.0.0` / `v1.0.2` 覆盖逻辑**：
   - 删除了 `ech-proxy-android.yml` 中的 `gh release upload v1.0.0 app-release.apk --clobber` 步骤；
   - 删除了 `ech-proxy.yml` 中的 `gh release upload v1.0.2 ...` 步骤；
3. **解耦构建时机**：
   - `ech-proxy-android.yml` 改为仅支持 `workflow_dispatch`（网页手动点击），平时 push 绝不自动打包；
   - 正式版本发布统一收敛至 [`release.yml`](.github/workflows/release.yml)，仅在打 `v*` Tag 时统一构建并归档到对应版本号下。

### 2. `v1.0.3` 交付结果
已打标并推送 Tag `v1.0.3`，Action 自动化构建（Run ID: `35079539245`）已全部成功完成，产物已完整归档至 GitHub Release `v1.0.3`：

| 交付文件名称 | 目标平台 / 架构 | 下载地址 |
| :--- | :--- | :--- |
| `app-release.apk` | Android (arm64-v8a) | [下载 app-release.apk](https://github.com/Hana-ame/ech-proxy/releases/download/v1.0.3/app-release.apk) |
| `ech-proxy-linux-amd64` | Linux x86_64 | [下载 ech-proxy-linux-amd64](https://github.com/Hana-ame/ech-proxy/releases/download/v1.0.3/ech-proxy-linux-amd64) |
| `ech-proxy-linux-aarch64` | Linux aarch64 (ARM64) | [下载 ech-proxy-linux-aarch64](https://github.com/Hana-ame/ech-proxy/releases/download/v1.0.3/ech-proxy-linux-aarch64) |
| `ech-proxy-windows-amd64.exe`| Windows x86_64 | [下载 ech-proxy-windows-amd64.exe](https://github.com/Hana-ame/ech-proxy/releases/download/v1.0.3/ech-proxy-windows-amd64.exe) |

---

## 七、 后续维护与配置规范指南

### 1. 规则核心机制：`rewrites` vs `body_replace` vs `sw_inject`

为彻底杜绝配置混淆，响应重写与 Service Worker 的协作职责明确划分如下：

| 配置项 | 语法格式 | 作用范围 | 核心机制与使用场景 |
| :--- | :--- | :--- | :--- |
| **`rewrites`** | `{"target.com": "local.proxy"}` | **Body + sw.js (双重生效)** | **域名级别映射**。<br>1. **静态 Body 替换**：将 HTML、JS、JSON、XML 及响应头 (`Location`/`Refresh`) 中的 `target.com` 替换为本地代理域名（自动附带当前监听端口）。<br>2. **Service Worker 动态拦截**：在开启 `sw_inject` 时，`rewrites` 的全部映射对会自动注入到浏览器端 `sw.js` 的 `__swMap` 中，用于在浏览器网络层实时拦截前端 JS 运行时动态拼接的请求（静态正则替换顾及不到的动态 URL，如 DLsite 图片 CDN）。 |
| **`body_replace`** | `[["old", "new"]]`<br>`[{"replace": ["old", "new"]}]` | **仅 Body (单向生效)** | **通用文本与正则替换**。<br>专门用于响应正文内容的精准文本替换或正则匹配（如特定脚本地址、版本号、内联代码微调等）。<br>**注意**：`body_replace` 绝对**不会**进入 `sw.js`，避免正则或非域名文本污染 Service Worker 的路由判定。 |
| **`sw_inject`** | `true` / `false` | **HTML 注册 + sw.js** | **Service Worker 注入开关**。<br>用于自身没有 Service Worker 的站点（如 DLsite）。开启后代理会在返回的 HTML 中自动注入 `/sw.js` 注册代码，并在请求 `/sw.js` 时动态输出包含 `rewrites` 映射与 `blocked_hosts` 拦截规则的脚本。<br>（**警告**：对于自带 Workbox 等 Service Worker 的站点如 Iwara 绝不能开启，避免冲突覆盖）。 |

### 2. 向下兼容铁律（旧客户端 v1.0.0 ~ v1.0.3 运行新 upstream.json）

由于 GitHub `main` 分支的 `upstream.json` 是所有线上版本共同读取的**单一可信源**，更新配置必须死守以下底线：

1. **`rewrites` 必须保持字典格式**：
   - 只能使用 `{"old.com": "proxy.com"}` 键值对，**绝对不能改写为数组**（旧版结构体定义为 `map[string]string`，改写数组会导致老客户端反序列化当场崩溃）。
2. **`wildcard` 必须保留完整三段式对象**：
   - 必须显式提供 `prefix`、`entry_suffix`、`upstream_suffix`。
   - 虽然新版支持简写 `"wildcard": true` 或 `"wildcard": "prefix-"`，但**老版本（v1.0.0/v1.0.2）拉取简写会报反序列化错误崩溃退出**。
3. **老字段 `referer` 必须显式保留**：
   - 虽然新版支持通用 `headers` 自动继承和推导，但老客户端二进制中没有 `headers` 引擎，必须保留各站点的 `referer`，否则旧客户端将彻底失去防盗链伪装能力。
4. **`headers` 与 `body_replace` 属于纯增量特性**：
   - 老版本客户端（v1.0.0 ~ v1.0.2）拉取到新字段时会静默忽略，虽然不崩溃，但也无法执行对应高级特性（如 Iwara 登录防 400 重写），新特性只有新版本客户端能够执行。

### 3. 入口与安全收敛状态

1. **目录收敛为三大模块**：
   - `win/`：PC 桌面端轻量入口。
   - `android/`：Android JNI 动态库与 App 轻量入口。
   - `echproxy/`：核心包，通用生命周期与服务器抽象收敛至 `echproxy/server.go`。
2. **安全第一的默认监听**：
   - 桌面端默认监听 `127.0.0.1:8443`，不再暴露局域网，需外网访问需显式 `-addr 0.0.0.0:8443`。
3. **配置原始顺序保持**：
   - 启动 Banner 移除了字母排序，全面采用 `orderedmap` 按照 `upstream.json` 里的原始书写顺序输出。

