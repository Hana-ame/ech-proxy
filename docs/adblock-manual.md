# ech-proxy 广告系统说明书

- 适用代码：分支 `feat/adult-and-domain-judgment`，commit `a64603a`（推送到 `origin/merge/ech-proxy-20261021`）
- 相关源码：`echproxy/rewrite/adscript.go`、`echproxy/rewrite/easylist.go`、`echproxy/proxy.go`、`echproxy/portal.go`、`win/main.go`
- 远端素材目录：VPS `/var/www/moonchan/` = `https://4545810.xyz/`

---

## 1. 一句话总览

| 文件 | 决定什么 |
|---|---|
| `pac.txt` | **走不走代理**（PAC 路由白名单） |
| `adult.txt` | **动不动广告**（去广告 + 注入自有广告的闸门） |
| EasyList | **剥/藏什么**（规则库，自动拉取） |
| `block.json` | **人工精选补充**（哪些 URL 要剥、哪些选择器要藏） |
| `ads.js` | **注入哪段广告脚本** |
| `on.txt` | **我们自己的广告插不插**（总开关） |

一句话：**PAC 管路由，adult.txt 管开关，EasyList+block.json 管内容，ads.js 管投放，on.txt 管投放总闸。**

---

## 2. 数据流

```
浏览器请求
   │
   ├─ PAC 判定（pac.txt）：直连 or 走代理
   │
   └─ 走代理 ──► adult.txt 命中？（请求 host 或上游 host）
                    │否 → 原样转发（不动任何广告）
                    │是
                    ▼
            ① 请求侧：EasyList $removeparam 去参数、$csp 加响应头
            ② 响应侧（仅 HTML 文档）：
                 stripBlockedURLs(内置 11 条 + block.json.blocked_urls)
               + EasyList StripMatchedURLs / StripEscapedURLs
                 → 注入隐藏样式（内置选择器 + block.json.selectors + EasyList cosmetic）
                 → 注入 ads.js（若 on.txt = on 且未 -skip-ad-script）
```

判定与注入在 `adscript.go:1187 InjectIntoHTMLForHost`；`IsAdultSite` 闸门确保**只有清单内站点**被处理。

---

## 3. 远端文件总表

| 文件 | 默认地址 | 刷新 | 失败语义 |
|---|---|---|---|
| `ads.js` | `…/ads.js` | 30 分钟 | 保留上一版；从未成功 → 内置 `BuiltInAdScript` |
| `on.txt` | `…/on.txt` | 30 分钟 | 重试 2 次后**强制 on** |
| `pac.txt` | `…/pac.txt` | 30 分钟 | **清空白名单**（fallback = []） |
| `adult.txt` | `…/adult.txt` | 30 分钟 | 保留上一版 |
| `block.json` | `…/block.json` | 30 分钟 | 清空远程规则（内置 11 条仍生效） |
| EasyList | `https://easylist.to/easylist/easylist.txt` | 30 分钟（独立协程） | 静默保留上一版；从未成功 → 不做 EasyList 剥离 |
| `ads.txt` | — | — | **当前无代码引用（死文件）**，见 §8.4 |

---

## 4. 逐文件说明

### 4.1 `on.txt` —— 自有广告总开关
- 取值：`1/true/on/yes/enable/enabled` 开；`0/false/off/no/disable/disabled` 关。
- 允许 `#`、`//` 注释与空行。
- 拉取失败重试 2 次（共 3 次），仍失败 → **强制 on**（宁可继续投放）。
- 语义对照：

| 动作 | `on` | `off` |
|---|---|---|
| 剥离原广告 | 做 | **照做** |
| 隐藏原广告 | 做 | **照做** |
| 插入 `ads.js` | 做 | 不做 |
| `/__ech_proxy__/ads.js` 返回 | 脚本内容 | `ads.js is skipped` 注释 |

`off` **不等于**停手：要"完全不动广告"须同时 `-skip-ad-block`。

### 4.2 `pac.txt` —— 路由白名单
- 一行一个域名；`#`、`//` 注释；不决定广告行为。
- 失败会**清空**（PAC 退化为直连/全局），这是唯一"失败即降级"的文件。
- 别名开关：`-adult-domains-url`（与 `-whitelist-url` 等价）。

### 4.3 `adult.txt` —— 去广告/注入闸门
- 一行一个域名，匹配请求 host 或上游 host（含父域后缀）。
- 失败**保留上一版**；从未拉到 → 空清单 → **任何站都不去广告**（安全默认）。
- 与 `pac.txt` 完全独立：可只在 pac（走代理不动广告）、只在 adult（动广告）、或都在。

### 4.4 `block.json` —— 人工精选规则
- 格式：JSON 对象/数组，或 EasyList `||domain^` / `##selector` / HOSTS 行。
- 支持的键：`domains/hosts/blocked_hosts/blocked_urls/urls/rules/blocklist/ads` → 剥离 URL；`selectors/css/elements` → 隐藏选择器。
- 与内置默认取并集：`EffectiveBlockedURLs` = 内置 11 条 + `blocked_urls`；`EffectiveAdBlockStyle` = 内置选择器 + `selectors`。
- 失败清空远程部分，内置兜底仍生效。

### 4.5 `ads.js` —— 注入脚本
- 任意合法 JS；失败/校验不过 → 保留上一版或内置 fallback。
- 注入标记 `id="ech-proxy-ad-script"`：同一页面只注入一次。
- 当前线上内容只有 **ad1**（`slimgather.com/c.Dt9m6/…`），`// ad2` 为空——若要第二个广告位，把内置 fallback 的 fussyreturn 段填进 `// ad2`。
- 调试残留 `console.log("advertise inserted")` 可删。

### 4.6 EasyList —— 规则库（自动）
- 「确定性可做子集」，**只作用于 adult.txt 命中站点**，不做全站请求拦截。
- 做：`||domain^`、`||domain/path`、`|https://domain/path`、`/path/*`、`@@`、`$denyallow`、`$important`、`$badfilter`、`$removeparam`、`$csp`、`##selector`、`#@#`。
- 不做：`$third-party/$domain/$script/$image/$xhr/$frame`、scriptlets(`##+js`)、procedural(`#?#`)、`##^`、`$redirect`、`$header=`。
- `-easylist-url -` 可整体禁用。

### 4.7 `ads.txt` —— 已失效
当前代码**没有任何引用**（`AdsAllowlistURL`/`ParseAdsAllowlist` 已随 revert 移除）。VPS 上那份 4 条放行记录不再被读取，见 §8.4。

---

## 5. 命令行开关与环境变量

| 开关 | 环境变量 | 说明 |
|---|---|---|
| `-skip-ad-script` | `ECH_PROXY_SKIP_AD_SCRIPT` / `ECH_PROXY_NO_AD_SCRIPT` | 不插入自有广告（别名 `-no-ad-script`、`-disable-ad-script`） |
| `-skip-ad-block` | `ECH_PROXY_SKIP_AD_BLOCK` | 不剥离/隐藏原广告 |
| `-ad-script-url` | `ECH_PROXY_AD_SCRIPT_URL` | `ads.js` 地址 |
| `-whitelist-url` | `ECH_PROXY_WHITELIST_URL` / `ECH_PROXY_ADULT_DOMAINS_URL` | `pac.txt` 地址 |
| `-adult-sites-url` | `ECH_PROXY_ADULT_SITES_URL` | `adult.txt` 地址 |
| `-blocklist-url` | `ECH_PROXY_BLOCKLIST_URL` | `block.json` 地址 |
| `-on-url` | `ECH_PROXY_ON_URL` | `on.txt` 地址 |
| `-easylist-url` | `ECH_PROXY_EASYLIST_URL` | EasyList 地址（`-` 禁用） |
| `-ad-script-interval` | — | 刷新周期（默认 30 分钟） |
| `-all` | `ECH_PROXY_ALL` | 全局模式（PAC 全代理） |
| `-local` | — | 443 模式（`*.443.exe` 自动启用） |
| `-http` | — | HTTP 明文模式 |
| `-sys-proxy` | `ECH_PROXY_SYS_PROXY` | 系统代理模式 |
| `-no-tray` / `-hide-console` | — | 托盘/控制台控制 |
| `-data-dir` | `ECH_PROXY_DATA_DIR` | 数据目录（CA 叶子证书在 `<data-dir>/ca/leaves/`） |
| `-config` | `ECH_PROXY_CONFIG` | `upstream.json`（仅 8443 方案） |
| `-log-dir` / `-log-file` | `ECH_PROXY_LOG_DIR` / `ECH_PROXY_LOG_FILE` | 日志 |

---

## 6. 运维与检查

**状态接口**（门户监听地址，默认 `127.0.0.1:8443`）：

| 端点 | 用途 |
|---|---|
| `/healthz` | 存活 |
| `/statusz` | JSON 状态：`ad_script_enabled`、`ad_on`、`skip_ad_script`、`skip_ad_block`、`ad_script_source`、`ad_script_version`、`whitelist_count`、`blocklist_count`、`all_mode`、`ip_mode`、`doh_primary/secondary` 等 |
| `/proxy.pac` | 当前 PAC（含白名单） |
| `/__ech_proxy__/ads.js` | 当前注入脚本；`?refresh=1` 由门户/本地管理 host 触发强制刷新 |
| `/debug/log?download=1` | 下载日志 |

**生效时间**：所有远端素材 30 分钟自动刷新；改完 VPS 文件后最多 30 分钟生效；想立刻生效可在门户 host 上请求 `…/ads.js?refresh=1`，或重启客户端。

**校验命令**（VPS 上执行）：
```bash
cd /var/www/moonchan
python3 -c "import json;json.load(open('block.json'))"   # block.json 必须合法
curl -s -o /dev/null -w '%{http_code}\n' https://4545810.xyz/adult.txt
```

---

## 7. 常见操作

| 想做什么 | 怎么做 |
|---|---|
| 让某站走代理 | 域名加进 `pac.txt` |
| 让某站去广告+投放 | 域名加进 `adult.txt`（并确保在 `pac.txt`） |
| 停止投放自有广告 | `on.txt` 写 `off`（原广告仍被剥） |
| 完全停手 | `on.txt=off` **且** 启动加 `-skip-ad-block` |
| 不剥/不藏原广告但继续投放 | 加 `-skip-ad-block`（此时 `on=on`） |
| 屏蔽新广告联盟 | 加进 `block.json.blocked_urls`，或等 EasyList 收录 |
| 隐藏新广告位 | 选择器加进 `block.json.selectors` |
| 换自有广告脚本 | 更新 `ads.js` URL 与内容 |
| 只有该站不动广告 | 从 `adult.txt` 删除该域名 |

---

## 8. 未完成 / 已知限制（截至 `a64603a`）

### 8.1 拦截能力
1. **无请求级拦截**：没有按 EasyList 直接 204 的路径；EasyList 只在 HTML 层剥离/隐藏 + 请求参数/CSP，且仅对 `adult.txt` 站点。直连流量完全不受影响。
2. EasyList 子集未实现（`easylist.go:16-25` 自述）：`$third-party/$domain/$script/$image/$xhr/$frame`、scriptlets(`##+js`)、procedural(`#?#`)、`##^`、`$redirect`、`$header=`。
3. `$domain=` 未实现 → 规则级站点限定做不到，只能靠 `adult.txt` 粗粒度限定。

### 8.2 素材与运维
4. **`ads.txt` 已失效**：revert 后代码无引用；现为死文件。处理方式二选一：删除，或重新接线为 EasyList 放行清单（需要改代码）。
5. `pac.txt` 拉取失败会**清空**白名单（退化为直连/全局），需保证该文件可访问。
6. 线上 `ads.js` 的 `ad2` 为空（只有一个广告位）。
7. `block.json` 与 EasyList 功能重叠（同一联盟可能两边都有），当前取并集，无优先级/去重调优。

### 8.3 客户端与可观测性
8. 证书「强行访问」批准仅存**会话内存**（`forcecert.go` 的 `approved` map，进程重启即清空），无持久化白名单。
9. `/statusz` **未暴露** EasyList 是否加载/规则条数，也未暴露 `adult.txt` 站点数——排查 EasyList 问题只能看行为或日志。
10. Flutter/Android 入口未接 `-adult-sites-url` / `-easylist-url` / `-blocklist-url` 等新参数，只能用默认地址，不能覆盖。

### 8.4 文档与发布
11. `README.md` / `RELEASE.md` 未更新 `adult.txt`、EasyList、`ads.txt` 状态与「certs 只归 8443」等新事实。
12. 未打新 tag；`RELEASE.md` 最新仍是 `v3.3.0`，本批改动没有版本条目。
13. EasyList 规则索引无条数上限/内存监控（下载上限 32MB）。

---

## 9. 排错

| 现象 | 先查 |
|---|---|
| 某站完全不处理 | 域名在 `adult.txt`？`/statusz` 看 `ad_script_enabled`、`ad_on` |
| 不投放自有广告 | `on.txt` 是否 `off`；是否 `-skip-ad-script`；`/__ech_proxy__/ads.js` 返回什么 |
| 原广告没被剥 | 是否 `-skip-ad-block`；`/statusz` 的 `blocklist_count`；EasyList 是否加载成功（拉不到则静默跳过） |
| 误剥正常资源 | 检查 `block.json.blocked_urls` 是否过宽；EasyList 子集规则是否命中 |
| 改了 VPS 文件没生效 | 等 ≤30 分钟，或 `?refresh=1`，或重启 |
| 路由不对 | `pac.txt` 是否含该域名；PAC 是否被系统/浏览器缓存 |
| `block.json` 无效 | `python3 -c "import json;json.load(open('block.json'))"` |

---

## 附：素材模板

```
/var/www/moonchan/
├── ads.js        # JS，注入的广告脚本
├── on.txt        # on / off
├── pac.txt       # 一行一个域名（路由）
├── adult.txt     # 一行一个域名（去广告/注入闸门）
├── block.json    # {"blocked_urls":[…],"selectors":[…]}
└── ads.txt       # 当前无效（见 §8.4）
```