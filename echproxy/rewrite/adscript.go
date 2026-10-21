package rewrite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hana-ame/ech-proxy/echproxy/logger"
	"github.com/Hana-ame/ech-proxy/echproxy/netdial"
)

const (
	// DefaultAdScriptURL 是远程去广告与成人站点推广脚本的默认拉取地址（支持热更新）。
	DefaultAdScriptURL = "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/ad_script.js?proxy_host=raw.githubusercontent.com"

	// DefaultWhitelistURL 是远程唯一白名单（即黄网域名 JSON 列表）的默认拉取地址：
	// 白名单 = 黄网 = 去掉原有广告 + 加上自己广告 + 通过 ech-proxy 的 PAC 规则代理（其他直接 DIRECT）；
	// 留空使用该默认地址，拉取或解析失败时严格执行 fallback = empty（[]）。
	DefaultWhitelistURL = "https://proxy.moonchan.xyz/Hana-ame/ech-proxy/refs/heads/main/certs/l.moonchan.xyz/whitelist.json?proxy_host=raw.githubusercontent.com"

	// DefaultAdScriptUpdateInterval 是远程脚本与远程白名单后台自动检查更新的默认周期（30 分钟）。
	DefaultAdScriptUpdateInterval = 30 * time.Minute

	maxAdScriptBytes   = 2 << 20 // 2 MB 安全上限
	maxDomainJSONBytes = 1 << 20 // 1 MB 域名列表 JSON 上限
	cachedScriptName   = "ad_script.js"
)

// DefaultAdNetworkBlockedURLs 是服务端 HTML 重写层对黄网剥离的常见第三方广告联盟域名列表。
var DefaultAdNetworkBlockedURLs = []string{
	"https://syndication.exoclick.com",
	"https://main.exoclick.com",
	"https://a.magsrv.com",
	"https://a.realsrv.com",
	"https://adserver.juicyads.com",
	"https://poweredby.jads.co",
	"https://ads.trafficjunky.net",
	"https://ads.ero-advertising.com",
	"https://cdn.tsyndicate.com",
	"https://pagead2.googlesyndication.com",
	"https://securepubads.g.doubleclick.net",
}

// DefaultAdultAdSignatures 是用于在 HTML 中识别“出现了成人网站广告”的特征列表。
// 仅包含成人网站广告联盟域名与成人广告专属 DOM 标记，不包含 Google AdSense / DoubleClick 等常规广告，防止普通网站误判。
var DefaultAdultAdSignatures = []string{
	"exoclick.com",
	"exosrv.com",
	"magsrv.com",
	"realsrv.com",
	"juicyads.com",
	"jads.co",
	"trafficjunky.net",
	"trafficjunky.com",
	"ero-advertising.com",
	"ero-advertising.ch",
	"tsyndicate.com",
	"trafficstars.com",
	"plugrush.com",
	"adxpansion.com",
	"media.dlsite.com",
	"dmm.co.jp/ad",
	"ad.duga.jp",
	"chaturbate.com/affiliates",
	"stripchat.com/checkurl",
	"data-exo-zone",
	"exo-native-widget",
	"data-juicyads",
	"adsbyjuicy",
	"data-trafficjunky",
	"data-ero-ad",
	"data-adult-ad",
	`class="adult-ad"`,
	`id="adult-ad"`,
}

// BuiltInAdScript 是内置的默认去广告与黄网自有广告注入脚本（当远程脚本尚未拉取完成或离线时自动兜底）。
const BuiltInAdScript = `/**
 * ech-proxy Remote Ad-Blocker & Adult-Site Custom Promotion Script
 * Version: 2026.10.20-v3
 *
 * Unified Rules:
 * 1. Remote Whitelist (certs/l.moonchan.xyz/whitelist.json, configurable via -whitelist-url,
 *    empty -> default remote URL, fetch failure -> fallback = []).
 *    Whitelist = Adult Website (黄网) = Remove original ads + Add custom promotion ad + Proxied via PAC.
 * 2. Websites whose HTML contains adult website advertisements (ExoClick, JuicyAds,
 *    TrafficJunky, Ero-Advertising, TrafficStars, PlugRush, DLsite/DMM adult ad widgets, etc.)
 *    are also recognized as Adult Websites (黄网) -> Remove original ads + Add custom promotion ad.
 */
(function () {
  "use strict";
  if (typeof window === "undefined" || typeof document === "undefined") return;
  if (window.__ECH_PROXY_DISABLE_AD_SCRIPT__ === true) return;
  if (window.__ECH_PROXY_AD_SCRIPT_LOADED__ === true) return;
  window.__ECH_PROXY_AD_SCRIPT_LOADED__ = true;

  var SCRIPT_VERSION = "2026.10.20-v3";
  var DEFAULT_CUSTOM_AD = {
    id: "ech-proxy-custom-ad",
    badge: "ECH-PROXY 推荐",
    title: "⚡ ECH-Proxy 高速免配置加密加速通道 — 畅享海量绅士站点与高清原图",
    subtitle: "支持 Pixiv / ExHentai / DLsite / Iwara / ASMR.one 全自动 ECH & SNI 加速，点击访问导航门户获取最新福利与节点！",
    ctaText: "立即前往导航门户 →",
    targetUrl: "https://l.moonchan.xyz:8443/",
    bgColor: "linear-gradient(90deg, #141923 0%, #1d2738 50%, #182232 100%)",
    borderColor: "#5ce1e6",
    accentColor: "#5ce1e6"
  };

  var userCfg = window.__ECH_PROXY_AD_CONFIG__ || {};
  var AD_CONFIG = {
    id: userCfg.id || DEFAULT_CUSTOM_AD.id,
    badge: userCfg.badge || DEFAULT_CUSTOM_AD.badge,
    title: userCfg.title || DEFAULT_CUSTOM_AD.title,
    subtitle: userCfg.subtitle || DEFAULT_CUSTOM_AD.subtitle,
    ctaText: userCfg.ctaText || DEFAULT_CUSTOM_AD.ctaText,
    targetUrl: userCfg.targetUrl || DEFAULT_CUSTOM_AD.targetUrl,
    bgColor: userCfg.bgColor || DEFAULT_CUSTOM_AD.bgColor,
    borderColor: userCfg.borderColor || DEFAULT_CUSTOM_AD.borderColor,
    accentColor: userCfg.accentColor || DEFAULT_CUSTOM_AD.accentColor
  };

  // Adult advertisement network domains (presence in HTML marks page as an adult website / 黄网)
  var ADULT_AD_DOMAINS = [
    "exoclick.com", "exosrv.com", "magsrv.com", "realsrv.com",
    "juicyads.com", "jads.co",
    "trafficjunky.net", "trafficjunky.com",
    "ero-advertising.com", "ero-advertising.ch",
    "tsyndicate.com", "trafficstars.com",
    "plugrush.com", "adxpansion.com",
    "media.dlsite.com", "dmm.co.jp/ad", "ad.duga.jp",
    "chaturbate.com/affiliates", "stripchat.com/checkurl"
  ];

  // Adult advertisement DOM selectors (presence in HTML marks page as an adult website / 黄网)
  var ADULT_AD_SELECTORS = [
    ".exo-native-widget", "[data-exo-zone]", "[id^='exo_']", "[class*='exo-ad']",
    "[data-juicyads]", "ins.adsbyjuicy",
    "[data-trafficjunky]", "[class*='trafficjunky']",
    "[data-ero-ad]", "[id^='ero_ad']",
    "[data-adult-ad]", ".adult-ad", "#adult-ad",
    "iframe[src*='exoclick']", "iframe[src*='exosrv']",
    "iframe[src*='magsrv']", "iframe[src*='realsrv']",
    "iframe[src*='juicyads']", "iframe[src*='jads.co']",
    "iframe[src*='trafficjunky']", "iframe[src*='ero-advertising']",
    "iframe[src*='tsyndicate']", "iframe[src*='trafficstars']",
    "iframe[src*='plugrush']", "iframe[src*='ad.duga.jp']",
    "iframe[src*='dmm.co.jp/ad']", "iframe[src*='media.dlsite.com']",
    "script[src*='exoclick']", "script[src*='exosrv']",
    "script[src*='magsrv']", "script[src*='realsrv']",
    "script[src*='juicyads']", "script[src*='jads.co']",
    "script[src*='trafficjunky']", "script[src*='ero-advertising']",
    "script[src*='tsyndicate']", "script[src*='trafficstars']",
    "script[src*='plugrush']"
  ];

  // All ad network domains to strip on adult websites
  var ALL_AD_NETWORK_DOMAINS = ADULT_AD_DOMAINS.concat([
    "popads.net", "popcash.net", "propellerads.com", "adsterra.com", "adsco.re",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com",
    "taboola.com", "outbrain.com", "mgid.com", "revcontent.com"
  ]);

  // All ad selectors to hide/remove on adult websites
  var ALL_AD_SELECTORS = ADULT_AD_SELECTORS.concat([
    "ins.adsbygoogle", "[id^='div-gpt-ad']", "[id^='google_ads_iframe']",
    "[id^='ad-banner']", "[id^='ad_banner']", "[id^='ads-banner']",
    "[class*='ad-banner']", "[class*='ad_banner']", "[class*='ad-container']",
    "[class*='ad_container']", "[class*='ads-container']", "[class*='adsbox']",
    ".ad-slot", ".ad-wrapper", ".ad-zone", ".advertisement", ".sponsor-banner",
    "[data-ad-slot]", "[data-ad-client]",
    "iframe[src*='adsterra']", "iframe[src*='doubleclick']", "iframe[src*='googlesyndication']"
  ]);

  function getScriptElement() {
    if (document.getElementById) {
      return document.getElementById("ech-proxy-ad-script");
    }
    return null;
  }

  function normalizeDomain(d) {
    if (!d || typeof d !== "string") return "";
    var s = d.trim().toLowerCase();
    s = s.replace(/^https?:\/\//, "");
    var slashIdx = s.indexOf("/");
    if (slashIdx !== -1) s = s.slice(0, slashIdx);
    var colonIdx = s.indexOf(":");
    if (colonIdx !== -1) s = s.slice(0, colonIdx);
    s = s.replace(/^(\*\.)+/, "").replace(/^\.+/, "").replace(/\.+$/, "");
    return s;
  }

  function normalizeDomainArray(arr) {
    if (!Array.isArray(arr)) return [];
    var out = [];
    var seen = {};
    for (var i = 0; i < arr.length; i++) {
      var n = normalizeDomain(arr[i]);
      if (n && !seen[n]) {
        seen[n] = true;
        out.push(n);
      }
    }
    return out;
  }

  function parseJSONDomainAttr(attrVal) {
    if (!attrVal || typeof attrVal !== "string") return [];
    try {
      var parsed = JSON.parse(attrVal);
      if (Array.isArray(parsed)) return normalizeDomainArray(parsed);
      if (parsed && Array.isArray(parsed.domains)) return normalizeDomainArray(parsed.domains);
      if (parsed && Array.isArray(parsed.whitelist)) return normalizeDomainArray(parsed.whitelist);
    } catch (_) {}
    return [];
  }

  // Single Remote Whitelist (Whitelist = 黄网; fallback = empty [])
  function getWhitelist() {
    var list = [];
    if (Array.isArray(window.__ECH_PROXY_WHITELIST__)) {
      list = list.concat(window.__ECH_PROXY_WHITELIST__);
    }
    var scriptEl = getScriptElement();
    if (scriptEl && scriptEl.getAttribute) {
      var attrDomains = parseJSONDomainAttr(scriptEl.getAttribute("data-whitelist"));
      if (attrDomains.length > 0) {
        list = list.concat(attrDomains);
      }
    }
    return normalizeDomainArray(list);
  }

  function getCandidateHosts() {
    var hosts = [];
    var locHost = normalizeDomain((window.location && window.location.hostname) || "");
    if (locHost) hosts.push(locHost);
    var scriptEl = getScriptElement();
    if (scriptEl && scriptEl.getAttribute) {
      var upHost = normalizeDomain(scriptEl.getAttribute("data-upstream-host") || "");
      if (upHost && hosts.indexOf(upHost) === -1) hosts.push(upHost);
    }
    return hosts;
  }

  function matchesDomainList(hosts, domainList) {
    if (!hosts || !hosts.length || !domainList || !domainList.length) return false;
    for (var h = 0; h < hosts.length; h++) {
      var host = hosts[h];
      if (!host) continue;
      for (var i = 0; i < domainList.length; i++) {
        var d = domainList[i];
        if (!d) continue;
        if (host === d || (host.length > d.length && host.slice(-(d.length + 1)) === "." + d)) {
          return true;
        }
      }
    }
    return false;
  }

  var state = {
    version: SCRIPT_VERSION,
    whitelisted: false,
    removedCount: 0,
    isAdult: false,
    adultReason: "",
    hasAdultAds: false,
    customAdInjected: false,
    dismissed: false
  };
  window.__ECH_PROXY_AD_STATE__ = state;

  function isOwnElement(el) {
    if (!el || !el.getAttribute) return false;
    if (el.id === AD_CONFIG.id || el.id === "ech-proxy-ad-script" || el.id === "ech-proxy-adblock-style") return true;
    return el.getAttribute("data-ech-custom-ad") === "1" || el.getAttribute("data-ech-proxy") === "ad-script";
  }

  function matchesDomainSubstrings(url, domains) {
    if (!url || typeof url !== "string") return false;
    var lower = url.toLowerCase();
    for (var i = 0; i < domains.length; i++) {
      if (lower.indexOf(domains[i]) !== -1) return true;
    }
    return false;
  }

  // Check whether the HTML/DOM contains adult website advertisements.
  function detectAdultAdsInDOM() {
    if (state.hasAdultAds) return true;
    var scriptEl = getScriptElement();
    if (scriptEl && scriptEl.getAttribute && scriptEl.getAttribute("data-has-adult-ad") === "1") {
      state.hasAdultAds = true;
      return true;
    }
    if (document.querySelectorAll) {
      try {
        var adultNodes = document.querySelectorAll(ADULT_AD_SELECTORS.join(","));
        for (var i = 0; i < adultNodes.length; i++) {
          if (adultNodes[i] && !isOwnElement(adultNodes[i])) {
            state.hasAdultAds = true;
            return true;
          }
        }
      } catch (_) {}
      try {
        var resourceNodes = document.querySelectorAll("iframe[src], script[src], a[href], img[src], [data-src]");
        for (var j = 0; j < resourceNodes.length; j++) {
          var el = resourceNodes[j];
          if (!el || isOwnElement(el)) continue;
          var src = el.getAttribute("src") || el.getAttribute("href") || el.getAttribute("data-src") || "";
          if (matchesDomainSubstrings(src, ADULT_AD_DOMAINS)) {
            state.hasAdultAds = true;
            return true;
          }
        }
      } catch (_) {}
    }
    return false;
  }

  // Adult website (黄网) judgment:
  // 1. Domain is in the remote Whitelist (白名单 = 黄网, fallback = []), OR
  // 2. HTML/DOM contains adult website advertisements (html中出现了成人网站广告)
  function isAdultWebsite() {
    var scriptEl = getScriptElement();
    if (scriptEl && scriptEl.getAttribute && scriptEl.getAttribute("data-is-adult") === "1") {
      state.whitelisted = scriptEl.getAttribute("data-whitelisted") === "1";
      state.adultReason = scriptEl.getAttribute("data-adult-reason") || "whitelist";
      return true;
    }
    var hosts = getCandidateHosts();
    var whitelist = getWhitelist();
    if (matchesDomainList(hosts, whitelist)) {
      state.whitelisted = true;
      state.adultReason = "whitelist";
      return true;
    }
    state.whitelisted = false;
    if (detectAdultAdsInDOM()) {
      state.adultReason = "html-adult-ad";
      return true;
    }
    state.adultReason = "";
    return false;
  }

  function injectAdBlockStyle() {
    if (document.getElementById("ech-proxy-adblock-style")) return;
    var head = document.head || document.getElementsByTagName("head")[0] || document.documentElement;
    if (!head) return;
    var style = document.createElement("style");
    style.id = "ech-proxy-adblock-style";
    style.setAttribute("data-ech-proxy", "ad-script");
    style.textContent = ALL_AD_SELECTORS.join(",\n") + " {\n  display: none !important;\n  visibility: hidden !important;\n  height: 0 !important;\n  max-height: 0 !important;\n  overflow: hidden !important;\n  pointer-events: none !important;\n}\n";
    head.appendChild(style);
  }

  function removeOriginalAds() {
    var removed = 0;
    if (document.querySelectorAll) {
      try {
        var nodes = document.querySelectorAll(ALL_AD_SELECTORS.join(","));
        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];
          if (node && !isOwnElement(node) && node.parentNode) {
            node.parentNode.removeChild(node);
            removed++;
          }
        }
      } catch (_) {}
      try {
        var framesAndScripts = document.querySelectorAll("iframe[src], script[src], a[href]");
        for (var j = 0; j < framesAndScripts.length; j++) {
          var el = framesAndScripts[j];
          if (!el || isOwnElement(el)) continue;
          var tag = (el.tagName || "").toUpperCase();
          var attr = tag === "A" ? el.getAttribute("href") : el.getAttribute("src");
          if (matchesDomainSubstrings(attr, ALL_AD_NETWORK_DOMAINS) && el.parentNode) {
            el.parentNode.removeChild(el);
            removed++;
          }
        }
      } catch (_) {}
    }
    state.removedCount += removed;
    return removed;
  }

  function injectCustomAdBanner() {
    if (state.dismissed) return false;
    if (document.getElementById(AD_CONFIG.id)) {
      state.customAdInjected = true;
      return true;
    }
    var body = document.body || document.getElementsByTagName("body")[0];
    if (!body) return false;

    var banner = document.createElement("div");
    banner.id = AD_CONFIG.id;
    banner.setAttribute("data-ech-custom-ad", "1");
    banner.style.cssText = "position:relative;z-index:2147483000;box-sizing:border-box;width:calc(100% - 24px);max-width:1160px;margin:10px auto;padding:10px 16px;background:" + AD_CONFIG.bgColor + ";border:1px solid " + AD_CONFIG.borderColor + ";border-radius:10px;color:#f0f6fc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;line-height:1.5;display:flex;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 4px 16px rgba(0,0,0,0.35);";

    var leftBox = document.createElement("div");
    leftBox.style.cssText = "display:flex;align-items:center;gap:10px;flex-wrap:wrap;flex:1;min-width:0;";

    var badge = document.createElement("span");
    badge.textContent = AD_CONFIG.badge;
    badge.style.cssText = "display:inline-block;padding:2px 8px;border-radius:4px;background:" + AD_CONFIG.accentColor + ";color:#0d1117;font-weight:700;font-size:11px;letter-spacing:0.5px;flex-shrink:0;";

    var textWrap = document.createElement("div");
    textWrap.style.cssText = "display:flex;flex-direction:column;min-width:0;";

    var titleLink = document.createElement("a");
    titleLink.href = AD_CONFIG.targetUrl;
    titleLink.target = "_blank";
    titleLink.rel = "noopener noreferrer";
    titleLink.textContent = AD_CONFIG.title;
    titleLink.style.cssText = "color:#5ce1e6;font-weight:600;text-decoration:none;font-size:14px;";

    var subText = document.createElement("span");
    subText.textContent = AD_CONFIG.subtitle;
    subText.style.cssText = "color:#8b949e;font-size:12px;";

    textWrap.appendChild(titleLink);
    textWrap.appendChild(subText);
    leftBox.appendChild(badge);
    leftBox.appendChild(textWrap);

    var rightBox = document.createElement("div");
    rightBox.style.cssText = "display:flex;align-items:center;gap:8px;flex-shrink:0;";

    var ctaBtn = document.createElement("a");
    ctaBtn.href = AD_CONFIG.targetUrl;
    ctaBtn.target = "_blank";
    ctaBtn.rel = "noopener noreferrer";
    ctaBtn.textContent = AD_CONFIG.ctaText;
    ctaBtn.style.cssText = "display:inline-block;padding:5px 12px;border-radius:6px;background:rgba(92,225,230,0.15);border:1px solid #5ce1e6;color:#5ce1e6;font-weight:600;font-size:12px;text-decoration:none;white-space:nowrap;";

    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.title = "关闭推广横幅";
    closeBtn.textContent = "×";
    closeBtn.style.cssText = "background:transparent;border:none;color:#8b949e;font-size:18px;line-height:1;cursor:pointer;padding:2px 6px;";
    closeBtn.onclick = function () {
      state.dismissed = true;
      if (banner.parentNode) banner.parentNode.removeChild(banner);
    };

    rightBox.appendChild(ctaBtn);
    rightBox.appendChild(closeBtn);
    banner.appendChild(leftBox);
    banner.appendChild(rightBox);

    if (body.firstChild) {
      body.insertBefore(banner, body.firstChild);
    } else {
      body.appendChild(banner);
    }
    state.customAdInjected = true;
    return true;
  }

  // 白名单 = 黄网（或 HTML 含成人网站广告）= 去掉原有广告 + 加上自己广告
  function runPass() {
    detectAdultAdsInDOM();
    state.isAdult = isAdultWebsite();
    if (!state.isAdult) {
      return;
    }
    injectAdBlockStyle();
    removeOriginalAds();
    injectCustomAdBanner();
  }

  // Optional browser-side remote whitelist JSON loader (fallback = [] on error)
  function fetchRemoteWhitelistIfConfigured() {
    if (typeof window.fetch !== "function") return;
    var whiteUrl = window.__ECH_PROXY_WHITELIST_URL__;
    if (typeof whiteUrl === "string" && whiteUrl.trim() !== "") {
      window.fetch(whiteUrl.trim())
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (data) {
          window.__ECH_PROXY_WHITELIST__ = Array.isArray(data) ? data : (data && Array.isArray(data.domains) ? data.domains : []);
          runPass();
        })
        .catch(function () {
          window.__ECH_PROXY_WHITELIST__ = [];
          runPass();
        });
    }
  }

  runPass();
  fetchRemoteWhitelistIfConfigured();

  if (document.readyState === "loading" && document.addEventListener) {
    document.addEventListener("DOMContentLoaded", runPass, { once: true });
  }
  if (typeof MutationObserver !== "undefined" && document.documentElement) {
    var scheduled = false;
    var observer = new MutationObserver(function () {
      if (scheduled) return;
      scheduled = true;
      setTimeout(function () {
        scheduled = false;
        runPass();
      }, 250);
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
})();
`

// ParseDomainListJSON 解析远程唯一白名单 JSON 列表（支持 ["a.com","b.com"] 或 {"domains":[...]}）。
// 当输入为空或格式非法时返回 error，调用方据此执行 fallback = empty（[]）。
func ParseDomainListJSON(raw []byte) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxDomainJSONBytes {
		return nil, fmt.Errorf("empty or oversized whitelist JSON (len=%d)", len(trimmed))
	}

	var list []string
	if err := json.Unmarshal(trimmed, &list); err == nil {
		return normalizeDomainSlice(list), nil
	}

	var obj struct {
		Domains   []string `json:"domains"`
		Whitelist []string `json:"whitelist"`
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, fmt.Errorf("invalid whitelist JSON: %w", err)
	}
	merged := append([]string(nil), obj.Domains...)
	merged = append(merged, obj.Whitelist...)
	return normalizeDomainSlice(merged), nil
}

func normalizeDomainEntry(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	for strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*.")
	}
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, " \t\r\n/\\:*?") || !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func normalizeDomainSlice(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, item := range in {
		d := normalizeDomainEntry(item)
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// MatchDomainInList 判断目标域名（或其父域名）是否命中给定的归一化域名列表。
func MatchDomainInList(host string, domainList []string) bool {
	h := normalizeDomainEntry(host)
	if h == "" || len(domainList) == 0 {
		return false
	}
	for _, d := range domainList {
		if d == "" {
			continue
		}
		if h == d || (len(h) > len(d) && strings.HasSuffix(h, "."+d)) {
			return true
		}
	}
	return false
}

// ContainsAdultAdInHTML 检测 HTML 正文中是否出现了成人网站广告特征。
func ContainsAdultAdInHTML(htmlBody []byte) bool {
	if len(htmlBody) == 0 {
		return false
	}
	lower := bytes.ToLower(htmlBody)
	for _, sig := range DefaultAdultAdSignatures {
		if bytes.Contains(lower, []byte(sig)) {
			return true
		}
	}
	return false
}

// AdScriptOptions 配置远程脚本与远程唯一白名单（黄网列表）管理器。
type AdScriptOptions struct {
	Enabled        bool                         // 是否启用远程脚本加载与注入（可通过 -no-ad-script 关闭）
	AllMode        bool                         // 是否开启 all 全局代理模式（无视白名单所有网站均走 ech-proxy）
	ScriptURL      string                       // 远程脚本 URL 或本地文件路径（留空使用 DefaultAdScriptURL）
	WhitelistURL   string                       // 远程唯一白名单（黄网域名 JSON 列表）URL（留空使用 DefaultWhitelistURL，拉取失败 fallback = empty []）
	UpdateInterval time.Duration                // 自动拉取更新间隔（默认 30m）
	CacheDir       string                       // 本地磁盘缓存目录（仅用于缓存 ad_script.js 脚本本体）
	FetchFn        func(string) ([]byte, error) // 自定义拉取函数（测试注入用，默认 netdial.FetchBytes）
}

// AdScriptManager 负责远程脚本与远程唯一白名单（白名单 = 黄网 = 去掉原有广告 + 加上自己广告 + PAC 走代理）的管理与注入。
type AdScriptManager struct {
	mu             sync.RWMutex
	enabled        atomic.Bool
	allMode        atomic.Bool
	scriptURL      string
	whitelistURL   string
	updateInterval time.Duration
	cacheDir       string
	fetchFn        func(string) ([]byte, error)

	scriptBytes []byte
	versionHash string
	source      string   // "builtin", "cache", "remote"
	whitelist   []string // 远程唯一白名单（黄网列表），默认及拉取失败 fallback 均为空切片 []
	lastUpdated time.Time
	lastError   string
	stopOnce    sync.Once
	stopCh      chan struct{}
}

// NewAdScriptManager 创建并初始化远程脚本及唯一白名单管理器。
func NewAdScriptManager(opts AdScriptOptions) *AdScriptManager {
	scriptURL := strings.TrimSpace(opts.ScriptURL)
	if scriptURL == "" {
		scriptURL = DefaultAdScriptURL
	}
	whiteURL := strings.TrimSpace(opts.WhitelistURL)
	if whiteURL == "" {
		whiteURL = DefaultWhitelistURL
	}
	interval := opts.UpdateInterval
	if interval <= 0 {
		interval = DefaultAdScriptUpdateInterval
	}
	fetchFn := opts.FetchFn
	if fetchFn == nil {
		fetchFn = netdial.FetchBytes
	}

	m := &AdScriptManager{
		scriptURL:      scriptURL,
		whitelistURL:   whiteURL,
		updateInterval: interval,
		cacheDir:       strings.TrimSpace(opts.CacheDir),
		fetchFn:        fetchFn,
		whitelist:      []string{}, // fallback = empty
		stopCh:         make(chan struct{}),
	}
	m.enabled.Store(opts.Enabled)
	m.allMode.Store(opts.AllMode)

	// 1. 加载内置默认脚本作为脚本代码本体保底（内置脚本不含任何硬编码域名，域名列表严格遵循 fallback = empty）
	m.setScriptLocked([]byte(BuiltInAdScript), "builtin")

	// 2. 若本地磁盘有上次拉取缓存的脚本且合法，则恢复脚本代码缓存
	if m.cacheDir != "" {
		cachePath := filepath.Join(m.cacheDir, cachedScriptName)
		if cached, err := os.ReadFile(cachePath); err == nil && isValidAdScript(cached) {
			m.setScriptLocked(cached, "cache")
		}
	}
	return m
}

func (m *AdScriptManager) setScriptLocked(raw []byte, src string) {
	sum := sha256.Sum256(raw)
	m.scriptBytes = append([]byte(nil), raw...)
	m.versionHash = hex.EncodeToString(sum[:8])
	m.source = src
	m.lastUpdated = time.Now()
}

// isValidAdScript 校验拉取到的脚本内容是否为合法的 JavaScript（拦截 404/502 HTML 错误页或空内容）。
func isValidAdScript(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 16 || len(trimmed) > maxAdScriptBytes {
		return false
	}
	head := strings.ToLower(string(trimmed[:minInt(len(trimmed), 64)]))
	if strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") || strings.HasPrefix(head, "<?xml") {
		return false
	}
	if bytes.Contains(bytes.ToLower(trimmed), []byte("</script>")) {
		return false
	}
	return true
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Enabled 返回当前是否启用了远程脚本注入。
func (m *AdScriptManager) Enabled() bool {
	if m == nil {
		return false
	}
	return m.enabled.Load()
}

// SetEnabled 动态开启或关闭远程脚本注入功能（支持 CLI flag 与托盘菜单实时切换）。
func (m *AdScriptManager) SetEnabled(v bool) {
	if m == nil {
		return
	}
	m.enabled.Store(v)
	log.Printf("[AdScript] Feature enabled=%v (all=%v, url=%s)", v, m.AllMode(), m.ScriptURL())
}

// AllMode 返回是否处于全局 all 模式（无视名单所有网站均走 ech-proxy）。
func (m *AdScriptManager) AllMode() bool {
	if m == nil {
		return false
	}
	return m.allMode.Load()
}

// SetAllMode 动态设置是否开启全局 all 模式。
func (m *AdScriptManager) SetAllMode(all bool) {
	if m == nil {
		return
	}
	m.allMode.Store(all)
}

// ScriptURL 返回远程脚本配置地址。
func (m *AdScriptManager) ScriptURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scriptURL
}

// WhitelistURL 返回远程唯一白名单（黄网列表）JSON 的配置地址。
func (m *AdScriptManager) WhitelistURL() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whitelistURL
}

// Whitelist 返回当前生效的远程白名单（黄网域名列表）副本（拉取失败或未拉取时为空切片 []）。
func (m *AdScriptManager) Whitelist() []string {
	if m == nil {
		return []string{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.whitelist) == 0 {
		return []string{}
	}
	return append([]string(nil), m.whitelist...)
}

// SetWhitelist 显式设置白名单域名列表（自动归一化，传 nil/空切片时重置为空列表 []）。
func (m *AdScriptManager) SetWhitelist(domains []string) {
	if m == nil {
		return
	}
	norm := normalizeDomainSlice(domains)
	m.mu.Lock()
	m.whitelist = norm
	m.mu.Unlock()
}

// IsWhitelisted 判断给定域名（如 requestHost, upstreamHost）是否命中远程白名单（白名单 = 黄网）。
func (m *AdScriptManager) IsWhitelisted(hosts ...string) bool {
	if m == nil {
		return false
	}
	wl := m.Whitelist()
	if len(wl) == 0 {
		return false
	}
	for _, h := range hosts {
		if MatchDomainInList(h, wl) {
			return true
		}
	}
	return false
}

// IsAdultWebsite 判定目标网页是否为黄网（成人网站）：
//  1. 域名命中远程白名单（白名单 = 黄网，拉取失败 fallback = []）；
//  2. 或者网页 HTML 中出现了成人网站广告。
func (m *AdScriptManager) IsAdultWebsite(htmlBody []byte, hosts ...string) (isAdult bool, reason string) {
	if m != nil && m.IsWhitelisted(hosts...) {
		return true, "whitelist"
	}
	if ContainsAdultAdInHTML(htmlBody) {
		return true, "html-adult-ad"
	}
	return false, ""
}

// VersionHash 返回当前生效脚本的 SHA-256 短指纹。
func (m *AdScriptManager) VersionHash() string {
	if m == nil {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.versionHash
}

// Source 返回当前脚本来源（"builtin" / "cache" / "remote"）。
func (m *AdScriptManager) Source() string {
	if m == nil {
		return "disabled"
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.source
}

// LastUpdated 返回最近一次脚本加载/更新的时间。
func (m *AdScriptManager) LastUpdated() time.Time {
	if m == nil {
		return time.Time{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastUpdated
}

// ScriptBytes 返回当前生效的脚本内容副本。
func (m *AdScriptManager) ScriptBytes() []byte {
	if m == nil || !m.Enabled() {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]byte(nil), m.scriptBytes...)
}

// RefreshWhitelistOnce 从 WhitelistURL 拉取远程唯一白名单（黄网域名 JSON 列表）；
// 若拉取失败或 JSON 非法，严格执行 fallback = empty（重置为空列表 []）。
func (m *AdScriptManager) RefreshWhitelistOnce() ([]string, error) {
	if m == nil {
		return []string{}, nil
	}
	m.mu.RLock()
	url := m.whitelistURL
	fetch := m.fetchFn
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		m.mu.Lock()
		m.whitelist = []string{}
		m.mu.Unlock()
		return []string{}, nil
	}

	raw, err := fetch(url)
	if err != nil {
		m.mu.Lock()
		m.whitelist = []string{}
		m.mu.Unlock()
		return []string{}, fmt.Errorf("fetch whitelist JSON from %s: %w", url, err)
	}
	domains, perr := ParseDomainListJSON(raw)
	if perr != nil {
		m.mu.Lock()
		m.whitelist = []string{}
		m.mu.Unlock()
		return []string{}, fmt.Errorf("parse whitelist JSON from %s: %w", url, perr)
	}

	m.mu.Lock()
	m.whitelist = domains
	m.mu.Unlock()
	return append([]string(nil), domains...), nil
}

// RefreshOnce 立即从远程拉取最新脚本与远程唯一白名单（失败时白名单自动 fallback = empty []）。
func (m *AdScriptManager) RefreshOnce() (bool, error) {
	if m == nil {
		return false, nil
	}

	// 刷新远程白名单（即使禁用广告脚本，PAC 规则也依赖远程白名单，除非处于 all 模式）
	_, whiteErr := m.RefreshWhitelistOnce()

	if !m.Enabled() {
		return false, whiteErr
	}

	m.mu.RLock()
	url := m.scriptURL
	fetch := m.fetchFn
	oldHash := m.versionHash
	cacheDir := m.cacheDir
	m.mu.RUnlock()

	if url == "" || fetch == nil {
		return false, whiteErr
	}

	raw, err := fetch(url)
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return false, fmt.Errorf("fetch remote ad script from %s: %w", url, err)
	}
	if !isValidAdScript(raw) {
		err := fmt.Errorf("remote ad script from %s failed validation (len=%d)", url, len(raw))
		m.mu.Lock()
		m.lastError = err.Error()
		m.mu.Unlock()
		return false, err
	}

	sum := sha256.Sum256(raw)
	newHash := hex.EncodeToString(sum[:8])

	m.mu.Lock()
	m.lastError = ""
	changed := newHash != oldHash || m.source != "remote"
	m.setScriptLocked(raw, "remote")
	m.mu.Unlock()

	if changed {
		if cacheDir != "" {
			if err := os.MkdirAll(cacheDir, 0o755); err == nil {
				_ = os.WriteFile(filepath.Join(cacheDir, cachedScriptName), raw, 0o644)
			}
		}
		log.Printf("[AdScript] Remote script updated from %s (version=%s, size=%d bytes, whitelist=%d)",
			url, newHash, len(raw), len(m.Whitelist()))
	}
	return changed, nil
}

// StartAutoUpdate 启动后台自动更新协程：启动后立即拉取一次最新远程脚本及远程白名单，随后按 UpdateInterval 周期自动更新。
func (m *AdScriptManager) StartAutoUpdate(ctx context.Context) {
	if m == nil {
		return
	}
	logger.SafeGo("AdScript-AutoUpdate", func() {
		if _, err := m.RefreshOnce(); err != nil {
			log.Printf("[AdScript] Initial remote fetch skipped (%v); using %s script (version=%s, whitelist=%d)",
				err, m.Source(), m.VersionHash(), len(m.Whitelist()))
		}

		ticker := time.NewTicker(m.updateInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				_, _ = m.RefreshOnce()
			}
		}
	})
}

// Stop 停止后台自动更新协程。
func (m *AdScriptManager) Stop() {
	if m == nil {
		return
	}
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// InjectIntoHTML 调用 InjectIntoHTMLForHost。
func (m *AdScriptManager) InjectIntoHTML(htmlBody []byte) []byte {
	return m.InjectIntoHTMLForHost(htmlBody)
}

// InjectIntoHTMLForHost 对黄网（命中远程白名单 或 HTML 中出现成人网站广告）执行：
//  1. 去掉原有广告（服务端剥离第三方广告外链 + 客户端脚本隐藏/移除广告节点）；
//  2. 加上自己广告（注入顶部可关闭的自有推广横幅）。
// 非黄网页面保持原样不修改。
func (m *AdScriptManager) InjectIntoHTMLForHost(htmlBody []byte, hosts ...string) []byte {
	if m == nil || !m.Enabled() || len(htmlBody) == 0 {
		return htmlBody
	}
	if !looksLikeHTMLDocument(htmlBody) {
		return htmlBody
	}
	if bytes.Contains(htmlBody, []byte(`id="ech-proxy-ad-script"`)) {
		return htmlBody
	}

	// 判定是否为黄网：1. 命中远程白名单（白名单 = 黄网） 2. HTML 中包含成人网站广告
	hasAdultAd := ContainsAdultAdInHTML(htmlBody)
	whitelisted := m.IsWhitelisted(hosts...)
	isAdult, adultReason := m.IsAdultWebsite(htmlBody, hosts...)
	if !isAdult {
		// 默认白名单模式下（若非 all 模式且无主机上下文时仅当 allMode 才注入脚本），非黄网不修改
		if !m.AllMode() {
			return htmlBody
		}
	}

	script := m.ScriptBytes()
	if len(script) == 0 {
		return htmlBody
	}
	ver := m.VersionHash()
	whitelistJSON, _ := json.Marshal(m.Whitelist())

	upstreamHost := ""
	for _, h := range hosts {
		if nh := normalizeDomainEntry(h); nh != "" {
			upstreamHost = nh
		}
	}

	cleaned := htmlBody
	if isAdult {
		cleaned = stripBlockedURLs(htmlBody, DefaultAdNetworkBlockedURLs)
	}

	whitelistedStr := "0"
	if whitelisted {
		whitelistedStr = "1"
	}
	isAdultStr := "0"
	if isAdult {
		isAdultStr = "1"
	}
	hasAdultAdStr := "0"
	if hasAdultAd {
		hasAdultAdStr = "1"
	}

	var tag bytes.Buffer
	tag.WriteString(`<script id="ech-proxy-ad-script" data-ech-proxy="ad-script" data-version="`)
	tag.WriteString(html.EscapeString(ver))
	tag.WriteString(`" data-whitelisted="`)
	tag.WriteString(whitelistedStr)
	tag.WriteString(`" data-is-adult="`)
	tag.WriteString(isAdultStr)
	tag.WriteString(`" data-has-adult-ad="`)
	tag.WriteString(hasAdultAdStr)
	tag.WriteString(`" data-adult-reason="`)
	tag.WriteString(html.EscapeString(adultReason))
	tag.WriteString(`" data-upstream-host="`)
	tag.WriteString(html.EscapeString(upstreamHost))
	tag.WriteString(`" data-whitelist="`)
	tag.WriteString(html.EscapeString(string(whitelistJSON)))
	tag.WriteString(`">`)
	tag.Write(script)
	tag.WriteString(`</script>`)
	injectedTag := tag.Bytes()

	lower := bytes.ToLower(cleaned)
	if idx := bytes.Index(lower, []byte("</head>")); idx >= 0 {
		out := make([]byte, 0, len(cleaned)+len(injectedTag))
		out = append(out, cleaned[:idx]...)
		out = append(out, injectedTag...)
		out = append(out, cleaned[idx:]...)
		return out
	}
	if idx := bytes.Index(lower, []byte("</body>")); idx >= 0 {
		out := make([]byte, 0, len(cleaned)+len(injectedTag))
		out = append(out, cleaned[:idx]...)
		out = append(out, injectedTag...)
		out = append(out, cleaned[idx:]...)
		return out
	}
	return append(cleaned, injectedTag...)
}

func looksLikeHTMLDocument(b []byte) bool {
	sample := b
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	lower := bytes.ToLower(sample)
	return bytes.Contains(lower, []byte("<html")) ||
		bytes.Contains(lower, []byte("<!doctype html")) ||
		bytes.Contains(lower, []byte("<head")) ||
		bytes.Contains(lower, []byte("<body"))
}
