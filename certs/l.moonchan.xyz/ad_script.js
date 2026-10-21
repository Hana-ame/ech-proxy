/**
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
