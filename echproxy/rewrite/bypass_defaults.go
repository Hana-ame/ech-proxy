package rewrite

import "sync"

// defaultSensitiveBypassDomains 是内置的高敏感域名默认绕过清单（定长私有数组，防止外部包篡改）。
// 覆盖网银、支付、微信认证（不误伤 mp.weixin.qq.com）、密码管理器、系统更新、成对 OCSP/CRL 信任链及核心账号登录。
var defaultSensitiveBypassDomains = [...]string{
	// 中国主流网银与银联（Banking CN）
	"icbc.com.cn",
	"ccb.com",
	"abchina.com",
	"abchina.com.cn",
	"boc.cn",
	"bankcomm.com",
	"cmbchina.com",
	"psbc.com",
	"pingan.com",
	"spdb.com.cn",
	"cib.com.cn",
	"citicbank.com",
	"cmbc.com.cn",
	"cebbank.com",
	"hxb.com.cn",
	"cgbchina.com.cn",
	"unionpay.com",
	"95516.com",
	// 国际主流银行与券商（Banking Global）
	"chase.com",
	"bankofamerica.com",
	"wellsfargo.com",
	"citi.com",
	"citibank.com",
	"hsbc.com",
	"hsbc.com.hk",
	"hsbc.co.uk",
	"barclays.co.uk",
	"capitalone.com",
	"americanexpress.com",
	"schwab.com",
	"fidelity.com",
	"interactivebrokers.com",
	"wise.com",
	"revolut.com",
	// 支付、钱包与微信认证（Payment & WeChat Auth，保留 mp.weixin.qq.com 正常走代理）
	"alipay.com",
	"alipayobjects.com",
	"tenpay.com",
	"pay.weixin.qq.com",
	"open.weixin.qq.com",
	"login.weixin.qq.com",
	"paypal.com",
	"paypalobjects.com",
	"stripe.com",
	"squareup.com",
	"applepay.apple.com",
	"pay.google.com",
	"adyen.com",
	"braintreegateway.com",
	"checkout.com",
	"visa.com",
	"mastercard.com",
	// 密码管理器与身份认证（Password Managers & Passkeys）
	"1password.com",
	"1password.eu",
	"1password.ca",
	"bitwarden.com",
	"bitwarden.eu",
	"bitwarden.net",
	"keepassxc.org",
	"dashlane.com",
	"lastpass.com",
	"nordpass.com",
	"proton.me",
	"protonpass.me",
	"roboform.com",
	"enpass.io",
	"keepersecurity.com",
	"yubico.com",
	// 操作系统更新与成对 OCSP/CRL 证书信任服务（OS Updates & PKI Trust）
	"windowsupdate.com",
	"update.microsoft.com",
	"download.windowsupdate.com",
	"delivery.mp.microsoft.com",
	"mp.microsoft.com",
	"msftconnecttest.com",
	"ctldl.windowsupdate.com",
	"swscan.apple.com",
	"swdist.apple.com",
	"mesu.apple.com",
	"gdmf.apple.com",
	"xp.apple.com",
	"ocsp.apple.com",
	"ocsp2.apple.com",
	"crl.apple.com",
	"crl.microsoft.com",
	"ocsp.digicert.com",
	"crl.digicert.com",
	"crl3.digicert.com",
	"crl4.digicert.com",
	"ocsp.pki.goog",
	"crl.pki.goog",
	"ocsp.starfieldtech.com",
	"crl.starfieldtech.com",
	"ocsp.verisign.com",
	"crl.verisign.com",
	"ocsp.sectigo.com",
	"crl.sectigo.com",
	"ocsp.usertrust.com",
	"crl.usertrust.com",
	"ocsp.globalsign.com",
	"crl.globalsign.com",
	"ocsp.comodoca.com",
	"crl.comodoca.com",
	"ocsp.entrust.net",
	"crl.entrust.net",
	"ocsp.godaddy.com",
	"crl.godaddy.com",
	"ocsp.r2m01.amazontrust.com",
	"ocsp.sca1b.amazontrust.com",
	// 核心账号登录与 OAuth 强校验域名（Core Auth）
	"accounts.google.com",
	"login.microsoftonline.com",
	"login.live.com",
	"appleid.apple.com",
	"idmsa.apple.com",
}

// defaultSensitiveBypassNormalized 使用 sync.OnceValue 预计算归一化后的只读兜底快照，
// 避免在空表/远端不可达时每次 CONNECT / BypassList() 重复分配和归一化。
var defaultSensitiveBypassNormalized = sync.OnceValue(func() []string {
	return normalizeDomainSlice(defaultSensitiveBypassDomains[:])
})

// DefaultSensitiveBypassDomains 返回内置高敏感绕过域名清单的只读副本。
func DefaultSensitiveBypassDomains() []string {
	return append([]string(nil), defaultSensitiveBypassNormalized()...)
}

// MergeWithDefaultSensitiveBypass 将用户/远端 bypass.txt 列表与内置高敏感绕过域名合并去重。
func MergeWithDefaultSensitiveBypass(domains []string) []string {
	if len(domains) == 0 {
		return append([]string(nil), defaultSensitiveBypassNormalized()...)
	}
	base := defaultSensitiveBypassNormalized()
	merged := make([]string, 0, len(base)+len(domains))
	merged = append(merged, base...)
	merged = append(merged, domains...)
	return normalizeDomainSlice(merged)
}
