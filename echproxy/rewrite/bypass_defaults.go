package rewrite

// DefaultSensitiveBypassDomains 是内置的高敏感域名默认绕过清单（网银、支付、密码管理器、系统更新与证书吊销/核心登录）。
// 即使远端 bypass.txt 不可达或本地 bypass.txt 仅包含自定义域名，这些高敏感域名也始终跳过本地 CA MITM，
// 避免在 -all 全代理模式下对金融、密码库与系统信任链流量执行本地解密重签。
var DefaultSensitiveBypassDomains = []string{
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
	// 支付与钱包（Payment）
	"alipay.com",
	"alipayobjects.com",
	"tenpay.com",
	"pay.weixin.qq.com",
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
	// 操作系统更新与证书吊销/信任服务（OS Updates & System Trust）
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
	"crl.microsoft.com",
	"ocsp.digicert.com",
	"ocsp.pki.goog",
	// 核心账号登录与强证书校验域名（Core Auth）
	"login.microsoftonline.com",
	"login.live.com",
	"appleid.apple.com",
	"idmsa.apple.com",
}

// MergeWithDefaultSensitiveBypass 将用户/远端 bypass.txt 列表与内置高敏感绕过域名合并去重。
func MergeWithDefaultSensitiveBypass(domains []string) []string {
	merged := make([]string, 0, len(DefaultSensitiveBypassDomains)+len(domains))
	merged = append(merged, DefaultSensitiveBypassDomains...)
	merged = append(merged, domains...)
	return normalizeDomainSlice(merged)
}
