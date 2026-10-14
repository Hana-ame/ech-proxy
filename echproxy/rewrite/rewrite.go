package rewrite

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Hana-ame/ech-proxy/echproxy/config"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// MaxRewriteSize 是执行文本解压与内容替换的最大响应体积上限（8 MB）。
const MaxRewriteSize = 8 << 20

// IsTextContent 判断 Content-Type 是否属于可重写文本类型。
func IsTextContent(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "x-www-form-urlencoded")
}

// DecompressBody 按 Content-Encoding（gzip / br / zstd）解压响应体。
func DecompressBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readLimited(r)
	case "br":
		return readLimited(brotli.NewReader(bytes.NewReader(body)))
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readLimited(r)
	default:
		return body, nil
	}
}

func readLimited(r io.Reader) ([]byte, error) {
	const limit = MaxRewriteSize + 1
	out, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) >= limit {
		return nil, fmt.Errorf("decompressed body exceeds %d bytes", limit)
	}
	return out, nil
}

// CompressBody 若原响应为 gzip 且客户端支持 gzip，则将改写后的正文重新压缩为 gzip。
func CompressBody(body []byte, origEncoding, acceptEncoding string) ([]byte, string) {
	if !strings.EqualFold(origEncoding, "gzip") || !acceptsGzip(acceptEncoding) {
		return body, ""
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(body); err != nil {
		return body, ""
	}
	if err := w.Close(); err != nil {
		return body, ""
	}
	return buf.Bytes(), "gzip"
}

func acceptsGzip(ae string) bool {
	for _, p := range strings.Split(ae, ",") {
		p = strings.TrimSpace(p)
		if p == "gzip" || strings.HasPrefix(p, "gzip;") {
			return true
		}
	}
	return false
}

// BuildEntryRewriter 根据单条上游配置与全局屏蔽列表构建响应正文重写函数。
func BuildEntryRewriter(uc config.UpstreamConfig, blocked []string) func([]byte, string) []byte {
	rules := make(map[string]string, len(uc.Rewrites)+3)
	for k, v := range uc.Rewrites {
		rules[k] = v
	}
	if w := uc.Wildcard; w != nil && (w.Prefix != "" || w.EntrySuffix != w.UpstreamSuffix) {
		rules["*"+w.UpstreamSuffix] = w.Prefix + "*" + w.EntrySuffix
		base := strings.TrimSuffix(w.Prefix, "-")
		bare := strings.TrimPrefix(w.UpstreamSuffix, ".")
		rules[bare] = base + w.EntrySuffix
		rules["."+bare] = base + w.EntrySuffix
	}
	domainRewriter := buildDomainRewriter(rules)
	config.CompileBodyReplace(uc.BodyReplace)

	return func(body []byte, port string) []byte {
		body = stripBlockedURLs(body, blocked)
		body = domainRewriter(body, port)
		if len(uc.BodyReplace) > 0 {
			body = applyBodyReplace(body, uc.BodyReplace)
		}
		return body
	}
}

func applyBodyReplace(body []byte, rules []config.BodyReplaceRule) []byte {
	for _, r := range rules {
		if r.Old == "" {
			continue
		}
		if r.Regex {
			if r.Compiled != nil {
				body = r.Compiled.ReplaceAll(body, []byte(r.New))
			}
			continue
		}
		if bytes.Contains(body, []byte(r.Old)) {
			body = bytes.ReplaceAll(body, []byte(r.Old), []byte(r.New))
		} else if r.Compiled != nil {
			body = r.Compiled.ReplaceAll(body, []byte(r.New))
		}
	}
	return body
}

func stripBlockedURLs(body []byte, blocked []string) []byte {
	out := body
	for _, b := range blocked {
		out = stripOneBlockedURL(out, []byte(b))
		if strings.HasPrefix(b, "https://") {
			out = stripOneBlockedURL(out, []byte("//"+b[len("https://"):]))
		}
	}
	return out
}

func stripOneBlockedURL(body, blocked []byte) []byte {
	var out []byte
	rest := body
	for {
		i := bytes.Index(rest, blocked)
		if i < 0 {
			out = append(out, rest...)
			break
		}
		j := i + len(blocked)
		for j < len(rest) {
			c := rest[j]
			if c == '"' || c == '\'' || c == ')' || c == '`' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '<' || c == '>' {
				break
			}
			j++
		}
		out = append(out, rest[:i]...)
		rest = rest[j:]
	}
	return out
}

func buildDomainRewriter(rt map[string]string) func([]byte, string) []byte {
	var exact, wildcard []string
	for k := range rt {
		if strings.HasPrefix(k, "*.") {
			wildcard = append(wildcard, k)
		} else {
			exact = append(exact, k)
		}
	}
	sort.Slice(exact, func(i, j int) bool { return len(exact[i]) > len(exact[j]) })
	sort.Slice(wildcard, func(i, j int) bool { return len(wildcard[i]) > len(wildcard[j]) })
	keys := append(exact, wildcard...)

	return func(body []byte, port string) []byte {
		for _, k := range keys {
			target := rt[k]
			if port != "" && !strings.HasPrefix(k, ".") && !strings.Contains(target, ":") {
				target += ":" + port
			}
			if strings.HasPrefix(k, "*.") {
				body = replaceWildcardDomain(body, k[2:], target)
			} else {
				body = replaceDomainBounded(body, k, target)
			}
		}
		return body
	}
}

func replaceWildcardDomain(body []byte, suffix, target string) []byte {
	var out []byte
	rest := body
	for {
		i := bytes.Index(rest, []byte(suffix))
		if i < 0 {
			out = append(out, rest...)
			break
		}
		start := i
		for start > 0 && isDomainChar(rest[start-1]) {
			if start >= 3 && rest[start-3] == '%' && isHexDigit(rest[start-2]) && isHexDigit(rest[start-1]) {
				break
			}
			start--
		}
		sub := strings.TrimSuffix(string(rest[start:i]), ".")
		if sub == "" {
			out = append(out, rest[:i+len(suffix)]...)
			rest = rest[i+len(suffix):]
			continue
		}
		var left, right byte
		if start > 0 {
			left = rest[start-1]
		}
		j := i + len(suffix)
		if j < len(rest) {
			right = rest[j]
		}
		leftOK := !isDomainChar(left) || (start >= 3 && rest[start-3] == '%' && isHexDigit(rest[start-2]) && isHexDigit(left))
		if leftOK && !isDomainChar(right) {
			out = append(out, rest[:start]...)
			out = append(out, strings.ReplaceAll(target, "*", sub)...)
		} else {
			out = append(out, rest[:j]...)
		}
		rest = rest[j:]
	}
	return out
}

func replaceDomainBounded(body []byte, from, to string) []byte {
	fromB, toB := []byte(from), []byte(to)
	var out []byte
	rest := body
	for {
		i := bytes.Index(rest, fromB)
		if i < 0 {
			out = append(out, rest...)
			break
		}
		var left, right byte
		if i > 0 {
			left = rest[i-1]
		}
		j := i + len(fromB)
		if j < len(rest) {
			right = rest[j]
		}
		leftOK := !isDomainChar(left) || (i >= 3 && rest[i-3] == '%' && isHexDigit(rest[i-2]) && isHexDigit(left))
		if leftOK && !isDomainChar(right) {
			out = append(out, rest[:i]...)
			out = append(out, toB...)
		} else {
			out = append(out, rest[:j]...)
		}
		rest = rest[j:]
	}
	return out
}

func isDomainChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
