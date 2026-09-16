package echproxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const maxRewriteSize = 8 << 20

func isTextContent(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "x-www-form-urlencoded")
}

func readDecompressed(r io.Reader) ([]byte, error) {
	const limit = maxRewriteSize + 1
	out, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) >= limit {
		return nil, fmt.Errorf("decompressed body exceeds %d bytes", limit)
	}
	return out, nil
}

func decompressBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readDecompressed(r)
	case "br":
		return readDecompressed(brotli.NewReader(bytes.NewReader(body)))
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return readDecompressed(r)
	default:
		return body, nil
	}
}

// acceptsGzip reports whether the Accept-Encoding header includes gzip.
func acceptsGzip(acceptEncoding string) bool {
	for _, part := range strings.Split(acceptEncoding, ",") {
		part = strings.TrimSpace(part)
		if part == "gzip" || strings.HasPrefix(part, "gzip;") {
			return true
		}
	}
	return false
}

// compressBody re-compresses a plain body using gzip if gzip was the original encoding
// and the client accepts gzip. Returns the compressed bytes and the encoding name to set,
// or the original body and "" if re-compression is skipped.
func compressBody(body []byte, originalEncoding, acceptEncoding string) ([]byte, string) {
	enc := strings.ToLower(originalEncoding)
	if enc != "gzip" {
		// Only re-compress if the original was gzip; brotli/zstd encoders are complex
		// and rarely worth the overhead for text bodies in a proxy setting.
		return body, ""
	}
	if !acceptsGzip(acceptEncoding) {
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
