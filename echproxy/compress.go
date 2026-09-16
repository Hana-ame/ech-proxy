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
