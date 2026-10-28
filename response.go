package cloudfetch

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Response is an HTTP response from a Client.
//
// Text and Bytes read the whole body, decompress it according to its
// Content-Encoding, close it, and cache the result, so they can be called
// more than once. Reading Body directly gives the raw, possibly compressed
// bytes instead. For Cloudflare 403, 429 and 503 responses Client has already
// read the body to look for a challenge, so use Text or Bytes for those.
type Response struct {
	*http.Response
	body []byte
}

// Bytes returns the response body as bytes, decompressing if needed.
func (r *Response) Bytes() ([]byte, error) {
	if r.body != nil {
		return r.body, nil
	}
	defer r.Body.Close()

	var reader io.Reader = r.Body
	switch strings.ToLower(r.Header.Get("Content-Encoding")) {
	case "br":
		reader = brotli.NewReader(r.Body)
	case "gzip":
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	case "deflate":
		reader = flate.NewReader(r.Body)
	case "zstd":
		zr, err := zstd.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		reader = zr
	}

	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	r.body = b
	return r.body, nil
}

// Text returns the response body as a string, decompressing if needed.
func (r *Response) Text() (string, error) {
	b, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
