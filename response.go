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

// Response is an HTTP response from a Client. Text and Bytes return the
// decompressed body and can be called repeatedly; Body is raw. Use them for
// Cloudflare 403/429/503 responses, whose body the Client has already read.
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
