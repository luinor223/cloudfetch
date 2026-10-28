package cloudfetch

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error {
	c.closed = true
	return nil
}

func newTestResponse(encoding string, body []byte) (*Response, *closeTracker) {
	ct := &closeTracker{Reader: bytes.NewReader(body)}
	return &Response{Response: &http.Response{
		Header: http.Header{"Content-Encoding": {encoding}},
		Body:   ct,
	}}, ct
}

func compress(t *testing.T, encoding string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	case "deflate":
		fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		w = fw
	case "zstd":
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatal(err)
		}
		w = zw
	default:
		return data
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestResponseDecode(t *testing.T) {
	want := strings.Repeat("hello cloudfetch ", 100)

	for _, enc := range []string{"", "gzip", "br", "deflate", "zstd", "GZIP"} {
		t.Run("encoding="+enc, func(t *testing.T) {
			r, body := newTestResponse(enc, compress(t, strings.ToLower(enc), []byte(want)))

			got, err := r.Text()
			if err != nil {
				t.Fatalf("Text: %v", err)
			}
			if got != want {
				t.Errorf("Text = %q, want %q", got, want)
			}
			if !body.closed {
				t.Error("body was not closed")
			}

			// Second read is served from the cache.
			b, err := r.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if string(b) != want {
				t.Error("cached Bytes differ from Text")
			}
		})
	}

	t.Run("invalid gzip", func(t *testing.T) {
		r, body := newTestResponse("gzip", []byte("not gzip"))
		if _, err := r.Text(); err == nil {
			t.Fatal("expected error for invalid gzip body")
		}
		if !body.closed {
			t.Error("body was not closed")
		}
	})
}
