package cloudfetch

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

// newTestClient returns a Client whose requests go to a local TLS test server
// instead of through the uTLS transport.
func newTestClient(t *testing.T, h http.Handler, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	c := New(opts...)
	c.Underlying().Transport = srv.Client().Transport
	return c, srv
}

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

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}

func TestResponseDecode(t *testing.T) {
	want := strings.Repeat("hello cloudfetch ", 100)

	for _, enc := range []string{"", "gzip", "br", "deflate", "GZIP"} {
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

func TestSetHeaders(t *testing.T) {
	c := New(WithHeader("User-Agent", "custom-agent"), WithHeader("X-Test", "1"))
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("Accept", "application/json")

	c.setHeaders(req)

	checks := map[string]string{
		"Accept":          "application/json", // preset by caller, kept
		"User-Agent":      "custom-agent",     // WithHeader overrides defaults
		"X-Test":          "1",
		"Accept-Language": "en-US,en;q=0.9",
		"Sec-Fetch-Mode":  "navigate",
	}
	for k, want := range checks {
		if got := req.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestDo_SendsHeaders(t *testing.T) {
	var ua string
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
	}))

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if ua != defaultUA {
		t.Errorf("User-Agent = %q, want %q", ua, defaultUA)
	}
}

func TestDo_PersistsCookies(t *testing.T) {
	var sawCookie bool
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCookie = sawCookie || hasCookie(r, "session")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
	}))

	for range 2 {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		resp.Body.Close()
	}

	if !sawCookie {
		t.Error("cookie was not sent on the second request")
	}
	if cookies := c.Cookies(srv.URL); len(cookies) != 1 || cookies[0].Value != "abc" {
		t.Errorf("Cookies = %v, want session=abc", cookies)
	}
}

func TestDo_ErrorStatusWithoutChallenge(t *testing.T) {
	var hits int
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "forbidden")
	}))

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if text, _ := resp.Text(); text != "forbidden" {
		t.Errorf("body = %q, want %q", text, "forbidden")
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1", hits)
	}
}

func TestDo_UnsolvableChallenges(t *testing.T) {
	for name, body := range map[string]string{"managed": managedPage, "captcha": captchaPage} {
		t.Run(name, func(t *testing.T) {
			c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "cloudflare")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, body)
			}))

			if _, err := c.Get(srv.URL); err == nil {
				t.Fatal("expected error for unsolvable challenge")
			}
		})
	}
}

func TestDo_SolvesIUAM(t *testing.T) {
	var slept time.Duration
	sleep = func(d time.Duration) { slept = d }
	t.Cleanup(func() { sleep = time.Sleep })

	var form url.Values
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/cdn-cgi/l/chk_jschl":
			_ = r.ParseForm()
			form = r.PostForm
			http.SetCookie(w, &http.Cookie{Name: "cf_clearance", Value: "ok", Path: "/"})
		case hasCookie(r, "cf_clearance"):
			_, _ = io.WriteString(w, "content")
		default:
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, iuamPage)
		}
	}))
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if text, _ := resp.Text(); text != "content" {
		t.Errorf("body = %q, want %q", text, "content")
	}
	if slept != 4*time.Second {
		t.Errorf("waited %v before submitting, want 4s from the page", slept)
	}

	wantForm := map[string]string{
		"r":            "r-token",
		"jschl_vc":     "vc-token",
		"pass":         "pass-token",
		"jschl_answer": strconv.Itoa(22+len(u.Host)) + ".0000000000",
	}
	for k, want := range wantForm {
		if got := form.Get(k); got != want {
			t.Errorf("form %s = %q, want %q", k, got, want)
		}
	}
}
