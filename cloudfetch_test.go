package cloudfetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// stubWait replaces the challenge wait for the test; nil returns at once.
func stubWait(t *testing.T, f func(context.Context, time.Duration) error) {
	t.Helper()
	if f == nil {
		f = func(context.Context, time.Duration) error { return nil }
	}
	realWait := wait
	wait = f
	t.Cleanup(func() { wait = realWait })
}

// serveChallenge writes a Cloudflare challenge response with the given page.
func serveChallenge(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Server", "cloudflare")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, page)
}

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
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

func TestHeadersMatchBrowser(t *testing.T) {
	tests := []struct {
		browser    Browser
		uaToken    string // ties the User-Agent to the TLS fingerprint's version
		clientHint bool   // Chromium 89+ sends sec-ch-ua
	}{
		{Chrome, "Chrome/" + Chrome.hello.Version + ".", true},
		{Firefox, "Firefox/" + Firefox.hello.Version + ".", false},
		{Safari, "Version/" + Safari.hello.Version + " ", false},
		{Edge, "Edg/" + Edge.hello.Version + ".", false},
	}
	for _, tt := range tests {
		t.Run(tt.browser.hello.Client, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			New(WithBrowser(tt.browser)).setHeaders(req)

			if ua := req.Header.Get("User-Agent"); !strings.Contains(ua, tt.uaToken) {
				t.Errorf("User-Agent = %q, want it to contain %q", ua, tt.uaToken)
			}
			if got := req.Header.Get("sec-ch-ua") != ""; got != tt.clientHint {
				t.Errorf("sec-ch-ua sent = %v, want %v", got, tt.clientHint)
			}
			for _, enc := range strings.Split(req.Header.Get("Accept-Encoding"), ", ") {
				r, _ := newTestResponse(enc, compress(t, enc, []byte("ok")))
				if text, err := r.Text(); err != nil || text != "ok" {
					t.Errorf("advertised encoding %q not decoded: %q, %v", enc, text, err)
				}
			}
		})
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

	if !strings.Contains(ua, "Chrome/"+Chrome.hello.Version+".") {
		t.Errorf("User-Agent = %q, want Chrome %s", ua, Chrome.hello.Version)
	}
}

func TestDo_HeaderPrecedence(t *testing.T) {
	var got http.Header
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}), WithHeader("X-Test", "client"), WithHeader("Accept-Language", "fr"))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test", "request")

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	checks := map[string]string{
		"X-Test":          "request", // request beats WithHeader
		"Accept-Language": "fr",      // WithHeader beats the browser default
		"Sec-Fetch-Mode":  "navigate",
	}
	for k, want := range checks {
		if v := got.Get(k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}
	if len(req.Header) != 1 {
		t.Errorf("Do modified the caller's request headers: %v", req.Header)
	}
}

func TestDo_MaxRetries(t *testing.T) {
	stubWait(t, nil)

	for _, retries := range []int{0, 2} {
		t.Run(strconv.Itoa(retries), func(t *testing.T) {
			var submits atomic.Int32
			c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					submits.Add(1)
					return
				}
				serveChallenge(w, http.StatusServiceUnavailable, iuamPage) // never accepts the answer
			}), WithMaxRetries(retries))

			if _, err := c.Get(srv.URL); !errors.Is(err, ErrChallengeFailed) {
				t.Fatalf("err = %v, want ErrChallengeFailed", err)
			}
			if n := submits.Load(); n != int32(retries) {
				t.Errorf("submitted %d answers, want %d", n, retries)
			}
		})
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
	tests := map[string]struct {
		body string
		want error
	}{
		"managed": {managedPage, ErrManagedChallenge},
		"captcha": {captchaPage, ErrCaptcha},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serveChallenge(w, http.StatusForbidden, tt.body)
			}))

			if _, err := c.Get(srv.URL); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDo_SolvesIUAM(t *testing.T) {
	var slept time.Duration
	stubWait(t, func(_ context.Context, d time.Duration) error {
		slept = d
		return nil
	})

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
			serveChallenge(w, http.StatusServiceUnavailable, iuamPage)
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

func TestDo_PostResendsBodyAfterChallenge(t *testing.T) {
	stubWait(t, nil)

	var bodies []string
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdn-cgi/l/chk_jschl" {
			http.SetCookie(w, &http.Cookie{Name: "cf_clearance", Value: "ok", Path: "/"})
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if !hasCookie(r, "cf_clearance") {
			serveChallenge(w, http.StatusServiceUnavailable, iuamPage)
		}
	}))

	resp, err := c.Post(srv.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	if want := []string{"payload", "payload"}; !slices.Equal(bodies, want) {
		t.Errorf("request bodies = %q, want %q", bodies, want)
	}
}

func TestDo_CancelsChallengeWait(t *testing.T) {
	var submitted bool
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			submitted = true
		}
		serveChallenge(w, http.StatusServiceUnavailable, iuamPage) // asks for a 4s wait
	}))

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = c.Do(req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Do returned after %v, want it to stop at the deadline", elapsed)
	}
	if submitted {
		t.Error("challenge answer was submitted after the deadline")
	}
}
