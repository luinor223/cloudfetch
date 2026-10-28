package cloudfetch

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
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

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
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
		id         utls.ClientHelloID
		uaToken    string // ties the User-Agent to the uTLS preset's version
		clientHint bool   // Chromium 89+ sends sec-ch-ua
	}{
		{Chrome, "Chrome/" + Chrome.Version + ".", true},
		{Firefox, "Firefox/" + Firefox.Version + ".", false},
		{Safari, "Version/" + Safari.Version + " ", false},
		{Edge, "Edg/" + Edge.Version + ".", false},
		{utls.HelloRandomized, "Chrome/" + Chrome.Version + ".", true},
	}
	for _, tt := range tests {
		t.Run(tt.id.Client, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			New(WithBrowser(tt.id)).setHeaders(req)

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

	if !strings.Contains(ua, "Chrome/"+Chrome.Version+".") {
		t.Errorf("User-Agent = %q, want Chrome %s", ua, Chrome.Version)
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
	realWait := wait
	wait = func(_ context.Context, d time.Duration) error {
		slept = d
		return nil
	}
	t.Cleanup(func() { wait = realWait })

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

func TestDo_PostResendsBodyAfterChallenge(t *testing.T) {
	realWait := wait
	wait = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { wait = realWait })

	var bodies []string
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cdn-cgi/l/chk_jschl" {
			http.SetCookie(w, &http.Cookie{Name: "cf_clearance", Value: "ok", Path: "/"})
			return
		}
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if !hasCookie(r, "cf_clearance") {
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, iuamPage)
		}
	}))

	resp, err := c.Post(srv.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	if want := []string{"payload", "payload"}; !slices.Equal(bodies, want) {
		t.Errorf("request bodies = %q, want %q", bodies, want)
	}
}

func TestDoContext_CancelsChallengeWait(t *testing.T) {
	var submitted bool
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			submitted = true
		}
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, iuamPage) // asks for a 4s wait
	}))

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.DoContext(ctx, http.MethodGet, srv.URL, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("DoContext returned after %v, want it to stop at the deadline", elapsed)
	}
	if submitted {
		t.Error("challenge answer was submitted after the deadline")
	}
}

// newUTLSTestClient returns a Client that dials a local TLS test server
// through the real uTLS transport.
func newUTLSTestClient(t *testing.T, h http.Handler, enableHTTP2 bool, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = enableHTTP2
	srv.StartTLS()
	t.Cleanup(srv.Close)

	c := New(opts...)
	c.rootCAs = x509.NewCertPool()
	c.rootCAs.AddCert(srv.Certificate())
	return c, srv
}

func TestTransport_UTLS(t *testing.T) {
	tests := []struct {
		name       string
		http2      bool
		browser    utls.ClientHelloID
		wantProto  int
		wantConns  int // TLS connections for two requests
		wantGREASE bool
	}{
		{"chrome h2", true, Chrome, 2, 1, true},
		{"chrome h1", false, Chrome, 1, 2, true},
		{"firefox h2", true, Firefox, 2, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var protos []int
			c, srv := newUTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protos = append(protos, r.ProtoMajor)
				_, _ = io.WriteString(w, "ok")
			}), tt.http2, WithBrowser(tt.browser))

			var mu sync.Mutex
			var hellos []*tls.ClientHelloInfo
			srv.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				mu.Lock()
				hellos = append(hellos, hello)
				mu.Unlock()
				return nil, nil
			}

			for range 2 {
				resp, err := c.Get(srv.URL)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				if text, _ := resp.Text(); text != "ok" {
					t.Errorf("body = %q, want %q", text, "ok")
				}
			}

			for _, p := range protos {
				if p != tt.wantProto {
					t.Errorf("request used HTTP/%d, want HTTP/%d", p, tt.wantProto)
				}
			}

			mu.Lock()
			defer mu.Unlock()
			if len(hellos) != tt.wantConns {
				t.Fatalf("got %d TLS handshakes, want %d", len(hellos), tt.wantConns)
			}
			hello := hellos[0]
			if !slices.Contains(hello.SupportedProtos, "h2") {
				t.Errorf("ALPN = %v, want h2 offered", hello.SupportedProtos)
			}
			if got := slices.ContainsFunc(hello.CipherSuites, isGREASE); got != tt.wantGREASE {
				t.Errorf("GREASE cipher suite offered = %v, want %v", got, tt.wantGREASE)
			}
		})
	}
}

// isGREASE reports whether v is a GREASE value (RFC 8701), which Chrome
// sends and Go's crypto/tls does not.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func TestTransport_UntrustedCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failure
	srv.StartTLS()
	t.Cleanup(srv.Close)

	if _, err := New().Get(srv.URL); err == nil {
		t.Fatal("expected certificate verification error")
	}
}

// newConnectProxy starts an HTTP CONNECT proxy that requires wantAuth as the
// Proxy-Authorization header (if non-empty) and counts opened tunnels.
func newConnectProxy(t *testing.T, wantAuth string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var tunnels atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if wantAuth != "" && r.Header.Get("Proxy-Authorization") != wantAuth {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			target.Close()
			return
		}
		tunnels.Add(1)
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() {
			_, _ = io.Copy(target, client)
			target.Close()
		}()
		go func() {
			_, _ = io.Copy(client, target)
			client.Close()
		}()
	}))
	t.Cleanup(srv.Close)
	return srv, &tunnels
}

func TestTransport_Proxy(t *testing.T) {
	proxy, tunnels := newConnectProxy(t, "Basic dXNlcjpwYXNz") // user:pass
	proxyURL := strings.Replace(proxy.URL, "http://", "http://user:pass@", 1)

	c, srv := newUTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), true, WithProxy(proxyURL))

	for range 2 {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if text, _ := resp.Text(); text != "ok" {
			t.Errorf("body = %q, want %q", text, "ok")
		}
	}
	if n := tunnels.Load(); n != 1 {
		t.Errorf("proxy opened %d tunnels, want 1 (h2 connection reused)", n)
	}
}

func TestTransport_ProxyErrors(t *testing.T) {
	proxy, _ := newConnectProxy(t, "Basic dXNlcjpwYXNz")

	tests := []struct {
		name     string
		proxyURL string
		wantErr  string
	}{
		{"auth rejected", proxy.URL, "407 Proxy Authentication Required"},
		{"unsupported scheme", "socks5://127.0.0.1:1080", `unsupported proxy scheme "socks5"`},
		{"unreachable proxy", "http://127.0.0.1:1", "dial proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, srv := newUTLSTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false, WithProxy(tt.proxyURL))
			_, err := c.Get(srv.URL)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
