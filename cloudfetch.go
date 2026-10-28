// Package cloudfetch provides an HTTP client that bypasses Cloudflare bot
// detection by mimicking a real browser's TLS fingerprint and headers.
//
// It uses uTLS to reproduce a browser's TLS Client Hello (JA3/JA4
// fingerprint), sends that browser's default headers, keeps a cookie jar
// across requests, and solves Cloudflare's classic IUAM JS challenge.
package cloudfetch

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Option configures a Client.
type Option func(*Client)

// WithBrowser sets the browser to impersonate: its TLS fingerprint and its
// default headers. Defaults to Chrome.
func WithBrowser(b Browser) Option {
	return func(c *Client) { c.browser = b }
}

// WithTimeout sets the HTTP client timeout. Defaults to 30s.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithProxy routes connections through an HTTP proxy, given as
// "http://[user:pass@]host:port", using CONNECT tunnels. The TLS handshake
// with the target still happens end to end, so the fingerprint is unchanged.
func WithProxy(proxyURL string) Option {
	return func(c *Client) { c.proxyURL = proxyURL }
}

// WithHeader adds a header sent with every request. It overrides the
// browser's default for the same header, and is overridden by headers set on
// the request itself.
func WithHeader(key, value string) Option {
	return func(c *Client) { c.extraHeaders[key] = value }
}

// WithMaxRetries sets how many times to solve a challenge for one request
// before giving up with ErrChallengeFailed. Defaults to 3; 0 disables solving.
func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

// Client is an HTTP client with browser TLS fingerprinting. It is safe for
// concurrent use.
type Client struct {
	browser      Browser
	timeout      time.Duration
	maxRetries   int
	proxyURL     string
	extraHeaders map[string]string
	jar          http.CookieJar
	httpClient   *http.Client
	once         sync.Once

	// rootCAs overrides the system roots for certificate verification (tests).
	rootCAs *x509.CertPool
}

// New creates a new Client with the given options.
func New(opts ...Option) *Client {
	c := &Client{
		browser:      Chrome,
		timeout:      30 * time.Second,
		maxRetries:   3,
		extraHeaders: make(map[string]string),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Client) init() {
	c.once.Do(func() {
		jar, _ := cookiejar.New(nil)
		c.jar = jar

		c.httpClient = &http.Client{
			Jar:       jar,
			Timeout:   c.timeout,
			Transport: &utlsTransport{client: c},
		}
	})
}

// utlsTransport dials with uTLS and dispatches to h1 or h2 based on ALPN.
type utlsTransport struct {
	client *Client

	mu      sync.Mutex
	h2Conns map[string]*http2.ClientConn //nolint:staticcheck
}

func (t *utlsTransport) dialUTLS(ctx context.Context, network, addr string) (*utls.UConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	conn, err := t.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName: host,
		RootCAs:    t.client.rootCAs,
	}, t.client.browser.hello)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return tlsConn, nil
}

// dial opens a TCP connection to addr, tunneling through the proxy if set.
func (t *utlsTransport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if t.client.proxyURL == "" {
		return dialer.DialContext(ctx, network, addr)
	}

	proxy, err := url.Parse(t.client.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	if proxy.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme %q: only http is supported", proxy.Scheme)
	}
	proxyAddr := proxy.Host
	if proxy.Port() == "" {
		proxyAddr = net.JoinHostPort(proxy.Hostname(), "80")
	}

	conn, err := dialer.DialContext(ctx, network, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if err := connectTunnel(ctx, conn, proxy, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// connectTunnel asks the proxy on conn to open a tunnel to addr.
func connectTunnel(ctx context.Context, conn net.Conn, proxy *url.URL, addr string) error {
	// Unblock the CONNECT exchange if ctx ends first.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if u := proxy.User; u != nil {
		pass, _ := u.Password()
		creds := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+creds)
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("proxy CONNECT: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("proxy CONNECT: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy CONNECT: %s", resp.Status)
	}
	return nil
}

func (t *utlsTransport) getH2Conn(addr string, tlsConn net.Conn) (*http2.ClientConn, error) { //nolint:staticcheck
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.h2Conns == nil {
		t.h2Conns = make(map[string]*http2.ClientConn) //nolint:staticcheck
	}

	if cc, ok := t.h2Conns[addr]; ok {
		if cc.CanTakeNewRequest() {
			return cc, nil
		}
		delete(t.h2Conns, addr)
	}

	h2t := &http2.Transport{ //nolint:staticcheck
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return t.dialUTLS(ctx, network, addr)
		},
	}

	cc, err := h2t.NewClientConn(tlsConn) //nolint:staticcheck
	if err != nil {
		return nil, err
	}

	t.h2Conns[addr] = cc
	return cc, nil
}

func (t *utlsTransport) cachedH2(addr string) *http2.ClientConn { //nolint:staticcheck
	t.mu.Lock()
	defer t.mu.Unlock()
	if cc, ok := t.h2Conns[addr]; ok && cc.CanTakeNewRequest() {
		return cc
	}
	return nil
}

// CloseIdleConnections closes cached HTTP/2 connections with no requests in
// progress. http.Client.CloseIdleConnections calls it.
func (t *utlsTransport) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for addr, cc := range t.h2Conns {
		if cc.State().StreamsActive == 0 {
			cc.Close()
			delete(t.h2Conns, addr)
		}
	}
}

func (t *utlsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	if cc := t.cachedH2(addr); cc != nil {
		return cc.RoundTrip(req)
	}

	tlsConn, err := t.dialUTLS(req.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		cc, err := t.getH2Conn(addr, tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("h2 client conn: %w", err)
		}
		return cc.RoundTrip(req)
	}

	// HTTP/1.1 fallback: wrap the pre-dialed conn in a one-shot transport.
	h1 := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
		DisableKeepAlives: true,
	}
	resp, err := h1.RoundTrip(req)
	h1.CloseIdleConnections()
	return resp, err
}

// setHeaders fills in headers req doesn't set: WithHeader headers first, then
// the browser's defaults.
func (c *Client) setHeaders(req *http.Request) {
	for k, v := range c.extraHeaders {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	for _, h := range c.browser.headers {
		if req.Header.Get(h[0]) == "" {
			req.Header.Set(h[0], h[1])
		}
	}
}

// Response is an HTTP response from a Client.
//
// Text and Bytes read the whole body, decompress it according to its
// Content-Encoding, close it, and cache the result, so they can be called
// more than once. Reading Body directly gives the raw, possibly compressed
// bytes instead. For 403, 429 and 503 responses Client has already read the
// body to look for a challenge, so use Text or Bytes for those.
type Response struct {
	*http.Response
	body []byte
}

func (r *Response) decode() ([]byte, error) {
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
	b, err := r.decode()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Bytes returns the response body as bytes, decompressing if needed.
func (r *Response) Bytes() ([]byte, error) {
	return r.decode()
}

// Errors returned by Client when a challenge can't be solved.
var (
	// ErrManagedChallenge means the site served a managed challenge
	// (Turnstile), which needs a real browser.
	ErrManagedChallenge = errors.New("cloudfetch: managed challenge (Turnstile) needs a real browser")

	// ErrCaptcha means the site served a CAPTCHA, which needs an external
	// solving service.
	ErrCaptcha = errors.New("cloudfetch: CAPTCHA challenge needs an external solving service")

	// ErrChallengeFailed means the site still served a JS challenge after the
	// number of attempts set by WithMaxRetries.
	ErrChallengeFailed = errors.New("cloudfetch: challenge not solved")
)

// Get issues a GET request to url.
func (c *Client) Get(url string) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post issues a POST request to url with the given body and Content-Type.
func (c *Client) Post(url, contentType string, body io.Reader) (*Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// Do sends req and returns the response, solving Cloudflare challenges along
// the way. It fills in the headers req doesn't set and leaves req unmodified.
// req's context also bounds the waits before submitting challenge answers.
//
// If a challenge can't be solved, Do returns ErrManagedChallenge, ErrCaptcha
// or ErrChallengeFailed. Otherwise the caller must close the response body,
// directly or by calling Text or Bytes.
func (c *Client) Do(req *http.Request) (*Response, error) {
	c.init()
	ctx := req.Context()

	// Make the body replayable so it can be resent after solving a challenge.
	getBody := req.GetBody
	if getBody == nil && req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}

	var solveErr error
	for attempt := 0; ; attempt++ {
		r := req.Clone(ctx)
		if getBody != nil {
			body, err := getBody()
			if err != nil {
				return nil, err
			}
			r.Body, r.GetBody = body, getBody
		}
		c.setHeaders(r)

		resp, err := c.httpClient.Do(r) //nolint:bodyclose // closed by Response.decode or the caller
		if err != nil {
			return nil, err
		}
		wrapped := &Response{Response: resp}
		if !isChallengeStatus(resp.StatusCode) {
			return wrapped, nil
		}
		text, err := wrapped.Text()
		if err != nil {
			return wrapped, nil
		}

		ct := detectChallenge(resp, text)
		switch ct {
		case noChallenge:
			return wrapped, nil
		case managedChallenge:
			return nil, ErrManagedChallenge
		case captchaChallenge:
			return nil, ErrCaptcha
		}

		if attempt == c.maxRetries {
			if solveErr != nil {
				return nil, fmt.Errorf("%w after %d attempts: %w", ErrChallengeFailed, attempt, solveErr)
			}
			return nil, fmt.Errorf("%w after %d attempts", ErrChallengeFailed, attempt)
		}
		if ct == iuamChallenge {
			solveErr = c.solveIUAM(ctx, text, req.URL)
		} else {
			solveErr = c.solveV2Challenge(ctx, text, req.URL)
		}
		if solveErr != nil && ctx.Err() != nil {
			return nil, solveErr
		}
	}
}

// CloseIdleConnections closes connections kept open by earlier requests that
// are not in use. It does not interrupt requests in progress.
func (c *Client) CloseIdleConnections() {
	c.init()
	c.httpClient.CloseIdleConnections()
}

// Cookies returns the cookies stored for the given URL.
func (c *Client) Cookies(rawURL string) []*http.Cookie {
	c.init()
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return c.jar.Cookies(u)
}

// Underlying returns the *http.Client that sends requests. It keeps the
// browser's TLS fingerprint and the cookie jar, but requests sent through it
// directly get none of the browser's default headers and no challenge solving.
func (c *Client) Underlying() *http.Client {
	c.init()
	return c.httpClient
}
