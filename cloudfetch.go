// Package cloudfetch is an HTTP client that gets past Cloudflare bot detection
// by sending a real browser's TLS fingerprint and headers. It solves classic
// IUAM challenges itself and hands harder ones to an optional Solver.
package cloudfetch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
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

// WithProxy tunnels connections through an HTTP CONNECT proxy,
// "http://[user:pass@]host:port". The fingerprint is unchanged.
func WithProxy(proxyURL string) Option {
	return func(c *Client) { c.proxyURL = proxyURL }
}

// WithHeader adds a header to every request, over the browser's default but
// under headers set on the request.
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
	solver       Solver
	httpClient   *http.Client

	mu         sync.Mutex // guards clearances and their fields
	clearances map[string]*hostClearance
}

// New creates a new Client with the given options.
func New(opts ...Option) *Client {
	c := &Client{
		browser:      Chrome,
		timeout:      30 * time.Second,
		maxRetries:   3,
		extraHeaders: make(map[string]string),
		clearances:   make(map[string]*hostClearance),
	}
	for _, o := range opts {
		o(c)
	}

	t := &utlsTransport{hello: c.browser.hello}
	if c.proxyURL != "" {
		t.proxy, t.proxyErr = parseProxy(c.proxyURL)
	}
	jar, _ := cookiejar.New(nil)
	c.httpClient = &http.Client{Jar: jar, Timeout: c.timeout, Transport: t}
	return c
}

// Errors returned by Client when a challenge can't be solved.
var (
	// ErrManagedChallenge means a Managed or Interactive Challenge that needs
	// a real browser, and no Solver got past it.
	ErrManagedChallenge = errors.New("cloudfetch: managed challenge (Turnstile) needs a real browser")

	// ErrCaptcha means the site served a CAPTCHA.
	ErrCaptcha = errors.New("cloudfetch: CAPTCHA challenge needs an external solving service")

	// ErrChallengeFailed means a JS challenge wasn't solved within
	// WithMaxRetries attempts or by the Solver.
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

// Do sends req, solving Cloudflare challenges on the way, and fills in headers
// req doesn't set without modifying it. If a challenge can't be solved it
// returns ErrManagedChallenge, ErrCaptcha or ErrChallengeFailed; otherwise the
// caller must close the body, directly or via Text or Bytes.
func (c *Client) Do(req *http.Request) (*Response, error) {
	ctx := req.Context()

	// Make the body replayable so it can be resent after solving a challenge.
	getBody := req.GetBody
	if getBody == nil && (c.maxRetries > 0 || c.solver != nil) && req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		getBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
	}

	var solveErr error
	var solverTried bool
	for jsAttempts := 0; ; {
		r := req.Clone(ctx)
		if getBody != nil {
			body, err := getBody()
			if err != nil {
				return nil, err
			}
			r.Body, r.GetBody = body, getBody
		}
		c.setHeaders(r)

		sent := time.Now()
		resp, err := c.httpClient.Do(r) //nolint:bodyclose // closed by Response.Bytes or the caller
		if err != nil {
			return nil, err
		}
		wrapped := &Response{Response: resp}
		if !mayBeChallenge(resp) {
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
		case captchaChallenge:
			return nil, ErrCaptcha
		}

		// Solver: managed and v2 at once, IUAM once attempts run out.
		if c.solver != nil && !solverTried && (ct != iuamChallenge || jsAttempts >= c.maxRetries) {
			solverTried = true
			fail := ErrChallengeFailed
			if ct == managedChallenge {
				fail = ErrManagedChallenge
			}
			if err := c.clear(ctx, req.URL, sent, fail); err != nil {
				return nil, err
			}
			continue
		}
		if ct == managedChallenge {
			return nil, ErrManagedChallenge
		}

		if jsAttempts >= c.maxRetries {
			if solveErr != nil {
				return nil, fmt.Errorf("%w after %d attempts: %w", ErrChallengeFailed, jsAttempts, solveErr)
			}
			return nil, fmt.Errorf("%w after %d attempts", ErrChallengeFailed, jsAttempts)
		}
		jsAttempts++
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
	c.httpClient.CloseIdleConnections()
}

// Cookies returns the cookies stored for the given URL.
func (c *Client) Cookies(rawURL string) []*http.Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return c.httpClient.Jar.Cookies(u)
}

// Underlying returns the *http.Client behind c: fingerprint and cookie jar,
// but no default headers or challenge solving.
func (c *Client) Underlying() *http.Client {
	return c.httpClient
}

// setHeaders fills in missing headers: Solver headers, then WithHeader ones,
// then browser defaults.
func (c *Client) setHeaders(req *http.Request) {
	for k, v := range c.clearanceHeader(req.URL.Hostname()) {
		if req.Header.Get(k) == "" && len(v) > 0 {
			req.Header.Set(k, v[0])
		}
	}
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
