// Package cloudfetch provides an HTTP client that bypasses Cloudflare bot
// detection by mimicking a real browser's TLS fingerprint and headers.
//
// It uses uTLS to reproduce a browser's TLS Client Hello (JA3/JA4
// fingerprint), sends that browser's default headers, keeps a cookie jar
// across requests, and solves Cloudflare's classic IUAM JS challenge.
package cloudfetch

import (
	"bytes"
	"crypto/x509"
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
