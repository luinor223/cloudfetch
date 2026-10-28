// Package cloudfetch provides an HTTP client that bypasses Cloudflare bot
// detection by mimicking a real browser's TLS fingerprint and headers.
//
// It uses uTLS to reproduce a browser's TLS Client Hello (JA3/JA4
// fingerprint), sends that browser's default headers, and maintains a cookie
// jar across requests.
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
// default headers. Defaults to Chrome. For a utls ClientHelloID other than the
// package presets, headers follow the preset for the same browser, so set
// User-Agent with WithHeader if the version differs.
func WithBrowser(id utls.ClientHelloID) Option {
	return func(c *Client) { c.helloID = id }
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

// WithHeader adds a default header sent with every request.
func WithHeader(key, value string) Option {
	return func(c *Client) { c.extraHeaders[key] = value }
}

// Client is an HTTP client with browser TLS fingerprinting.
type Client struct {
	helloID      utls.ClientHelloID
	timeout      time.Duration
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
		helloID:      Chrome,
		timeout:      30 * time.Second,
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
	}, t.client.helloID)

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

func (c *Client) setHeaders(req *http.Request) {
	for _, h := range headersFor(c.helloID) {
		if req.Header.Get(h[0]) == "" {
			req.Header.Set(h[0], h[1])
		}
	}

	for k, v := range c.extraHeaders {
		req.Header.Set(k, v)
	}
}

// Response wraps http.Response with convenience methods.
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

// Get performs an HTTP GET request.
func (c *Client) Get(rawURL string) (*Response, error) {
	return c.Do("GET", rawURL, nil)
}

// Post performs an HTTP POST request.
func (c *Client) Post(rawURL string, body io.Reader) (*Response, error) {
	return c.Do("POST", rawURL, body)
}

// MaxChallengeRetries is how many times to attempt solving a challenge.
var MaxChallengeRetries = 3

// Do performs an HTTP request with the given method.
// If a Cloudflare challenge is detected, it attempts to solve it automatically.
func (c *Client) Do(method, rawURL string, body io.Reader) (*Response, error) {
	return c.DoContext(context.Background(), method, rawURL, body)
}

// DoContext is like Do but honors ctx for every request and for the waits
// before submitting challenge answers. WithTimeout limits each HTTP request;
// give ctx a deadline to bound the whole call, including challenge solving.
func (c *Client) DoContext(ctx context.Context, method, rawURL string, body io.Reader) (*Response, error) {
	c.init()

	// Buffer the body so it can be resent after solving a challenge.
	var payload []byte
	if body != nil {
		b, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}

	for attempt := range MaxChallengeRetries + 1 {
		var reqBody io.Reader
		if body != nil {
			reqBody = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
		if err != nil {
			return nil, err
		}
		c.setHeaders(req)

		resp, err := c.httpClient.Do(req) //nolint:bodyclose // closed by Response.decode or the caller
		if err != nil {
			return nil, err
		}

		wrapped := &Response{Response: resp}

		if !isChallengeStatus(resp.StatusCode) {
			return wrapped, nil
		}

		if attempt == MaxChallengeRetries {
			return wrapped, nil
		}

		text, err := wrapped.Text()
		if err != nil {
			return wrapped, nil
		}

		ct := detectChallenge(resp, text)
		if ct == noChallenge {
			return wrapped, nil
		}

		parsedURL, _ := url.Parse(rawURL)

		switch ct {
		case iuamChallenge:
			err = c.solveIUAM(ctx, text, parsedURL)
		case v2Challenge:
			err = c.solveV2Challenge(ctx, text, parsedURL)
		case managedChallenge:
			return nil, fmt.Errorf("managed challenge (Turnstile) detected — requires a real browser")
		case captchaChallenge:
			return nil, fmt.Errorf("CAPTCHA challenge detected — requires external solving service")
		}

		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			if attempt == MaxChallengeRetries-1 {
				return nil, fmt.Errorf("challenge solve failed after %d attempts: %w", attempt+1, err)
			}
			continue
		}
	}

	return nil, fmt.Errorf("challenge solve failed after %d attempts", MaxChallengeRetries)
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

// Underlying returns the raw *http.Client for advanced use.
func (c *Client) Underlying() *http.Client {
	c.init()
	return c.httpClient
}
