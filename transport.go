package cloudfetch

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

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
