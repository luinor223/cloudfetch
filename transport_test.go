package cloudfetch

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

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
		browser    Browser
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

func TestClient_CloseIdleConnections(t *testing.T) {
	c, srv := newUTLSTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), true)
	var handshakes atomic.Int32
	srv.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		return nil, nil
	}

	get := func() {
		t.Helper()
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		resp.Body.Close()
	}

	get()
	get()
	if n := handshakes.Load(); n != 1 {
		t.Fatalf("got %d handshakes before closing, want 1 (connection reused)", n)
	}
	c.CloseIdleConnections()
	get()
	if n := handshakes.Load(); n != 2 {
		t.Errorf("got %d handshakes after closing, want 2 (new connection)", n)
	}
}
