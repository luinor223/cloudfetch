package cloudfetch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// A Solver gets past challenges cloudfetch can't, usually with a real
// browser. See github.com/luinor223/cloudfetch/chromesolver.
type Solver interface {
	// Solve gets past u's challenge and returns the clearance.
	Solve(ctx context.Context, u *url.URL) (*Clearance, error)
}

// Clearance holds the cookies a Solver earned (typically cf_clearance) and the
// identity headers it sent (User-Agent, Sec-CH-UA*). Cloudflare ties the
// cookie to them, so the Client sends them to that host from then on.
type Clearance struct {
	Cookies []*http.Cookie
	Header  http.Header
}

// WithSolver sets a Solver for challenges cloudfetch can't solve: managed and
// challenge-platform ones at once, IUAM ones after WithMaxRetries attempts.
// It runs at most once per request.
func WithSolver(s Solver) Option {
	return func(c *Client) { c.solver = s }
}

// hostClearance is the Solver state for one host.
type hostClearance struct {
	lock   chan struct{} // held while the Solver runs
	header http.Header   // read-only
	at     time.Time     // last success
}

// clear runs the Solver for u's host, unless another request cleared it after
// sent, and stores the result. Errors wrap fail.
func (c *Client) clear(ctx context.Context, u *url.URL, sent time.Time, fail error) error {
	h := c.host(u.Hostname())
	select {
	case h.lock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-h.lock }()

	c.mu.Lock()
	cleared := h.at.After(sent)
	c.mu.Unlock()
	if cleared {
		return nil
	}

	cl, err := c.solver.Solve(ctx, u)
	if err != nil {
		return fmt.Errorf("%w: solver: %w", fail, err)
	}
	c.httpClient.Jar.SetCookies(u, cl.Cookies)

	c.mu.Lock()
	h.header, h.at = cl.Header.Clone(), time.Now()
	c.mu.Unlock()
	return nil
}

// host returns the Solver state for host, creating it if needed.
func (c *Client) host(host string) *hostClearance {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.clearances[host]
	if h == nil {
		h = &hostClearance{lock: make(chan struct{}, 1)}
		c.clearances[host] = h
	}
	return h
}

// clearanceHeader returns the Solver's headers for host. Don't modify them.
func (c *Client) clearanceHeader(host string) http.Header {
	if c.solver == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.clearances[host]; h != nil {
		return h.header
	}
	return nil
}
