// Package chromesolver is a cloudfetch.Solver that clears challenges, including
// Managed and Interactive Challenges, in headless Chrome, clicking the
// Turnstile checkbox when one appears. It needs Chrome installed.
//
//	client := cloudfetch.New(cloudfetch.WithSolver(chromesolver.New()))
//
// cf_clearance is tied to the IP, so with a proxy, pass chromedp.ProxyServer
// to WithAllocatorOptions.
package chromesolver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/luinor223/cloudfetch"
)

// Option configures a Solver.
type Option func(*Solver)

// WithTimeout sets how long one Solve may take, including starting Chrome.
// Defaults to 60s.
func WithTimeout(d time.Duration) Option {
	return func(s *Solver) { s.timeout = d }
}

// WithAllocatorOptions adds Chrome options, such as chromedp.ProxyServer,
// over the defaults.
func WithAllocatorOptions(opts ...chromedp.ExecAllocatorOption) Option {
	return func(s *Solver) { s.allocOpts = append(s.allocOpts, opts...) }
}

// Solver starts a fresh Chrome per Solve. It is safe for concurrent use.
type Solver struct {
	timeout   time.Duration
	allocOpts []chromedp.ExecAllocatorOption

	uaOnce sync.Once
	ua     string
	uaErr  error
}

var _ cloudfetch.Solver = (*Solver)(nil)

// New returns a Solver with the given options.
func New(opts ...Option) *Solver {
	s := &Solver{timeout: 60 * time.Second}
	for _, o := range opts {
		o(s)
	}
	return s
}

// pollInterval is how often Solve checks for the clearance cookie.
const pollInterval = 250 * time.Millisecond

// Solve loads u in Chrome and returns its cookies once cf_clearance is set.
func (s *Solver) Solve(ctx context.Context, u *url.URL) (*cloudfetch.Clearance, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	ua, err := s.userAgent(ctx)
	if err != nil {
		return nil, err
	}

	browser, stop := s.browser(ctx, chromedp.UserAgent(ua))
	defer stop()

	cl, err := chromedp.Run(browser, clearance(u))
	if err != nil {
		return nil, err
	}
	if cl.Header.Get("User-Agent") == "" {
		cl.Header.Set("User-Agent", ua)
	}
	return cl, nil
}

// identityHeaders identify the browser; Chrome sends them lower-case.
var identityHeaders = []string{"user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"}

// clearance loads u, waits for cf_clearance, and records the identity headers
// of the last request Chrome sent to u's host.
func clearance(u *url.URL) chromedp.Action[*cloudfetch.Clearance] {
	return func(ctx context.Context, t *chromedp.Target) (*cloudfetch.Clearance, error) {
		evCtx, stopEvents := context.WithCancel(ctx)
		defer stopEvents()
		header := http.Header{}
		done := make(chan struct{})
		events := cdp.Events(evCtx, t, network.RequestWillBeSentExtraInfo) // subscribes now
		go func() {
			defer close(done)
			for ev, err := range events {
				if err != nil {
					return
				}
				if h := sentTo(ev.Headers, u.Host); h != nil {
					header = h
				}
			}
		}()

		if _, err := chromedp.Navigate(u.String())(ctx, t); err != nil {
			return nil, fmt.Errorf("chromesolver: load %s: %w", u, err)
		}
		cookies, err := waitForClearance(u)(ctx, t)
		stopEvents()
		<-done
		if err != nil {
			return nil, fmt.Errorf("chromesolver: no cf_clearance for %s: %w", u, err)
		}
		return &cloudfetch.Clearance{Cookies: cookies, Header: header}, nil
	}
}

// sentTo returns the identity headers of a request, if it went to host.
func sentTo(h network.Headers, host string) http.Header {
	authority, _ := h[":authority"].(string)
	if authority == "" {
		authority, _ = h["host"].(string)
	}
	if authority != host {
		return nil
	}
	out := http.Header{}
	for _, k := range identityHeaders {
		if v, ok := h[k].(string); ok {
			out.Set(k, v)
		}
	}
	return out
}

// browser starts Chrome and returns its tab context and a stop func.
func (s *Solver) browser(ctx context.Context, extra ...chromedp.ExecAllocatorOption) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Hide navigator.webdriver, which Cloudflare checks.
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
	)
	opts = append(opts, extra...)
	opts = append(opts, s.allocOpts...)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	return tabCtx, func() { cancelTab(); cancelAlloc() }
}

// userAgent returns Chrome's User-Agent without "Headless", probed once.
func (s *Solver) userAgent(ctx context.Context) (string, error) {
	s.uaOnce.Do(func() {
		browser, stop := s.browser(ctx)
		defer stop()
		ua, err := chromedp.Run(browser, chromedp.Evaluate[string](`navigator.userAgent`))
		if err != nil {
			s.uaErr = fmt.Errorf("chromesolver: start Chrome: %w", err)
			return
		}
		s.ua = strings.Replace(ua, "HeadlessChrome", "Chrome", 1)
	})
	return s.ua, s.uaErr
}

// Turnstile shows "Verifying..." before its checkbox, so clicks start after
// clickDelay and repeat every clickInterval until the cookie appears.
const (
	clickDelay    = 2 * time.Second
	clickInterval = 3 * time.Second
)

// waitForClearance polls for cf_clearance, clicking the Turnstile checkbox
// if one shows up.
func waitForClearance(u *url.URL) chromedp.Action[[]*http.Cookie] {
	params := network.GetCookiesParams{URLs: []string{u.String()}}
	isClearance := func(c *network.Cookie) bool { return c.Name == "cf_clearance" }
	return func(ctx context.Context, t *chromedp.Target) ([]*http.Cookie, error) {
		tick := time.NewTicker(pollInterval)
		defer tick.Stop()
		var seen, clicked time.Time
		for {
			res, err := cdp.Call(ctx, t, network.GetCookies, params)
			if err != nil {
				return nil, err
			}
			if slices.ContainsFunc(res.Cookies, isClearance) {
				return httpCookies(res.Cookies), nil
			}
			if now := time.Now(); now.Sub(clicked) >= clickInterval {
				if box := turnstileBox(ctx, t); box == nil {
					seen = time.Time{}
				} else if seen.IsZero() {
					seen = now
				} else if now.Sub(seen) >= clickDelay && clickCheckbox(ctx, t, box) == nil {
					clicked = now
				}
			}
			select {
			case <-ctx.Done():
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, errors.New("timed out")
				}
				return nil, ctx.Err()
			case <-tick.C:
			}
		}
	}
}

// turnstileBox returns the border box of the Turnstile iframe, or nil.
func turnstileBox(ctx context.Context, t *chromedp.Target) dom.Quad {
	depth, pierce := int64(-1), true
	doc, err := cdp.Call(ctx, t, dom.GetDocument, dom.GetDocumentParams{Depth: &depth, Pierce: &pierce})
	if err != nil {
		return nil
	}
	f := findTurnstile(doc.Root)
	if f == nil {
		return nil
	}
	box, err := cdp.Call(ctx, t, dom.GetBoxModel, dom.GetBoxModelParams{BackendNodeID: f.BackendNodeID})
	if err != nil || len(box.Model.Border) < 8 {
		return nil
	}
	return box.Model.Border
}

// findTurnstile finds the challenges.cloudflare.com iframe under n, through
// shadow roots and frames.
func findTurnstile(n *cdp.Node) *cdp.Node {
	if n == nil {
		return nil
	}
	if n.NodeName == "IFRAME" {
		for i := 0; i+1 < len(n.Attributes); i += 2 {
			if n.Attributes[i] == "src" && strings.Contains(n.Attributes[i+1], "challenges.cloudflare.com") {
				return n
			}
		}
	}
	for _, c := range slices.Concat(n.Children, n.ShadowRoots) {
		if f := findTurnstile(c); f != nil {
			return f
		}
	}
	return findTurnstile(n.ContentDocument)
}

// clickCheckbox moves the mouse to the checkbox at the left of the widget
// along a curved, unevenly timed path and clicks a random point inside it.
func clickCheckbox(ctx context.Context, t *chromedp.Target, box dom.Quad) error {
	x := box[0] + 30 + between(-4, 4)
	y := (box[1]+box[5])/2 + between(-4, 4)

	// Quadratic Bezier from a random start, through a jittered midpoint.
	sx, sy := x-between(80, 200), y-between(30, 90)
	cx, cy := (sx+x)/2+between(-20, 20), (sy+y)/2+between(-20, 20)
	steps := 10 + rand.IntN(10)
	for i := 1; i <= steps; i++ {
		f := float64(i) / float64(steps)
		f = f * f * (3 - 2*f) // ease in and out
		px := (1-f)*(1-f)*sx + 2*(1-f)*f*cx + f*f*x
		py := (1-f)*(1-f)*sy + 2*(1-f)*f*cy + f*f*y
		if err := mouse(ctx, t, input.DispatchMouseEventTypeMouseMoved, px, py); err != nil {
			return err
		}
		pause(10, 30)
	}

	pause(60, 180)
	if err := mouse(ctx, t, input.DispatchMouseEventTypeMousePressed, x, y); err != nil {
		return err
	}
	pause(60, 140)
	return mouse(ctx, t, input.DispatchMouseEventTypeMouseReleased, x, y)
}

// between returns a random float in [lo, hi).
func between(lo, hi float64) float64 { return lo + rand.Float64()*(hi-lo) }

// pause sleeps a random number of milliseconds in [lo, hi).
func pause(lo, hi float64) { time.Sleep(time.Duration(between(lo, hi) * float64(time.Millisecond))) }

func mouse(ctx context.Context, t *chromedp.Target, typ input.DispatchMouseEventType, x, y float64) error {
	p := input.DispatchMouseEventParams{Type: typ, X: x, Y: y}
	if typ != input.DispatchMouseEventTypeMouseMoved {
		p.Button, p.Buttons, p.ClickCount = input.MouseButtonLeft, 1, 1
	}
	_, err := cdp.Call(ctx, t, input.DispatchMouseEvent, p)
	return err
}

// httpCookies converts Chrome's cookies for use in a cookie jar.
func httpCookies(cs []*network.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(cs))
	for _, c := range cs {
		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		}
		// Chrome writes a leading dot for domain cookies and the bare host
		// for host-only ones, which a jar expects without a Domain.
		if d, ok := strings.CutPrefix(c.Domain, "."); ok {
			hc.Domain = d
		}
		if !c.Session && c.Expires > 0 && !math.IsInf(c.Expires, 0) {
			sec, frac := math.Modf(c.Expires)
			hc.Expires = time.Unix(int64(sec), int64(frac*1e9))
		}
		switch c.SameSite {
		case network.CookieSameSiteStrict:
			hc.SameSite = http.SameSiteStrictMode
		case network.CookieSameSiteLax:
			hc.SameSite = http.SameSiteLaxMode
		case network.CookieSameSiteNone:
			hc.SameSite = http.SameSiteNoneMode
		}
		out = append(out, hc)
	}
	return out
}
