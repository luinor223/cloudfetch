package cloudfetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	solverUA    = "Mozilla/5.0 (solver)"
	solverHints = `"Solver";v="1"`
)

// fakeSolver returns a cf_clearance cookie and solverUA, or err.
type fakeSolver struct {
	calls atomic.Int32
	err   error
	wait  <-chan struct{} // if set, Solve blocks until it is closed
}

func (s *fakeSolver) Solve(ctx context.Context, _ *url.URL) (*Clearance, error) {
	s.calls.Add(1)
	if s.wait != nil {
		select {
		case <-s.wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return &Clearance{
		Cookies: []*http.Cookie{{Name: "cf_clearance", Value: "ok"}},
		Header:  http.Header{"User-Agent": {solverUA}, "Sec-Ch-Ua": {solverHints}},
	}, nil
}

// cleared reports whether r carries the clearance cookie and the solver's
// identity headers, in place of the browser preset's.
func cleared(r *http.Request) bool {
	c, err := r.Cookie("cf_clearance")
	return err == nil && c.Value == "ok" && r.UserAgent() == solverUA &&
		r.Header.Get("Sec-Ch-Ua") == solverHints
}

// managedUntilCleared serves a Managed Challenge until the request is cleared.
func managedUntilCleared(w http.ResponseWriter, r *http.Request) {
	if !cleared(r) {
		serveChallenge(w, http.StatusForbidden, managedPage)
		return
	}
	_, _ = io.WriteString(w, "real page")
}

func TestDo_SolverClearsManagedChallenge(t *testing.T) {
	s := &fakeSolver{}
	c, srv := newTestClient(t, http.HandlerFunc(managedUntilCleared), WithSolver(s))

	for i := range 2 {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		if text, _ := resp.Text(); text != "real page" {
			t.Fatalf("Get %d: body = %q, want %q", i, text, "real page")
		}
	}
	if n := s.calls.Load(); n != 1 {
		t.Errorf("solver called %d times, want 1", n)
	}
}

const v2Page = `<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1"></script><script>window._cf_chl_opt={cType: 'non-interactive', cRay: 'abc'}</script>`

func TestDo_SolverTakesJSChallenges(t *testing.T) {
	stubWait(t, nil)
	tests := map[string]struct {
		page        string
		status      int
		wantInlined int32 // in-process attempts before the solver
	}{
		"v2 at once":          {v2Page, http.StatusForbidden, 0},
		"iuam after attempts": {iuamPage, http.StatusServiceUnavailable, 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var challenged atomic.Int32
			s := &fakeSolver{}
			c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !cleared(r) {
					if r.URL.Path == "/" { // not an answer submission
						challenged.Add(1)
					}
					serveChallenge(w, tt.status, tt.page)
					return
				}
				_, _ = io.WriteString(w, "real page")
			}), WithSolver(s), WithMaxRetries(2))

			resp, err := c.Get(srv.URL)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if text, _ := resp.Text(); text != "real page" {
				t.Fatalf("body = %q, want %q", text, "real page")
			}
			if n := s.calls.Load(); n != 1 {
				t.Errorf("solver called %d times, want 1", n)
			}
			if got := challenged.Load() - 1; got != tt.wantInlined {
				t.Errorf("in-process attempts = %d, want %d", got, tt.wantInlined)
			}
		})
	}
}

func TestDo_SolverErrorOnJSChallenge(t *testing.T) {
	stubWait(t, nil)
	errBrowser := errors.New("browser failed")
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveChallenge(w, http.StatusForbidden, v2Page)
	}), WithSolver(&fakeSolver{err: errBrowser}))

	if _, err := c.Get(srv.URL); !errors.Is(err, ErrChallengeFailed) || !errors.Is(err, errBrowser) {
		t.Fatalf("err = %v, want ErrChallengeFailed wrapping %v", err, errBrowser)
	}
}

func TestDo_SolverError(t *testing.T) {
	errBrowser := errors.New("browser failed")
	s := &fakeSolver{err: errBrowser}
	c, srv := newTestClient(t, http.HandlerFunc(managedUntilCleared), WithSolver(s))

	_, err := c.Get(srv.URL)
	if !errors.Is(err, ErrManagedChallenge) || !errors.Is(err, errBrowser) {
		t.Fatalf("err = %v, want ErrManagedChallenge wrapping %v", err, errBrowser)
	}
}

func TestDo_SolverOncePerRequest(t *testing.T) {
	s := &fakeSolver{}
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveChallenge(w, http.StatusForbidden, managedPage)
	}), WithSolver(s))

	if _, err := c.Get(srv.URL); !errors.Is(err, ErrManagedChallenge) {
		t.Fatalf("err = %v, want ErrManagedChallenge", err)
	}
	if n := s.calls.Load(); n != 1 {
		t.Errorf("solver called %d times, want 1", n)
	}
}

func TestDo_ConcurrentRequestsShareOneSolve(t *testing.T) {
	release := make(chan struct{})
	var challenged atomic.Int32
	s := &fakeSolver{wait: release}
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cleared(r) && challenged.Add(1) == 2 {
			close(release) // both requests have hit the challenge
		}
		managedUntilCleared(w, r)
	}), WithSolver(s))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			resp, err := c.Do(req)
			if err == nil {
				resp.Body.Close()
			}
			errs[i] = err
		})
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d: %v", i, err)
		}
	}
	if n := s.calls.Load(); n != 1 {
		t.Errorf("solver called %d times, want 1", n)
	}
}

func TestDo_SolverThenJSChallengeWithoutRetries(t *testing.T) {
	stubWait(t, nil)
	s := &fakeSolver{}
	c, srv := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cleared(r) {
			serveChallenge(w, http.StatusForbidden, managedPage)
			return
		}
		serveChallenge(w, http.StatusServiceUnavailable, iuamPage)
	}), WithSolver(s), WithMaxRetries(0))

	if _, err := c.Get(srv.URL); !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("err = %v, want ErrChallengeFailed", err)
	}
}
