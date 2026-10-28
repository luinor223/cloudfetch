//go:build integration

package cloudfetch_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/luinor223/cloudfetch"
)

func TestGet_LiveSites(t *testing.T) {
	tests := []struct {
		name   string
		url    string
		opts   []cloudfetch.Option
		minLen int
	}{
		{
			name: "httpbin with options",
			url:  "https://httpbin.org/headers",
			opts: []cloudfetch.Option{
				cloudfetch.WithTimeout(10 * time.Second),
				cloudfetch.WithBrowser(cloudfetch.Firefox),
				cloudfetch.WithHeader("X-Test", "true"),
			},
		},
		{name: "cloudflare", url: "https://www.cloudflare.com/", minLen: 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := cloudfetch.New(tt.opts...).Get(tt.url)
			if err != nil {
				t.Fatalf("GET failed: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200, got %d", resp.StatusCode)
			}

			text, err := resp.Text()
			if err != nil {
				t.Fatalf("Text() failed: %v", err)
			}
			if len(text) < tt.minLen {
				t.Errorf("response too small: %d bytes", len(text))
			}
			t.Logf("OK: %d bytes from %s", len(text), tt.url)
		})
	}
}
