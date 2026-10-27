package cloudfetch_test

import (
	"strings"
	"testing"
	"time"

	"github.com/luinor223/cloudfetch"
)

func TestGet_TradingEconomics(t *testing.T) {
	client := cloudfetch.New()

	resp, err := client.Get("https://tradingeconomics.com/commodities")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	text, err := resp.Text()
	if err != nil {
		t.Fatalf("Text() failed: %v", err)
	}

	if !strings.Contains(text, "CL1:COM") {
		t.Error("response missing CL1:COM (Crude Oil symbol)")
	}
	if !strings.Contains(text, "datatable-heatmap") {
		t.Error("response missing heatmap columns (weekly/monthly/ytd/yoy)")
	}
	if len(text) < 100000 {
		t.Errorf("response too small: %d bytes (expected 100k+)", len(text))
	}

	t.Logf("OK: %d bytes, has commodity data and heatmap columns", len(text))
}

func TestOptions(t *testing.T) {
	client := cloudfetch.New(
		cloudfetch.WithTimeout(10*time.Second),
		cloudfetch.WithBrowser(cloudfetch.Firefox),
		cloudfetch.WithHeader("X-Test", "true"),
	)

	resp, err := client.Get("https://httpbin.org/headers")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	text, _ := resp.Text()
	t.Logf("OK: %d bytes", len(text))
}

func TestGet_Cloudflare(t *testing.T) {
	client := cloudfetch.New()

	resp, err := client.Get("https://www.cloudflare.com/")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	text, err := resp.Text()
	if err != nil {
		t.Fatalf("Text() failed: %v", err)
	}

	if len(text) < 1000 {
		t.Errorf("response too small: %d bytes", len(text))
	}

	t.Logf("OK: %d bytes from cloudflare.com", len(text))
}
