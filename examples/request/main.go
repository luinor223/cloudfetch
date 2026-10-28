// Command request sends a custom request with a deadline and its own headers,
// impersonating Firefox, and reports challenges it can't solve.
//
//	go run ./examples/request https://example.com
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/luinor223/cloudfetch"
)

func main() {
	url := "https://example.com"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	client := cloudfetch.New(
		cloudfetch.WithBrowser(cloudfetch.Firefox),
		cloudfetch.WithMaxRetries(2),
	)
	defer client.CloseIdleConnections()

	// The deadline covers the whole call, including challenge solving.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Accept-Language", "en-GB,en;q=0.8")

	resp, err := client.Do(req)
	switch {
	case errors.Is(err, cloudfetch.ErrManagedChallenge), errors.Is(err, cloudfetch.ErrCaptcha):
		log.Fatalf("this page needs a real browser: %v", err)
	case errors.Is(err, cloudfetch.ErrChallengeFailed):
		log.Fatalf("could not solve the challenge: %v", err)
	case err != nil:
		log.Fatal(err)
	}

	body, err := resp.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Type:   %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("Length: %d bytes\n", len(body))
}
