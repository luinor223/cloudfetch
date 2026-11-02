# cloudfetch

[![CI](https://github.com/luinor223/cloudfetch/actions/workflows/ci.yaml/badge.svg)](https://github.com/luinor223/cloudfetch/actions/workflows/ci.yaml)
[![Coverage](https://raw.githubusercontent.com/luinor223/cloudfetch/badges/.badges/main/coverage.svg)](https://github.com/luinor223/cloudfetch/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/luinor223/cloudfetch.svg)](https://pkg.go.dev/github.com/luinor223/cloudfetch)
[![Go Version](https://img.shields.io/github/go-mod/go-version/luinor223/cloudfetch)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Go HTTP client that bypasses Cloudflare bot detection by mimicking a real browser's TLS fingerprint.

## How it works

Cloudflare identifies bots partly by their TLS Client Hello fingerprint (JA3/JA4). Go's default `net/http` has a distinctive fingerprint that gets blocked. `cloudfetch` uses [uTLS](https://github.com/refraction-networking/utls) to reproduce a real browser's TLS handshake, sends that browser's headers, and keeps a cookie jar.

- **TLS fingerprint** — Chrome 133, Firefox 120, Safari 16 or Edge 85 via uTLS
- **Matching headers** — `User-Agent`, `Sec-CH-UA`, `Sec-Fetch-*`, etc. for the same browser and version as the TLS fingerprint
- **JS challenge solver** — solves the classic IUAM ("Checking your browser") challenge using [goja](https://github.com/dop251/goja) (pure Go JS interpreter)
- **Auto-retry** — detects challenge pages and retries after solving (up to 3 attempts)
- **HTTP/2** — automatic ALPN negotiation and h2 support
- **Compression** — transparent brotli/gzip/deflate/zstd decompression
- **Cookie jar** — maintains cookies across requests
- **Proxy** — HTTP CONNECT proxies, with optional basic auth
- **Browser handoff** — optionally passes challenges it can't solve to headless Chrome once, then reuses the clearance cookie (see [Browser handoff](#browser-handoff))

### Limitations

- **Header order and HTTP/2 settings** come from Go's `net/http`, not the browser. Sites that fingerprint those can still tell `cloudfetch` apart from a real browser.
- **Newer JS challenges** (`challenge-platform`) are detected, but without a solver `cloudfetch` only submits the page's form fields without running its script, so they usually fail.
- **Managed and Interactive Challenges (Turnstile)** need a real browser. Without a solver, `cloudfetch` returns `ErrManagedChallenge`; with `chromesolver`, Chrome passes them, clicking the checkbox when asked.
- **CAPTCHAs** (hCaptcha, reCAPTCHA) aren't solved.

## Install

```bash
go get github.com/luinor223/cloudfetch
```

## Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/luinor223/cloudfetch"
)

func main() {
    client := cloudfetch.New()

    resp, err := client.Get("https://example.com")
    if err != nil {
        log.Fatal(err)
    }

    text, err := resp.Text()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d, Length: %d\n", resp.StatusCode, len(text))
}
```

### Options

```go
// Firefox fingerprint instead of Chrome
client := cloudfetch.New(cloudfetch.WithBrowser(cloudfetch.Firefox))

// Per-request timeout. To bound a whole call, including challenge solving,
// give the request's context a deadline.
client := cloudfetch.New(cloudfetch.WithTimeout(60 * time.Second))

// Challenge solve attempts per request (default 3, 0 disables solving)
client := cloudfetch.New(cloudfetch.WithMaxRetries(1))

// HTTP proxy (CONNECT), optionally with basic auth
client := cloudfetch.New(cloudfetch.WithProxy("http://user:pass@127.0.0.1:8080"))

// Header for every request (request headers still take precedence)
client := cloudfetch.New(cloudfetch.WithHeader("Referer", "https://google.com"))
```

### Methods

```go
resp, err := client.Get(url)
resp, err := client.Post(url, "application/json", body)
resp, err := client.Do(req)  // *http.Request: per-request headers, context

text, err := resp.Text()    // string, auto-decompressed
bytes, err := resp.Bytes()  // []byte, auto-decompressed

cookies := client.Cookies(url)
client.CloseIdleConnections()
httpClient := client.Underlying()  // raw *http.Client: fingerprint only, no headers or solving
```

### Browser handoff

Managed Challenges and newer JS challenges need a real browser. Set a `Solver`
and `cloudfetch` hands those pages to it (and classic IUAM pages once its own
attempts fail) once per request. It stores the cookies it gets (including `cf_clearance`), and
sends the browser's identity headers (`User-Agent`, `Sec-CH-UA*`) to that host
from then on, so the requests match the browser that passed. The
[`chromesolver`](chromesolver) module does this with headless Chrome. It's a
separate module so the core library doesn't pull in chromedp; installing it
also installs `cloudfetch`:

```bash
go get github.com/luinor223/cloudfetch/chromesolver
```

```go
client := cloudfetch.New(cloudfetch.WithSolver(chromesolver.New()))
resp, err := client.Get(url)  // first request starts Chrome (~6s), later ones don't
```

It needs Chrome or Chromium installed. Cloudflare ties `cf_clearance` to the IP
address and User-Agent, so if you use a proxy, give Chrome the same one with
`chromesolver.WithAllocatorOptions(chromedp.ProxyServer(...))`. When the cookie
expires, the next challenge runs the solver again.

### Errors

```go
resp, err := client.Get(url)
switch {
case errors.Is(err, cloudfetch.ErrManagedChallenge): // Turnstile: needs a real browser (see WithSolver)
case errors.Is(err, cloudfetch.ErrCaptcha):          // CAPTCHA
case errors.Is(err, cloudfetch.ErrChallengeFailed):  // JS challenge not solved after retries
}
```

## License

[MIT](LICENSE)
