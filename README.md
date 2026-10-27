# cloudfetch

Go HTTP client that bypasses Cloudflare bot detection by mimicking a real browser's TLS fingerprint.

## How it works

Cloudflare identifies bots partly by their TLS Client Hello fingerprint (JA3/JA4). Go's default `net/http` has a distinctive fingerprint that gets blocked. `cloudfetch` uses [uTLS](https://github.com/refraction-networking/utls) to reproduce Chrome's exact TLS handshake, plus browser-order HTTP headers and a cookie jar.

- **TLS fingerprint** — Chrome/Firefox/Safari/Edge via uTLS
- **HTTP/2** — automatic ALPN negotiation and h2 support
- **Browser headers** — correct `Sec-CH-UA`, `Sec-Fetch-*`, etc. in Chrome's order
- **Compression** — transparent brotli/gzip/deflate decompression
- **Cookie jar** — maintains cookies across requests

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

// Custom timeout
client := cloudfetch.New(cloudfetch.WithTimeout(60 * time.Second))

// Proxy
client := cloudfetch.New(cloudfetch.WithProxy("http://127.0.0.1:8080"))

// Extra headers
client := cloudfetch.New(cloudfetch.WithHeader("Referer", "https://google.com"))
```

### Methods

```go
resp, err := client.Get(url)
resp, err := client.Post(url, body)
resp, err := client.Do(method, url, body)

text, err := resp.Text()   // string, auto-decompressed
bytes, err := resp.Bytes()  // []byte, auto-decompressed

cookies := client.Cookies(url)
httpClient := client.Underlying()  // *http.Client for advanced use
```

## License

MIT
