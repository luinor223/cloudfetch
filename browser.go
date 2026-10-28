package cloudfetch

import utls "github.com/refraction-networking/utls"

// ClientHelloID aliases for convenience. Each comes with request headers
// matching the same browser and version, so the TLS fingerprint and the
// User-Agent agree.
var (
	Chrome  = utls.HelloChrome_Auto  // Chrome 133
	Firefox = utls.HelloFirefox_Auto // Firefox 120
	Safari  = utls.HelloSafari_Auto  // Safari 16.0
	Edge    = utls.HelloEdge_Auto    // Edge 85
)

// browserHeaders are the default navigation headers per utls client name,
// matching the versions of the presets above.
var browserHeaders = map[string][][2]string{
	Chrome.Client: {
		{"sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"`},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Accept-Encoding", "gzip, deflate, br, zstd"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Priority", "u=0, i"},
	},
	Firefox.Client: {
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Upgrade-Insecure-Requests", "1"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
	},
	Safari.Client: {
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Accept-Encoding", "gzip, deflate, br"},
	},
	Edge.Client: {
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36 Edg/85.0.564.51"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
	},
}

// headersFor returns the default headers for a fingerprint, falling back to
// Chrome's for clients without a profile (e.g. randomized fingerprints).
func headersFor(id utls.ClientHelloID) [][2]string {
	if h, ok := browserHeaders[id.Client]; ok {
		return h
	}
	return browserHeaders[Chrome.Client]
}
