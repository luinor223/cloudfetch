package cloudfetch

import utls "github.com/refraction-networking/utls"

// Browser is a browser to impersonate: its TLS fingerprint and the default
// headers it sends, both for the same version.
type Browser struct {
	hello   utls.ClientHelloID
	headers [][2]string
}

// Browsers to impersonate with WithBrowser.
var (
	// Chrome is Chrome 133 on Windows, the default.
	Chrome = Browser{utls.HelloChrome_133, [][2]string{
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
	}}

	// Firefox is Firefox 120 on Windows.
	Firefox = Browser{utls.HelloFirefox_120, [][2]string{
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Upgrade-Insecure-Requests", "1"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
	}}

	// Safari is Safari 16.0 on macOS.
	Safari = Browser{utls.HelloSafari_16_0, [][2]string{
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"},
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Accept-Encoding", "gzip, deflate, br"},
	}}

	// Edge is Edge 85 on Windows.
	Edge = Browser{utls.HelloEdge_85, [][2]string{
		{"Upgrade-Insecure-Requests", "1"},
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36 Edg/85.0.564.51"},
		{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-User", "?1"},
		{"Sec-Fetch-Dest", "document"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Accept-Language", "en-US,en;q=0.9"},
	}}
)
