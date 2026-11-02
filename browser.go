package cloudfetch

import (
	"encoding/hex"
	"math/rand/v2"

	utls "github.com/refraction-networking/utls"
)

// Browser is a browser to impersonate: its TLS fingerprint and the default
// headers it sends, both for the same version.
type Browser struct {
	hello   utls.ClientHelloID
	spec    func() (*utls.ClientHelloSpec, error) // if set, used instead of hello's
	headers [][2]string
}

// Browsers to impersonate with WithBrowser.
var (
	// Chrome is Chrome 156 on Windows, the default.
	Chrome = Browser{
		hello: utls.ClientHelloID{Client: "Chrome", Version: "156"},
		spec:  chrome156,
		headers: [][2]string{
			{"sec-ch-ua", `"Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"Upgrade-Insecure-Requests", "1"},
			{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"},
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"Sec-Fetch-Site", "none"},
			{"Sec-Fetch-Mode", "navigate"},
			{"Sec-Fetch-User", "?1"},
			{"Sec-Fetch-Dest", "document"},
			{"Accept-Encoding", "gzip, deflate, br, zstd"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Priority", "u=0, i"},
		},
	}

	// Firefox is Firefox 120 on Windows.
	Firefox = Browser{
		hello: utls.HelloFirefox_120,
		headers: [][2]string{
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
	}

	// Safari is Safari 16.0 on macOS.
	Safari = Browser{
		hello: utls.HelloSafari_16_0,
		headers: [][2]string{
			{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"},
			{"Accept-Language", "en-US,en;q=0.9"},
			{"Accept-Encoding", "gzip, deflate, br"},
		},
	}

	// Edge is Edge 85 on Windows.
	Edge = Browser{
		hello: utls.HelloEdge_85,
		headers: [][2]string{
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
)

// Chrome 156 additions to uTLS's Chrome 133 ClientHello, captured from
// Chrome 156.0.8078: ML-DSA signature algorithms and the Trust Anchor IDs
// extension.
const extTrustAnchorIDs = 0xca34

var (
	mlDSA          = []utls.SignatureScheme{0x0904, 0x0905, 0x0906}
	trustAnchorIDs = mustHex("00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f")
)

// chrome156 returns a fresh Chrome 156 ClientHello spec: uTLS's Chrome 133
// with a GREASE value and ML-DSA prepended to the signature algorithms and
// the Trust Anchor IDs extension added, shuffled like Chrome.
func chrome156() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, err
	}
	exts := spec.Extensions
	for i, e := range exts {
		if sa, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			algs := append([]utls.SignatureScheme{grease()}, mlDSA...)
			exts[i] = &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: append(algs, sa.SupportedSignatureAlgorithms...)}
		}
	}
	// Insert before the trailing GREASE extension, which stays last.
	last := len(exts) - 1
	exts = append(exts[:last:last], &utls.GenericExtension{Id: extTrustAnchorIDs, Data: trustAnchorIDs}, exts[last])
	spec.Extensions = utls.ShuffleChromeTLSExtensions(exts)
	return &spec, nil
}

// grease returns a random GREASE value (0x0a0a, 0x1a1a, ... 0xfafa).
func grease() utls.SignatureScheme {
	b := uint16(rand.IntN(16))<<4 | 0x0a
	return utls.SignatureScheme(b<<8 | b)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
