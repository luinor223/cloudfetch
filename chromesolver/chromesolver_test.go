package chromesolver

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
)

func TestHTTPCookies(t *testing.T) {
	got := httpCookies([]*network.Cookie{
		{Name: "cf_clearance", Value: "v", Domain: ".example.com", Path: "/", Expires: 1800000000.5, Secure: true, HTTPOnly: true, SameSite: network.CookieSameSiteNone},
		{Name: "host", Value: "h", Domain: "www.example.com", Path: "/", Expires: -1, Session: true, SameSite: network.CookieSameSiteLax},
	})
	want := []*http.Cookie{
		{Name: "cf_clearance", Value: "v", Domain: "example.com", Path: "/", Expires: time.Unix(1800000000, 5e8), Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode},
		{Name: "host", Value: "h", Path: "/", SameSite: http.SameSiteLaxMode},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("httpCookies =\n%+v\nwant\n%+v", got, want)
	}
}

func TestSentTo(t *testing.T) {
	h := network.Headers{
		":authority":         "example.com",
		"user-agent":         "UA",
		"sec-ch-ua":          `"Chrome";v="156"`,
		"sec-ch-ua-platform": `"macOS"`,
		"accept":             "*/*",
	}
	want := http.Header{"User-Agent": {"UA"}, "Sec-Ch-Ua": {`"Chrome";v="156"`}, "Sec-Ch-Ua-Platform": {`"macOS"`}}
	if got := sentTo(h, "example.com"); !reflect.DeepEqual(got, want) {
		t.Errorf("sentTo = %v, want %v", got, want)
	}
	if got := sentTo(h, "other.com"); got != nil {
		t.Errorf("sentTo other host = %v, want nil", got)
	}
}

func TestFindTurnstile(t *testing.T) {
	iframe := &cdp.Node{NodeName: "IFRAME", Attributes: []string{"src", "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile"}}
	root := &cdp.Node{NodeName: "#document", Children: []*cdp.Node{
		{NodeName: "IFRAME", Attributes: []string{"src", "https://example.com/ad"}},
		{NodeName: "DIV", ShadowRoots: []*cdp.Node{{NodeName: "#document-fragment", Children: []*cdp.Node{iframe}}}},
	}}
	if got := findTurnstile(root); got != iframe {
		t.Errorf("findTurnstile = %v, want the Turnstile iframe", got)
	}
	if got := findTurnstile(&cdp.Node{NodeName: "#document"}); got != nil {
		t.Errorf("findTurnstile on empty page = %v, want nil", got)
	}
}
