package cloudfetch

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// iuamPage is a trimmed v1 IUAM challenge page. The JSFuck expression
// evaluates to 20, then +2, plus the length of the host.
const iuamPage = `<!DOCTYPE html>
<html><head><title>Just a moment...</title></head><body>
<script type="text/javascript">
  (function(){
    var a = function() {try{return !!window.addEventListener} catch(e) {return !1} },
    a = function(b, c) {setTimeout(function(){
        var s,t,o,p,b,r,e,a,k,i,n,g,f, abcDef={"ghi":+((!+[]+!![]+[])+(+[]))};
        g = String.fromCharCode;
        t = document.createElement('div');
        t.innerHTML="<a href='/'>x</a>";
        t = t.firstChild.href;r = t.match(/https?:\/\//)[0];
        t = t.substr(r.length); t = t.substr(0,t.length-1);
        a = document.getElementById('jschl-answer');
        f = document.getElementById('challenge-form');
        ;abcDef.ghi+=+((!+[]+!![]+[]));a.value = (+abcDef.ghi + t.length).toFixed(10); '; 121'
        f.action += location.hash;
        f.submit();
      }, 4000);
    };
  })();
</script>
<form id="challenge-form" action="/cdn-cgi/l/chk_jschl" method="get">
  <input type="hidden" name="r" value="r-token"/>
  <input type="hidden" name="jschl_vc" value="vc-token"/>
  <input type="hidden" name="pass" value="pass-token"/>
  <input type="hidden" id="jschl-answer" name="jschl_answer"/>
</form>
</body></html>`

const (
	managedPage = `<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/managed/v1"></script>`
	captchaPage = `<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/captcha/v1"></script>`
)

func TestDetectChallenge(t *testing.T) {
	tests := []struct {
		name   string
		server string
		status int
		body   string
		want   challengeType
	}{
		{"not cloudflare", "nginx", 503, iuamPage, noChallenge},
		{"ok status", "cloudflare", 200, iuamPage, noChallenge},
		{"plain error", "cloudflare", 503, "<html>down</html>", noChallenge},
		{"server header case", "Cloudflare", 503, iuamPage, iuamChallenge},
		{"iuam jschl_vc", "cloudflare", 503, iuamPage, iuamChallenge},
		{"iuam trace image", "cloudflare", 503, `<img src="/cdn-cgi/images/trace/jsch/js/transparent.gif">`, iuamChallenge},
		{"v2", "cloudflare", 403, `<script src="/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1"></script><script>window._cf_chl_opt={cRay: 'abc'}</script>`, v2Challenge},
		{"managed", "cloudflare", 403, managedPage, managedChallenge},
		{"turnstile", "cloudflare", 403, `<div class="cf-turnstile"></div>`, managedChallenge},
		{"captcha", "cloudflare", 403, captchaPage, captchaChallenge},
		{"captcha needs 403", "cloudflare", 503, captchaPage, noChallenge},
		{"rate limited", "cloudflare", 429, iuamPage, iuamChallenge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.status,
				Header:     http.Header{"Server": {tt.server}},
			}
			if got := detectChallenge(resp, tt.body); got != tt.want {
				t.Errorf("detectChallenge() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEvalV1Challenge(t *testing.T) {
	script := func(expr string) string {
		return `setTimeout(function(){ var s,t,o,p; a = document.getElementById('jschl-answer'); a.value = ` + expr + `; }, 4000);`
	}
	tests := []struct {
		name    string
		body    string
		host    string
		want    string
		wantErr bool
	}{
		{"iuam page", iuamPage, "example.com", "33.0000000000", false}, // 20 + 2 + len(host)
		{"float", script("1.5 + 4"), "a.io", "5.5", false},
		{"integer", script("4 + 4"), "a.io", "8", false},
		{"no script", "<html></html>", "example.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evalV1Challenge(tt.body, parseChallengePage(tt.body), tt.host)
			if (err != nil) != tt.wantErr {
				t.Fatalf("evalV1Challenge error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("answer = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSolveV2Challenge_MissingOpts(t *testing.T) {
	c := New()
	u := &url.URL{Scheme: "https", Host: "example.com", Path: "/"}

	if err := c.solveV2Challenge(t.Context(), "<html></html>", u); err == nil {
		t.Error("expected error when cf_chl_opt is missing")
	}
	if err := c.solveV2Challenge(t.Context(), `window._cf_chl_opt={cType: 'managed'}`, u); err == nil {
		t.Error("expected error when cRay is missing")
	}
}

func TestRealChallengePages(t *testing.T) {
	// Expected values from cloudscraper's tests; see testdata/cloudflare.
	const host = "www.evildomain.com"
	tests := []struct {
		file   string
		status int
		want   challengeType
		answer string // "" when no answer was recorded
		inputs map[string]string
		rHash  string // SHA-256 of the r field, as recorded by cloudscraper
	}{
		{
			file: "js_challenge_11_12_2019.html", status: 503, want: iuamChallenge,
		},
		{
			file: "js_challenge1_16_05_2020.html", status: 503, want: iuamChallenge,
			answer: "-7.5155218172",
			inputs: map[string]string{"pass": "1589555973.262-n4Tt3w2mXt", "jschl_vc": "df9d3a159bbde53c214e7abfcb005e0c"},
			rHash:  "f111bf7fe2d4d39d47dd837590808eeacb6e208a7503587f14a95c9ab0fc2d70",
		},
		{
			file: "js_challenge2_16_05_2020.html", status: 503, want: iuamChallenge,
			answer: "58.4019148791",
			inputs: map[string]string{"pass": "1589581670.18-mkcsKJpz0a", "jschl_vc": "ebec58fc1df89e2e403fa249469e50eb"},
			rHash:  "af028b8967c508037f3888dfaf85d403df9532f4ad851fea76c2ece4f4d9853b",
		},
		{
			file: "js_challenge-27-05-2020.html", status: 503, want: iuamChallenge,
			answer: "102.7365930923",
			inputs: map[string]string{"pass": "1590526864.279-GCnY0hKdNH", "jschl_vc": "706241acd6cb287b270835d26b275f50"},
			rHash:  "b7f071b2f22b5dfecd144198317929d3f7c8d3d271c169e7676a42042c3581ed",
		},
		{file: "reCaptcha_challenge_12_12_2019.html", status: 403, want: captchaChallenge},
		{file: "bfm_07_01_2021.html", status: 503, want: noChallenge},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", "cloudflare", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			body := string(b)

			resp := &http.Response{StatusCode: tt.status, Header: http.Header{"Server": {"cloudflare"}}}
			if got := detectChallenge(resp, body); got != tt.want {
				t.Fatalf("detectChallenge() = %d, want %d", got, tt.want)
			}
			if tt.want != iuamChallenge {
				return
			}

			page := parseChallengePage(body)
			answer, err := evalV1Challenge(body, page, host)
			if err != nil {
				t.Fatalf("evalV1Challenge: %v", err)
			}
			if tt.answer == "" {
				if _, err := strconv.ParseFloat(answer, 64); err != nil || answer == "NaN" {
					t.Errorf("answer = %q, want a number", answer)
				}
				return
			}
			if answer != tt.answer {
				t.Errorf("answer = %q, want %q", answer, tt.answer)
			}

			// The form holds exactly the fields cloudscraper submitted.
			if names := slices.Sorted(maps.Keys(page.inputs)); !slices.Equal(names, []string{"jschl_answer", "jschl_vc", "pass", "r"}) {
				t.Errorf("form inputs = %v", names)
			}
			for name, want := range tt.inputs {
				if got := page.inputs.Get(name); got != want {
					t.Errorf("input %s = %q, want %q", name, got, want)
				}
			}
			if sum := sha256.Sum256([]byte(page.inputs.Get("r"))); hex.EncodeToString(sum[:]) != tt.rHash {
				t.Errorf("input r = %q does not match the recorded hash", page.inputs.Get("r"))
			}
		})
	}
}
