package cloudfetch

import (
	"net/http"
	"net/url"
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
		{"float", script("1.5 + t.length"), "a.io", "5.5", false},
		{"integer", script("4 + t.length"), "a.io", "8", false},
		{"no script", "<html></html>", "example.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evalV1Challenge(tt.body, tt.host)
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

	if err := c.solveV2Challenge("<html></html>", u); err == nil {
		t.Error("expected error when cf_chl_opt is missing")
	}
	if err := c.solveV2Challenge(`window._cf_chl_opt={cType: 'managed'}`, u); err == nil {
		t.Error("expected error when cRay is missing")
	}
}
