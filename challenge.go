package cloudfetch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// challengeType identifies which Cloudflare protection was triggered.
type challengeType int

const (
	noChallenge      challengeType = iota
	iuamChallenge                  // v1: classic IUAM "Checking your browser" with JSFuck arithmetic
	v2Challenge                    // v2: challenge-platform with cf_chl_opt
	managedChallenge               // Turnstile / managed (not solvable without browser)
	captchaChallenge               // hCaptcha / reCAPTCHA (needs external service)
)

var (
	reV1Form        = regexp.MustCompile(`<form[^>]*id="challenge-form"[^>]*action="([^"]*)"`)
	reV1JschlVc     = regexp.MustCompile(`name="jschl_vc"\s+value="([^"]*)"`)
	reV1Pass        = regexp.MustCompile(`name="pass"\s+value="([^"]*)"`)
	reV1R           = regexp.MustCompile(`name="r"\s+value="([^"]*)"`)
	reV1Script      = regexp.MustCompile(`(?s)setTimeout\(function\(\)\{\s*(var\s+s,t,o,p.*?a\.value\s*=.+?)\s*[;,]`)
	reV1Delay       = regexp.MustCompile(`},\s*(\d{4,5})\)`)
	reCfChlOpt      = regexp.MustCompile(`(?s)window\._cf_chl_opt\s*=\s*\{([^}]+)\}`)
	reCfChlOptField = regexp.MustCompile(`'?(\w+)'?\s*:\s*'([^']*)'`)
)

// wait pauses before submitting a challenge answer, returning early with
// ctx's error if it is done first. Tests replace it.
var wait = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isChallengeStatus reports whether a status code can carry a Cloudflare challenge.
func isChallengeStatus(code int) bool {
	switch code {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	}
	return false
}

// detectChallenge inspects the response to determine if it's a Cloudflare challenge.
func detectChallenge(resp *http.Response, body string) challengeType {
	server := resp.Header.Get("Server")
	if !strings.Contains(strings.ToLower(server), "cloudflare") {
		return noChallenge
	}

	sc := resp.StatusCode
	if !isChallengeStatus(sc) {
		return noChallenge
	}

	// v2 managed / turnstile (not solvable).
	if strings.Contains(body, "orchestrate/managed/v1") ||
		strings.Contains(body, "cf-turnstile") {
		return managedChallenge
	}

	// v2 captcha.
	if sc == 403 && strings.Contains(body, "orchestrate/captcha/v1") {
		return captchaChallenge
	}

	// v2 JS challenge (challenge-platform).
	if strings.Contains(body, "challenge-platform") && strings.Contains(body, "cf_chl_opt") {
		return v2Challenge
	}

	// v1 IUAM.
	if strings.Contains(body, "jschl_vc") || strings.Contains(body, "/cdn-cgi/images/trace/jsch/") {
		return iuamChallenge
	}

	return noChallenge
}

// solveIUAM solves the v1 IUAM challenge (JSFuck arithmetic).
func (c *Client) solveIUAM(ctx context.Context, body string, origURL *url.URL) error {
	actionMatch := reV1Form.FindStringSubmatch(body)
	if actionMatch == nil {
		return fmt.Errorf("could not find challenge form")
	}

	submitURL, err := origURL.Parse(actionMatch[1])
	if err != nil {
		return fmt.Errorf("invalid form action: %w", err)
	}

	params := url.Values{}
	if m := reV1R.FindStringSubmatch(body); m != nil {
		params.Set("r", m[1])
	}
	if m := reV1JschlVc.FindStringSubmatch(body); m != nil {
		params.Set("jschl_vc", m[1])
	}
	if m := reV1Pass.FindStringSubmatch(body); m != nil {
		params.Set("pass", m[1])
	}

	answer, err := evalV1Challenge(body, origURL.Host)
	if err != nil {
		return fmt.Errorf("JS eval: %w", err)
	}
	params.Set("jschl_answer", answer)

	// CF expects a delay before submission (typically 4s).
	delay := 4 * time.Second
	if m := reV1Delay.FindStringSubmatch(body); m != nil {
		if d, err := time.ParseDuration(m[1] + "ms"); err == nil {
			delay = d
		}
	}
	if err := wait(ctx, delay); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL.String(), strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", origURL.String())
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("challenge POST: %w", err)
	}
	resp.Body.Close()
	return nil
}

// evalV1Challenge extracts and evaluates the IUAM JSFuck arithmetic.
func evalV1Challenge(body, host string) (string, error) {
	scriptMatch := reV1Script.FindStringSubmatch(body)
	if scriptMatch == nil {
		return "", fmt.Errorf("could not extract challenge script")
	}
	script := scriptMatch[1]

	vm := goja.New()

	// Minimal DOM stubs so the challenge JS can run.
	_ = vm.Set("document", map[string]any{
		"createElement": func(tag string) map[string]any {
			return map[string]any{
				"firstChild": map[string]any{
					"href": "https://" + host + "/",
				},
			}
		},
		"getElementById": func(id string) map[string]any {
			return map[string]any{"value": "", "innerHTML": "", "action": ""}
		},
	})

	setup := fmt.Sprintf(`var t = "%s"; var a = {value: 0};`, host)

	_, err := vm.RunString(setup + "\n" + script)
	if err != nil {
		return "", fmt.Errorf("goja: %w", err)
	}

	val := vm.Get("a")
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return "", fmt.Errorf("answer variable 'a' not set")
	}

	answer := val.ToObject(vm).Get("value")
	if answer == nil || goja.IsUndefined(answer) {
		return "", fmt.Errorf("answer variable 'a.value' not set")
	}

	// Like a browser form input, submit the value's JS string form.
	return answer.String(), nil
}

// solveV2Challenge solves the v2 challenge-platform challenge.
func (c *Client) solveV2Challenge(ctx context.Context, body string, origURL *url.URL) error {
	optsMatch := reCfChlOpt.FindStringSubmatch(body)
	if optsMatch == nil {
		return fmt.Errorf("could not find cf_chl_opt")
	}

	fields := make(map[string]string)
	for _, m := range reCfChlOptField.FindAllStringSubmatch(optsMatch[1], -1) {
		fields[m[1]] = m[2]
	}

	cRay := fields["cRay"]
	if cRay == "" {
		return fmt.Errorf("missing cRay")
	}

	// Try form action first, fall back to challenge-platform URL.
	var submitURL string
	if m := reV1Form.FindStringSubmatch(body); m != nil {
		u, err := origURL.Parse(m[1])
		if err == nil {
			submitURL = u.String()
		}
	}
	if submitURL == "" {
		submitURL = fmt.Sprintf("%s://%s/cdn-cgi/challenge-platform/h/g/cv/result/%s",
			origURL.Scheme, origURL.Host, cRay)
	}

	params := url.Values{}
	if m := reV1R.FindStringSubmatch(body); m != nil {
		params.Set("r", m[1])
	}
	params.Set("cf_ch_verify", "plat")
	if h, ok := fields["cHash"]; ok {
		params.Set("cf_ch_cp", h)
	}

	if err := wait(ctx, 5*time.Second); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", origURL.String())
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("challenge POST: %w", err)
	}
	resp.Body.Close()
	return nil
}
