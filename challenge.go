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
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
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
	reV1Script      = regexp.MustCompile(`(?s)setTimeout\(function\(\)\{\s*(var\s+s,t,o,p.*?)(?:f\.action\s*\+=|\}\s*,\s*\d{4,5}\))`)
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

// challengePage is the parsed markup of a challenge page.
type challengePage struct {
	action string                // action of the challenge form, if any
	inputs url.Values            // inputs inside the challenge form
	byID   map[string]*html.Node // elements by id
}

// parseChallengePage parses a challenge page. Commented-out markup, which
// challenge pages use to hide decoy inputs, is not part of the tree.
func parseChallengePage(body string) *challengePage {
	page := &challengePage{inputs: url.Values{}, byID: make(map[string]*html.Node)}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return page
	}
	for n := range doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		if id := attr(n, "id"); id != "" {
			if _, ok := page.byID[id]; !ok {
				page.byID[id] = n
			}
		}
		if n.DataAtom == atom.Form && attr(n, "id") == "challenge-form" {
			page.action = attr(n, "action")
			for in := range n.Descendants() {
				if in.DataAtom == atom.Input && attr(in, "name") != "" {
					page.inputs.Add(attr(in, "name"), attr(in, "value"))
				}
			}
		}
	}
	return page
}

// text returns the text content of the element with the given id.
func (p *challengePage) text(id string) string {
	n, ok := p.byID[id]
	if !ok {
		return ""
	}
	var b strings.Builder
	for c := range n.Descendants() {
		if c.Type == html.TextNode {
			b.WriteString(c.Data)
		}
	}
	return b.String()
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// mayBeChallenge reports whether resp is a Cloudflare response with a status
// that can carry a challenge, so its body is worth reading.
func mayBeChallenge(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return strings.Contains(strings.ToLower(resp.Header.Get("Server")), "cloudflare")
	}
	return false
}

// detectChallenge inspects the response to determine if it's a Cloudflare challenge.
func detectChallenge(resp *http.Response, body string) challengeType {
	if !mayBeChallenge(resp) {
		return noChallenge
	}
	sc := resp.StatusCode

	if strings.Contains(body, "orchestrate/managed/v1") ||
		strings.Contains(body, "cf-turnstile") {
		return managedChallenge
	}

	// Newer challenge-platform page, or the older cf-captcha one.
	if sc == 403 && (strings.Contains(body, "orchestrate/captcha/v1") ||
		strings.Contains(body, "cf-captcha-container")) {
		return captchaChallenge
	}

	if strings.Contains(body, "challenge-platform") && strings.Contains(body, "cf_chl_opt") {
		return v2Challenge
	}

	if strings.Contains(body, "jschl_vc") || strings.Contains(body, "/cdn-cgi/images/trace/jsch/") {
		return iuamChallenge
	}

	return noChallenge
}

// solveIUAM solves the v1 IUAM challenge (JSFuck arithmetic).
func (c *Client) solveIUAM(ctx context.Context, body string, origURL *url.URL) error {
	page := parseChallengePage(body)
	if page.action == "" {
		return fmt.Errorf("could not find challenge form")
	}

	submitURL, err := origURL.Parse(page.action)
	if err != nil {
		return fmt.Errorf("invalid form action: %w", err)
	}

	answer, err := evalV1Challenge(body, page, origURL.Host)
	if err != nil {
		return fmt.Errorf("JS eval: %w", err)
	}
	// Submit the form as a browser would: its inputs, with the answer filled in.
	params := page.inputs
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

// evalV1Challenge runs the IUAM challenge function up to the form submit
// and returns the value it leaves in the answer input.
func evalV1Challenge(body string, page *challengePage, host string) (string, error) {
	scriptMatch := reV1Script.FindStringSubmatch(body)
	if scriptMatch == nil {
		return "", fmt.Errorf("could not extract challenge script")
	}
	script := scriptMatch[1]

	vm := goja.New()

	// Minimal browser stubs so the challenge JS can run. Elements expose the
	// page's text, which some challenges read part of the arithmetic from, and
	// keep what the script writes to them.
	noTimer := func(goja.FunctionCall) goja.Value { return vm.ToValue(0) }
	for _, name := range []string{"setTimeout", "setInterval", "clearTimeout", "clearInterval"} {
		_ = vm.Set(name, noTimer)
	}
	elements := make(map[string]map[string]any)
	_ = vm.Set("document", map[string]any{
		"createElement": func(tag string) map[string]any {
			return map[string]any{
				"firstChild": map[string]any{
					"href": "https://" + host + "/",
				},
			}
		},
		"getElementById": func(id string) map[string]any {
			if el, ok := elements[id]; ok {
				return el
			}
			el := map[string]any{"value": "", "innerHTML": page.text(id)}
			elements[id] = el
			return el
		},
	})

	if _, err := vm.RunString(script); err != nil {
		return "", fmt.Errorf("goja: %w", err)
	}

	answer, ok := elements["jschl-answer"]["value"]
	if !ok || answer == "" {
		return "", fmt.Errorf("challenge did not set the answer input")
	}
	// Like a browser form input, submit the value's JS string form.
	return vm.ToValue(answer).String(), nil
}

// solveV2Challenge makes a best-effort attempt at the v2 challenge-platform
// challenge by submitting its form fields. It does not run the challenge
// script, so modern challenges usually fail.
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

	page := parseChallengePage(body)
	var submitURL string
	if page.action != "" {
		u, err := origURL.Parse(page.action)
		if err == nil {
			submitURL = u.String()
		}
	}
	if submitURL == "" {
		submitURL = fmt.Sprintf("%s://%s/cdn-cgi/challenge-platform/h/g/cv/result/%s",
			origURL.Scheme, origURL.Host, cRay)
	}

	params := url.Values{}
	if r := page.inputs.Get("r"); r != "" {
		params.Set("r", r)
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
