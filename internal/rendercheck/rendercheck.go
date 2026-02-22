package rendercheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/html"
)

type VerifyMode string

const (
	VerifyAuto   VerifyMode = "auto"
	VerifyNever  VerifyMode = "never"
	VerifyAlways VerifyMode = "always"
)

type Options struct {
	Timeout      time.Duration
	MaxBytes     int64
	UserAgent    string
	InsecureTLS  bool
	Client       *http.Client
	Verify       VerifyMode
	Headless     bool
	BorderLow    int
	BorderHigh   int
	TextDeltaMin int
}

type Result struct {
	InputURL       string            `json:"input_url"`
	FinalURL       string            `json:"final_url,omitempty"`
	Status         int               `json:"status,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	NeedsRendering bool              `json:"needs_rendering"`
	Method         string            `json:"method"`
	Score          int               `json:"score"`
	Confidence     string            `json:"confidence"`
	Signals        []string          `json:"signals"`
	Metrics        map[string]any    `json:"metrics"`
	Errors         map[string]string `json:"errors,omitempty"`
}

type Heur struct {
	Score            int
	Signals          []string
	VisibleTextChars int
	ScriptTags       int
	ExternalScripts  int
	RootEmpty        bool
}

var (
	jsRequiredRe = regexp.MustCompile(`(?i)(enable javascript|turn on javascript|requires javascript|please enable js|javascript is required|you need to enable javascript)`)
	cfRe         = regexp.MustCompile(`(?i)(cf-browser-verification|challenge-form|just a moment|checking your browser|cloudflare)`)
	akamaiRe     = regexp.MustCompile(`(?i)(akamai|bot manager|access denied|reference #)`)
	perimeterXRe = regexp.MustCompile(`(?i)(perimeterx|px-captcha|why did this happen\?)`)

	frameworkMarkers = []*regexp.Regexp{
		regexp.MustCompile(`(?i)__NEXT_DATA__`),
		regexp.MustCompile(`(?i)__NUXT__`),
		regexp.MustCompile(`(?i)webpackJsonp|webpackChunk`),
		regexp.MustCompile(`(?i)data-reactroot|react-dom`),
		regexp.MustCompile(`(?i)ng-version|angular`),
		regexp.MustCompile(`(?i)vue(\.runtime)?(\.min)?\.js|__VUE__`),
		regexp.MustCompile(`(?i)svelte`),
		regexp.MustCompile(`(?i)astro\.js`),
	}
)

// NeedsRendering decides if the site likely needs JS rendering.
// It optionally uses Rod to verify borderline cases.
func NeedsRendering(ctx context.Context, raw string, opts Options) (*Result, error) {
	opts = normalizeOptions(opts)
	u, err := normalizeURL(raw)
	if err != nil {
		return nil, err
	}

	out := &Result{
		InputURL: raw,
		Method:   "heuristic",
		Metrics:  map[string]any{},
	}

	body, finalURL, status, ctype, fetchErr := fetchHTML(ctx, u, opts.MaxBytes, opts.InsecureTLS, opts.UserAgent, opts.Client)
	out.FinalURL = finalURL
	out.Status = status
	out.ContentType = ctype
	out.Metrics["initial_html_bytes"] = len(body)

	if fetchErr != nil {
		out.Errors = map[string]string{"fetch": fetchErr.Error()}
		out.NeedsRendering = false
		out.Score = 0
		out.Confidence = "low"
		out.Signals = append(out.Signals, "fetch-failed")
		return out, fetchErr
	}

	if !isHTMLContentType(ctype) {
		out.NeedsRendering = false
		out.Score = 0
		out.Confidence = "high"
		out.Signals = append(out.Signals, "non-html-content-type")
		return out, nil
	}

	h := heuristicScore(body)
	out.Score = h.Score
	out.Signals = append(out.Signals, h.Signals...)
	out.Metrics["initial_visible_text_chars"] = h.VisibleTextChars
	out.Metrics["initial_script_tags"] = h.ScriptTags
	out.Metrics["initial_external_scripts"] = h.ExternalScripts
	out.Metrics["initial_root_empty"] = h.RootEmpty

	needVerify := false
	switch opts.Verify {
	case VerifyAlways:
		needVerify = true
	case VerifyNever:
		needVerify = false
	default:
		needVerify = (out.Score >= opts.BorderLow && out.Score < opts.BorderHigh)
	}

	if containsChallengeSignal(out.Signals) {
		out.NeedsRendering = true
		out.Confidence = "high"
		return out, nil
	}

	if !needVerify {
		finalizeHeuristic(out)
		return out, nil
	}

	out.Method = "rod-verified"
	renderedHTML, rodErr := renderHTMLWithRod(ctx, out.FinalURL, opts)
	if rodErr != nil {
		if out.Errors == nil {
			out.Errors = map[string]string{}
		}
		out.Errors["rod"] = rodErr.Error()
		finalizeHeuristic(out)
		out.Confidence = "low"
		out.Signals = append(out.Signals, "rod-verify-failed")
		return out, nil
	}

	rh := heuristicScore([]byte(renderedHTML))
	out.Metrics["rendered_html_bytes"] = len(renderedHTML)
	out.Metrics["rendered_visible_text_chars"] = rh.VisibleTextChars
	out.Metrics["rendered_script_tags"] = rh.ScriptTags
	out.Metrics["rendered_external_scripts"] = rh.ExternalScripts
	out.Metrics["rendered_root_empty"] = rh.RootEmpty

	delta := rh.VisibleTextChars - h.VisibleTextChars
	out.Metrics["visible_text_delta"] = delta

	if delta >= opts.TextDeltaMin || (h.VisibleTextChars < 150 && rh.VisibleTextChars >= 600) {
		out.NeedsRendering = true
		out.Confidence = "high"
		out.Signals = append(out.Signals, "rod-text-increase")
		return out, nil
	}

	if containsChallengeSignal(rh.Signals) {
		out.NeedsRendering = true
		out.Confidence = "high"
		out.Signals = append(out.Signals, "challenge-after-render")
		return out, nil
	}

	out.NeedsRendering = false
	out.Confidence = "high"
	out.Signals = append(out.Signals, "rod-no-meaningful-change")
	return out, nil
}

func EncodeResult(w io.Writer, res *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func normalizeOptions(opts Options) Options {
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 2 << 20
	}
	if opts.Verify == "" {
		opts.Verify = VerifyAuto
	}
	if opts.BorderLow == 0 {
		opts.BorderLow = 3
	}
	if opts.BorderHigh == 0 {
		opts.BorderHigh = 8
	}
	if opts.TextDeltaMin == 0 {
		opts.TextDeltaMin = 350
	}
	return opts
}

func heuristicScore(body []byte) Heur {
	s := string(body)
	h := Heur{}

	if jsRequiredRe.MatchString(s) {
		h.Signals = append(h.Signals, "js-required-text")
		h.Score += 5
	}
	if cfRe.MatchString(s) {
		h.Signals = append(h.Signals, "possible-cloudflare-challenge")
		h.Score += 7
	}
	if akamaiRe.MatchString(s) {
		h.Signals = append(h.Signals, "possible-akamai-bot-page")
		h.Score += 6
	}
	if perimeterXRe.MatchString(s) {
		h.Signals = append(h.Signals, "possible-perimeterx-bot-page")
		h.Score += 6
	}

	for _, re := range frameworkMarkers {
		if re.MatchString(s) {
			h.Signals = append(h.Signals, "framework-marker")
			h.Score += 3
			break
		}
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		h.Signals = append(h.Signals, "html-parse-failed")
		return h
	}

	var (
		scriptTags      int
		externalScripts int
		rootEmpty       bool
		visibleText     strings.Builder
	)

	var walk func(n *html.Node, excluded bool)
	walk = func(n *html.Node, excluded bool) {
		if n == nil {
			return
		}

		ex := excluded
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "script", "style", "noscript", "head", "svg":
				ex = true
			}
			if strings.EqualFold(n.Data, "script") {
				scriptTags++
				if attr(n, "src") != "" {
					externalScripts++
				}
			}
			id := strings.ToLower(strings.TrimSpace(attr(n, "id")))
			if id == "root" || id == "app" || id == "__next" || id == "__nuxt" {
				if !nodeHasMeaningfulContent(n) {
					rootEmpty = true
				}
			}
		}

		if n.Type == html.TextNode && !ex {
			t := normalizeSpace(n.Data)
			if t != "" {
				visibleText.WriteString(t)
				visibleText.WriteByte(' ')
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, ex)
		}
	}
	walk(doc, false)

	h.VisibleTextChars = countNonSpaceRunes(visibleText.String())
	h.ScriptTags = scriptTags
	h.ExternalScripts = externalScripts
	h.RootEmpty = rootEmpty

	if rootEmpty {
		h.Signals = append(h.Signals, "empty-root-container")
		h.Score += 4
	}
	if h.VisibleTextChars < 120 && externalScripts >= 2 {
		h.Signals = append(h.Signals, "very-low-visible-text")
		h.Score += 3
	} else if h.VisibleTextChars < 250 && externalScripts >= 4 {
		h.Signals = append(h.Signals, "low-visible-text-many-scripts")
		h.Score += 2
	}
	if externalScripts >= 6 {
		h.Signals = append(h.Signals, "many-external-scripts")
		h.Score += 2
	}

	return h
}

func finalizeHeuristic(r *Result) {
	switch {
	case r.Score >= 8:
		r.NeedsRendering = true
		r.Confidence = "high"
	case r.Score >= 5:
		r.NeedsRendering = true
		r.Confidence = "medium"
	case r.Score >= 3:
		r.NeedsRendering = false
		r.Confidence = "low"
	default:
		r.NeedsRendering = false
		r.Confidence = "high"
	}
}

func containsChallengeSignal(signals []string) bool {
	for _, s := range signals {
		if strings.Contains(s, "challenge") || strings.Contains(s, "bot-page") {
			return true
		}
	}
	return false
}

func renderHTMLWithRod(ctx context.Context, targetURL string, opts Options) (string, error) {
	return safe1(func() string {
		u := browser.NewLauncher(opts.Headless).MustLaunch()

		rodBrowser := rod.New().ControlURL(u).Context(ctx).MustConnect()
		defer rodBrowser.MustClose()

		page := rodBrowser.MustPage(targetURL)
		if opts.Timeout > 0 {
			page = page.Timeout(opts.Timeout)
		}
		if opts.UserAgent != "" {
			page.MustSetUserAgent(&proto.NetworkSetUserAgentOverride{
				UserAgent: opts.UserAgent,
			})
		}
		waitForStability(page)

		return page.MustHTML()
	})
}

func fetchHTML(ctx context.Context, u string, maxBytes int64, insecure bool, ua string, client *http.Client) ([]byte, string, int, string, error) {
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if insecure {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		client = &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", 0, "", err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0, "", err
	}
	defer resp.Body.Close()

	ctype := resp.Header.Get("Content-Type")
	finalURL := resp.Request.URL.String()

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, finalURL, resp.StatusCode, ctype, err
	}
	return b, finalURL, resp.StatusCode, ctype, nil
}

func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty url")
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	pu, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if pu.Host == "" {
		return "", fmt.Errorf("invalid url: missing host")
	}
	return pu.String(), nil
}

func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

func attr(n *html.Node, key string) string {
	key = strings.ToLower(key)
	for _, a := range n.Attr {
		if strings.ToLower(a.Key) == key {
			return a.Val
		}
	}
	return ""
}

func nodeHasMeaningfulContent(n *html.Node) bool {
	var found bool
	var f func(*html.Node)
	f = func(x *html.Node) {
		if x == nil || found {
			return
		}
		if x != n && x.Type == html.ElementNode {
			tag := strings.ToLower(x.Data)
			if tag == "script" || tag == "style" || tag == "noscript" {
				return
			}
			found = true
			return
		}
		if x.Type == html.TextNode && x != n {
			if len(normalizeSpace(x.Data)) >= 10 {
				found = true
				return
			}
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return found
}

func normalizeSpace(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func countNonSpaceRunes(s string) int {
	n := 0
	for _, r := range s {
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n
}

func waitForStability(page *rod.Page) {
	if page == nil {
		return
	}

	waitReq := page.WaitRequestIdle(500*time.Millisecond, nil, nil)
	page.MustWaitLoad()
	page.MustWaitIdle()
	waitReq()
}

func safe1[T any](fn func() T) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(), nil
}
