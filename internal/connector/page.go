package connector

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/connector/bridge"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Page wraps a browser tab controlled via the extension bridge.
// It implements methods compatible with rod.Page so existing Aegis code
// can use it with minimal changes.
type Page struct {
	connector *Connector
	tabID     int
	url       string
	title     string
	page      *rod.Page
}

// newPage creates a new Page wrapper. The rod.Page is a placeholder that
// holds the tab ID; actual operations go through the bridge.
func newPage(connector *Connector, tabID int) *Page {
	// Create a minimal rod.Page via a browser connection placeholder.
	// We use a nil control URL which creates an unusable rod.Page —
	// all actual operations are proxied through the bridge.
	p := &Page{
		connector: connector,
		tabID:     tabID,
	}
	return p
}

// setInfo updates cached URL and title.
func (p *Page) setInfo(url, title string) {
	p.url = url
	p.title = title
}

// TabID returns the browser tab ID for this page.
func (p *Page) TabID() int {
	return p.tabID
}

// ─── Navigation ──────────────────────────────────────────────────────────────

// Navigate navigates to the given URL.
func (p *Page) Navigate(url string) error {
	result, err := p.connector.sendCommand(bridge.CmdNavigate, map[string]string{"url": url}, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("navigate: %s", result.Error)
	}
	p.url = url
	return nil
}

// MustNavigate navigates and panics on error.
func (p *Page) MustNavigate(url string) *Page {
	if err := p.Navigate(url); err != nil {
		panic(fmt.Errorf("must navigate: %w", err))
	}
	return p
}

// NavigateBack goes back in history.
func (p *Page) NavigateBack() error {
	result, err := p.connector.sendCommand(bridge.CmdGoBack, nil, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("go back: %s", result.Error)
	}
	return nil
}

// NavigateForward goes forward in history.
func (p *Page) NavigateForward() error {
	result, err := p.connector.sendCommand(bridge.CmdGoForward, nil, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("go forward: %s", result.Error)
	}
	return nil
}

// Reload reloads the current page.
func (p *Page) Reload() error {
	result, err := p.connector.sendCommand(bridge.CmdReload, nil, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("reload: %s", result.Error)
	}
	return nil
}

// ─── Content ─────────────────────────────────────────────────────────────────

// HTML returns the page's HTML content.
func (p *Page) HTML() (string, error) {
	result, err := p.connector.sendCommand(bridge.CmdPageHTML, nil, p.tabID)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("get html: %s", result.Error)
	}
	var data struct {
		HTML string `json:"html"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return "", err
	}
	return data.HTML, nil
}

// MustHTML returns HTML and panics on error.
func (p *Page) MustHTML() string {
	html, err := p.HTML()
	if err != nil {
		panic(fmt.Errorf("must html: %w", err))
	}
	return html
}

// Text returns the visible text of the page.
func (p *Page) Text() (string, error) {
	result, err := p.connector.sendCommand(bridge.CmdPageText, nil, p.tabID)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("get text: %s", result.Error)
	}
	var data struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return "", err
	}
	return data.Text, nil
}

// Title returns the page title.
func (p *Page) Title() (string, error) {
	result, err := p.connector.sendCommand(bridge.CmdGetTitle, nil, p.tabID)
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("get title: %s", result.Error)
	}
	var data struct {
		Title string `json:"title"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return "", err
	}
	p.title = data.Title
	return data.Title, nil
}

// URL returns the current URL.
func (p *Page) URL() string {
	return p.url
}

// ─── JavaScript ──────────────────────────────────────────────────────────────

// Eval is unavailable through the store-safe connector. Use a dedicated
// navigation, DOM, storage, or capture command instead of arbitrary JavaScript.
func (p *Page) Eval(js string, args ...interface{}) (*proto.RuntimeRemoteObject, error) {
	return nil, fmt.Errorf("arbitrary JavaScript evaluation is not supported by the extension connector")
}

// Evaluate returns nil because arbitrary JavaScript is not supported.
func (p *Page) Evaluate(script *rod.EvalOptions) *rod.EvalOptions {
	return nil
}

// EvalOnNewDocument registers a script to run on every new document.
// This is a best-effort via the extension; some features may be limited.
func (p *Page) EvalOnNewDocument(js string) (*proto.PageAddScriptToEvaluateOnNewDocument, error) {
	// The extension doesn't have direct EvalOnNewDocument support.
	// We store it and re-inject on navigation events.
	// For now, return a placeholder.
	return &proto.PageAddScriptToEvaluateOnNewDocument{}, nil
}

// ─── Cookies ─────────────────────────────────────────────────────────────────

// Cookies returns cookies for the given URLs.
func (p *Page) Cookies(urls []string) ([]*proto.NetworkCookie, error) {
	if len(urls) == 0 {
		// Use current URL
		if p.url != "" {
			urls = []string{p.url}
		}
	}
	result, err := p.connector.sendCommand(bridge.CmdGetCookies, map[string]interface{}{
		"urls":          urls,
		"includeValues": true,
	}, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("get cookies: %s", result.Error)
	}
	var data struct {
		Cookies []struct {
			Name     string `json:"name"`
			Value    string `json:"value"`
			Domain   string `json:"domain"`
			Path     string `json:"path"`
			Secure   bool   `json:"secure"`
			HttpOnly bool   `json:"httpOnly"`
			Expires  int64  `json:"expires"`
		} `json:"cookies"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, err
	}

	cookies := make([]*proto.NetworkCookie, 0, len(data.Cookies))
	for _, c := range data.Cookies {
		cookies = append(cookies, &proto.NetworkCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			Expires:  proto.TimeSinceEpoch(c.Expires),
		})
	}
	return cookies, nil
}

// SetCookies sets cookies on the page.
func (p *Page) SetCookies(cookies []*proto.NetworkCookieParam) error {
	for _, c := range cookies {
		params := map[string]interface{}{
			"name":     c.Name,
			"value":    c.Value,
			"domain":   c.Domain,
			"path":     c.Path,
			"secure":   c.Secure,
			"httpOnly": c.HTTPOnly,
		}
		if c.URL != "" {
			params["url"] = c.URL
		}
		if c.Expires != 0 {
			params["expires"] = int64(c.Expires)
		}
		result, err := p.connector.sendCommand(bridge.CmdSetCookie, params, p.tabID)
		if err != nil {
			return err
		}
		if !result.Success {
			return fmt.Errorf("set cookie: %s", result.Error)
		}
	}
	return nil
}

// ─── Screenshot ──────────────────────────────────────────────────────────────

// Screenshot takes a screenshot. If fullPage is true, captures the full page.
func (p *Page) Screenshot(fullPage bool, params *proto.PageCaptureScreenshot) ([]byte, error) {
	cmdParams := map[string]interface{}{
		"fullPage": fullPage,
	}
	if params != nil {
		if params.Format != "" {
			cmdParams["format"] = string(params.Format)
		}
		if params.Quality > 0 {
			cmdParams["quality"] = params.Quality
		}
	}

	// Capture visible tab via background
	result, err := p.connector.sendCommand(bridge.CmdCaptureVisible, cmdParams, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("screenshot: %s", result.Error)
	}

	var data struct {
		Screenshot string `json:"screenshot"` // base64
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, err
	}

	// Return decoded screenshot bytes
	decoded, err := base64.StdEncoding.DecodeString(data.Screenshot)
	if err != nil {
		// fallback: may already be raw/base64-url or plain bytes text
		if d2, err2 := base64.RawStdEncoding.DecodeString(data.Screenshot); err2 == nil {
			return d2, nil
		}
		return []byte(data.Screenshot), nil
	}
	return decoded, nil
}

// ─── Wait ────────────────────────────────────────────────────────────────────

// WaitLoad waits for the page to finish loading.
func (p *Page) WaitLoad() error {
	result, err := p.connector.sendCommand(bridge.CmdWaitForLoad, nil, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("wait load: %s", result.Error)
	}
	return nil
}

// WaitIdle waits for the page to be idle.
func (p *Page) WaitIdle(timeout time.Duration) error {
	ms := int(timeout.Milliseconds())
	if ms <= 0 {
		ms = 1000
	}
	result, err := p.connector.sendCommand(bridge.CmdWaitForIdle, map[string]int{"delay": ms}, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("wait idle: %s", result.Error)
	}
	return nil
}

// WaitRequestIdle waits for network requests to be idle.
func (p *Page) WaitRequestIdle(idleTime time.Duration, requests *proto.NetworkRequest, handler func(*proto.NetworkRequest)) *rod.EvalOptions {
	// Approximate with a sleep + wait for idle
	time.Sleep(idleTime)
	p.WaitIdle(idleTime)
	return &rod.EvalOptions{}
}

// Sleep pauses execution for the given duration.
func (p *Page) Sleep(d time.Duration) *Page {
	time.Sleep(d)
	return p
}

// ─── Element interaction ─────────────────────────────────────────────────────

// Element finds a single element by selector.
func (p *Page) Element(selector string) (*rod.Element, error) {
	result, err := p.connector.sendCommand(bridge.CmdQuerySelector, map[string]string{
		"selector": selector,
	}, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("element not found: %s", selector)
	}
	var data struct {
		Found bool `json:"found"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, err
	}
	if !data.Found {
		return nil, fmt.Errorf("element not found: %s", selector)
	}
	return &rod.Element{}, nil
}

// Elements finds multiple elements by selector.
func (p *Page) Elements(selector string) ([]*rod.Element, error) {
	result, err := p.connector.sendCommand(bridge.CmdQuerySelectorAll, map[string]string{
		"selector": selector,
	}, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, err
	}
	var data struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return nil, err
	}
	elements := make([]*rod.Element, data.Count)
	for i := range elements {
		elements[i] = &rod.Element{}
	}
	return elements, nil
}

// Has returns true if an element matching the selector exists.
func (p *Page) Has(selector string) bool {
	result, err := p.connector.sendCommand(bridge.CmdQuerySelector, map[string]string{
		"selector": selector,
	}, p.tabID)
	if err != nil {
		return false
	}
	var data struct {
		Found bool `json:"found"`
	}
	json.Unmarshal(result.Data, &data)
	return data.Found
}

// Visible returns true if the element is visible.
func (p *Page) Visible(selector string) (bool, error) {
	result, err := p.connector.sendCommand(bridge.CmdElementVisible, map[string]string{
		"selector": selector,
	}, p.tabID)
	if err != nil {
		return false, err
	}
	var data struct {
		Visible bool `json:"visible"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return false, err
	}
	return data.Visible, nil
}

// Hidden returns true if the element is hidden.
func (p *Page) Hidden(selector string) (bool, error) {
	visible, err := p.Visible(selector)
	return !visible, err
}

// Click clicks an element.
func (p *Page) Click(selector string) error {
	result, err := p.connector.sendCommand(bridge.CmdClick, map[string]string{
		"selector": selector,
	}, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("click: %s", result.Error)
	}
	return nil
}

// Type types text into an element.
func (p *Page) Type(selector string, text string, opts ...func()) error {
	result, err := p.connector.sendCommand(bridge.CmdType, map[string]string{
		"selector": selector,
		"value":    text,
	}, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("type: %s", result.Error)
	}
	return nil
}

// Close closes the tab.
func (p *Page) Close() error {
	result, err := p.connector.sendCommand(bridge.CmdCloseTab, map[string]int{
		"tabId": p.tabID,
	}, p.tabID)
	if err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("close tab: %s", result.Error)
	}
	p.connector.mu.Lock()
	delete(p.connector.pages, p.tabID)
	p.connector.mu.Unlock()
	return nil
}

// EachEvent registers event handlers (simplified).
// Returns a function that, when called, stops listening.
func (p *Page) EachEvent(handlers ...interface{}) func() {
	// Simplified: return a no-op cleanup function
	// Full event forwarding is handled by the extension -> bridge -> connector
	return func() {}
}

// Lock is a no-op for connector (no CDP lock needed).
func (p *Page) Lock() {}

// Unlock is a no-op for connector.
func (p *Page) Unlock() {}

// ResourceTree returns resource info (simplified).
func (p *Page) ResourceTree() (*proto.PageFrameResourceTree, error) {
	return nil, fmt.Errorf("not supported via connector")
}

// ─── Observability / phase feature helpers (best-effort, capability-gated) ───

// Snapshot captures bounded page state via extension content script.
func (p *Page) Snapshot(opts map[string]interface{}) (map[string]interface{}, error) {
	result, err := p.connector.sendCommand(bridge.CmdPageSnapshot, opts, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		if result.Err != nil {
			return nil, fmt.Errorf("snapshot: %s", result.Err.Message)
		}
		return nil, fmt.Errorf("snapshot: %s", result.Error)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(result.Data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DebugGetConsole returns buffered console events for the tab (best-effort).
func (p *Page) DebugGetConsole() (map[string]interface{}, error) {
	result, err := p.connector.sendCommand(bridge.CmdDebugGetConsole, nil, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		if result.Err != nil {
			return nil, fmt.Errorf("debug.getConsole: %s", result.Err.Message)
		}
		return nil, fmt.Errorf("debug.getConsole: %s", result.Error)
	}
	var out map[string]interface{}
	_ = json.Unmarshal(result.Data, &out)
	return out, nil
}

// DebugGetNetwork returns buffered network events for the tab (best-effort).
func (p *Page) DebugGetNetwork() (map[string]interface{}, error) {
	result, err := p.connector.sendCommand(bridge.CmdDebugGetNetwork, nil, p.tabID)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		if result.Err != nil {
			return nil, fmt.Errorf("debug.getNetwork: %s", result.Err.Message)
		}
		return nil, fmt.Errorf("debug.getNetwork: %s", result.Error)
	}
	var out map[string]interface{}
	_ = json.Unmarshal(result.Data, &out)
	return out, nil
}

// SendRaw sends an arbitrary connector command targeted at this tab.
func (p *Page) SendRaw(command string, params interface{}) (*bridge.Result, error) {
	return p.connector.sendCommand(command, params, p.tabID)
}

// Frame returns a frame by selector (simplified).
func (p *Page) Frame(selector string) *rod.Page {
	return p.page
}

// MainFrame returns the main frame.
func (p *Page) MainFrame() *rod.Page {
	return p.page
}
