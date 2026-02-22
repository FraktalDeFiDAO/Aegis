// Package browser provides browser automation utilities
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Injector provides methods for programmatic payload injection and event triggering
type Injector struct {
	page          *rod.Page
	browser       *rod.Browser
	timeout       time.Duration
	dialogHandler chan bool
	consoleErrors []string
}

// InjectorOption configures the injector
type InjectorOption func(*Injector)

// WithInjectorTimeout sets the injection timeout
func WithInjectorTimeout(timeout time.Duration) InjectorOption {
	return func(i *Injector) {
		i.timeout = timeout
	}
}

// NewInjector creates a new payload injector
func NewInjector(page *rod.Page, opts ...InjectorOption) *Injector {
	i := &Injector{
		page:          page,
		timeout:       10 * time.Second,
		dialogHandler: make(chan bool, 10),
		consoleErrors: []string{},
	}

	for _, opt := range opts {
		opt(i)
	}

	// Setup console listener
	i.setupConsoleListener()

	return i
}

// setupConsoleListener captures console messages
func (i *Injector) setupConsoleListener() {
	go i.page.EachEvent(func(e *proto.RuntimeConsoleAPICalled) {
		if e.Type == proto.RuntimeConsoleAPICalledTypeError {
			for _, arg := range e.Args {
				val := arg.Value.Str()
				if val != "" {
					i.consoleErrors = append(i.consoleErrors, val)
				}
			}
		}
	})()
}

// InjectionResult holds the result of a payload injection
type InjectionResult struct {
	Success       bool     `json:"success"`
	DialogTriggered bool   `json:"dialog_triggered"`
	DialogMessage string   `json:"dialog_message,omitempty"`
	ConsoleErrors []string `json:"console_errors,omitempty"`
	Exception     string   `json:"exception,omitempty"`
	Evidence      string   `json:"evidence,omitempty"`
}

// InjectPayload injects a payload into a specified element
func (i *Injector) InjectPayload(selector string, payload string) (*InjectionResult, error) {
	result := &InjectionResult{}

	ctx, cancel := context.WithTimeout(context.Background(), i.timeout)
	defer cancel()

	// Setup dialog handler
	dialogChan := make(chan string, 1)
	i.page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		result.DialogTriggered = true
		result.DialogMessage = e.Message
		dialogChan <- e.Message
		// Dismiss the dialog
		_ = proto.PageHandleJavaScriptDialog{Accept: true}.Call(i.page)
	})

	// Find the element
	element, err := i.page.Context(ctx).Element(selector)
	if err != nil {
		return result, fmt.Errorf("element not found: %s", selector)
	}

	// Get element tag name to determine injection method
	tagName, err := element.Eval(`() => this.tagName.toLowerCase()`)
	if err != nil {
		return result, err
	}

	tag := tagName.Value.Str()

	// Inject based on element type
	switch tag {
	case "input", "textarea":
		err = i.injectIntoInput(element, payload)
	case "script":
		err = i.injectIntoScript(element, payload)
	case "div", "span", "p":
		err = i.injectIntoContainer(element, payload)
	case "a":
		err = i.injectIntoAnchor(element, payload)
	case "img":
		err = i.injectIntoImage(element, payload)
	case "iframe":
		err = i.injectIntoIframe(element, payload)
	default:
		err = i.injectGeneric(element, payload)
	}

	if err != nil {
		result.Exception = err.Error()
		return result, err
	}

	// Wait for potential dialog
	select {
	case msg := <-dialogChan:
		result.DialogMessage = msg
		result.Success = true
	case <-time.After(500 * time.Millisecond):
		// No dialog triggered
	}

	// Capture console errors
	result.ConsoleErrors = i.consoleErrors

	return result, nil
}

// injectIntoInput injects payload into input/textarea elements
func (i *Injector) injectIntoInput(element *rod.Element, payload string) error {
	// Clear existing value
	_, err := element.Eval(`() => { this.value = ''; }`)
	if err != nil {
		return err
	}

	// Input the payload
	err = element.Input(payload)
	if err != nil {
		return err
	}

	// Trigger events
	i.TriggerEvent(element, "input")
	i.TriggerEvent(element, "change")
	i.TriggerEvent(element, "blur")

	return nil
}

// injectIntoScript injects payload into script elements
func (i *Injector) injectIntoScript(element *rod.Element, payload string) error {
	// Create new script with payload
	_, err := i.page.Eval(fmt.Sprintf(`() => {
		var script = document.createElement('script');
		script.textContent = %q;
		document.head.appendChild(script);
	}`, payload))
	return err
}

// injectIntoContainer injects payload into container elements
func (i *Injector) injectIntoContainer(element *rod.Element, payload string) error {
	// Inject via innerHTML
	_, err := element.Eval(fmt.Sprintf(`() => { this.innerHTML = %q; }`, payload))
	if err != nil {
		return err
	}

	// If payload contains script tags, they won't execute via innerHTML
	// Try alternative execution methods
	if strings.Contains(payload, "<script") {
		// Insert and execute
		_, err = i.page.Eval(fmt.Sprintf(`() => {
			var range = document.createRange();
			var frag = range.createContextualFragment(%q);
			document.body.appendChild(frag);
		}`, payload))
	}

	return err
}

// injectIntoAnchor injects payload into anchor elements
func (i *Injector) injectIntoAnchor(element *rod.Element, payload string) error {
	// Set href if it's a javascript: payload
	if strings.HasPrefix(strings.ToLower(payload), "javascript:") {
		_, err := element.Eval(fmt.Sprintf(`() => { this.href = %q; }`, payload))
		if err != nil {
			return err
		}
		// Click to trigger
		return element.Click(proto.InputMouseButtonLeft)
	}

	// Otherwise inject into innerHTML
	_, err := element.Eval(fmt.Sprintf(`() => { this.innerHTML = %q; }`, payload))
	return err
}

// injectIntoImage injects payload into image elements
func (i *Injector) injectIntoImage(element *rod.Element, payload string) error {
	// Check if payload is an event handler
	if strings.Contains(payload, "onerror") || strings.Contains(payload, "onload") {
		// Create new image with payload
		_, err := i.page.Eval(fmt.Sprintf(`() => {
			var div = document.createElement('div');
			div.innerHTML = %q;
			document.body.appendChild(div);
		}`, payload))
		return err
	}

	// Otherwise set src to trigger onerror
	_, err := element.Eval(`() => { this.src = 'x'; }`)
	return err
}

// injectIntoIframe injects payload into iframe elements
func (i *Injector) injectIntoIframe(element *rod.Element, payload string) error {
	// Check for srcdoc injection
	if strings.Contains(payload, "srcdoc") {
		_, err := i.page.Eval(fmt.Sprintf(`() => {
			var div = document.createElement('div');
			div.innerHTML = %q;
			document.body.appendChild(div);
		}`, payload))
		return err
	}

	// Set src if javascript: payload
	if strings.HasPrefix(strings.ToLower(payload), "javascript:") {
		_, err := element.Eval(fmt.Sprintf(`() => { this.src = %q; }`, payload))
		return err
	}

	// Try srcdoc
	_, err := element.Eval(fmt.Sprintf(`() => { this.srcdoc = %q; }`, payload))
	return err
}

// injectGeneric attempts generic payload injection
func (i *Injector) injectGeneric(element *rod.Element, payload string) error {
	// Try innerHTML first
	_, err := element.Eval(fmt.Sprintf(`() => { this.innerHTML = %q; }`, payload))
	if err != nil {
		// Try outerHTML
		_, err = element.Eval(fmt.Sprintf(`() => { this.outerHTML = %q; }`, payload))
	}
	return err
}

// TriggerEvent triggers a DOM event on an element
func (i *Injector) TriggerEvent(element *rod.Element, eventName string) error {
	_, err := element.Eval(fmt.Sprintf(`() => {
		var event = new Event(%q, { bubbles: true, cancelable: true });
		this.dispatchEvent(event);
	}`, eventName))
	return err
}

// TriggerMouseEvent triggers a mouse event on an element
func (i *Injector) TriggerMouseEvent(element *rod.Element, eventName string) error {
	_, err := element.Eval(fmt.Sprintf(`() => {
		var event = new MouseEvent(%q, {
			view: window,
			bubbles: true,
			cancelable: true,
			clientX: this.getBoundingClientRect().x + 1,
			clientY: this.getBoundingClientRect().y + 1
		});
		this.dispatchEvent(event);
	}`, eventName))
	return err
}

// TriggerKeyboardEvent triggers a keyboard event on an element
func (i *Injector) TriggerKeyboardEvent(element *rod.Element, eventName string, key string) error {
	_, err := element.Eval(fmt.Sprintf(`() => {
		var event = new KeyboardEvent(%q, {
			key: %q,
			code: %q,
			bubbles: true,
			cancelable: true
		});
		this.dispatchEvent(event);
	}`, eventName, key, "Key"+strings.ToUpper(key[:1])+key[1:]))
	return err
}

// CheckDialogTriggered returns whether a dialog was triggered
func (i *Injector) CheckDialogTriggered() bool {
	select {
	case <-i.dialogHandler:
		return true
	default:
		return false
	}
}

// CaptureConsoleErrors returns captured console errors
func (i *Injector) CaptureConsoleErrors() []string {
	return i.consoleErrors
}

// ClearConsoleErrors clears the captured console errors
func (i *Injector) ClearConsoleErrors() {
	i.consoleErrors = []string{}
}

// ExecuteScript executes arbitrary JavaScript and returns the result
func (i *Injector) ExecuteScript(script string) (interface{}, error) {
	result, err := i.page.Eval(script)
	if err != nil {
		return nil, err
	}
	return result.Value.Val(), nil
}

// TestXSSPayload tests an XSS payload and returns detailed results
func (i *Injector) TestXSSPayload(targetURL, selector, payload string) (*XSSTestResult, error) {
	result := &XSSTestResult{
		URL:     targetURL,
		Payload: payload,
	}

	// Navigate to target
	err := i.page.Navigate(targetURL)
	if err != nil {
		return result, err
	}
	i.page.MustWaitLoad()

	// Clear console errors
	i.ClearConsoleErrors()

	// Setup dialog watcher
	dialogTriggered := false
	dialogMessage := ""

	i.page.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		dialogTriggered = true
		dialogMessage = e.Message
		_ = proto.PageHandleJavaScriptDialog{Accept: true}.Call(i.page)
	})

	// Inject payload
	injResult, err := i.InjectPayload(selector, payload)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Wait for potential execution
	time.Sleep(500 * time.Millisecond)

	// Check results
	result.DialogTriggered = dialogTriggered || injResult.DialogTriggered
	result.DialogMessage = dialogMessage
	if result.DialogMessage == "" {
		result.DialogMessage = injResult.DialogMessage
	}
	result.ConsoleErrors = i.CaptureConsoleErrors()
	result.Vulnerable = result.DialogTriggered

	// Get page source for evidence
	html, _ := i.page.HTML()
	if strings.Contains(html, payload) {
		result.Reflected = true
		result.Evidence = extractEvidence(html, payload)
	}

	return result, nil
}

// XSSTestResult holds XSS test results
type XSSTestResult struct {
	URL             string   `json:"url"`
	Payload         string   `json:"payload"`
	Vulnerable      bool     `json:"vulnerable"`
	Reflected       bool     `json:"reflected"`
	DialogTriggered bool     `json:"dialog_triggered"`
	DialogMessage   string   `json:"dialog_message,omitempty"`
	ConsoleErrors   []string `json:"console_errors,omitempty"`
	Evidence        string   `json:"evidence,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// extractEvidence extracts evidence around the payload location
func extractEvidence(html, payload string) string {
	idx := strings.Index(html, payload)
	if idx == -1 {
		return ""
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 50
	if end > len(html) {
		end = len(html)
	}

	evidence := html[start:end]
	// Clean up
	evidence = strings.ReplaceAll(evidence, "\n", " ")
	evidence = strings.ReplaceAll(evidence, "\r", "")
	evidence = strings.ReplaceAll(evidence, "\t", " ")

	return evidence
}

// GetDOMState captures the current DOM state for analysis
func (i *Injector) GetDOMState() (*DOMState, error) {
	state := &DOMState{}

	// Get cookies
	cookies, err := i.page.Cookies(nil)
	if err == nil {
		for _, c := range cookies {
			state.Cookies = append(state.Cookies, CookieInfo{
				Name:     c.Name,
				Value:    truncateString(c.Value, 50),
				HttpOnly: c.HTTPOnly,
				Secure:   c.Secure,
				SameSite: string(c.SameSite),
			})
		}
	}

	// Get localStorage
	localStorage, err := i.page.Eval(`() => JSON.stringify(localStorage)`)
	if err == nil {
		var ls map[string]string
		json.Unmarshal([]byte(localStorage.Value.Str()), &ls)
		state.LocalStorage = ls
	}

	// Get sessionStorage
	sessionStorage, err := i.page.Eval(`() => JSON.stringify(sessionStorage)`)
	if err == nil {
		var ss map[string]string
		json.Unmarshal([]byte(sessionStorage.Value.Str()), &ss)
		state.SessionStorage = ss
	}

	// Get forms
	forms, err := i.page.Eval(`() => {
		var forms = [];
		document.querySelectorAll('form').forEach(f => {
			forms.push({
				action: f.action,
				method: f.method,
				hasCSRF: !!f.querySelector('[name*="csrf"], [name*="token"]')
			});
		});
		return JSON.stringify(forms);
	}`)
	if err == nil {
		json.Unmarshal([]byte(forms.Value.Str()), &state.Forms)
	}

	return state, nil
}

// DOMState represents the current DOM state
type DOMState struct {
	Cookies        []CookieInfo      `json:"cookies"`
	LocalStorage   map[string]string `json:"local_storage"`
	SessionStorage map[string]string `json:"session_storage"`
	Forms          []FormInfo        `json:"forms"`
}

// CookieInfo represents cookie information
type CookieInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	HttpOnly bool   `json:"http_only"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"same_site"`
}

// FormInfo represents form information
type FormInfo struct {
	Action  string `json:"action"`
	Method  string `json:"method"`
	HasCSRF bool   `json:"has_csrf"`
}

// truncateString truncates a string to maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
