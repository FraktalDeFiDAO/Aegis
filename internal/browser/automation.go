// Package browser provides browser automation utilities
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"gopkg.in/yaml.v3"
)

// Script represents a browser automation script
type Script struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string            `json:"version,omitempty" yaml:"version,omitempty"`
	Variables   map[string]string `json:"variables,omitempty" yaml:"variables,omitempty"`
	Settings    ScriptSettings    `json:"settings,omitempty" yaml:"settings,omitempty"`
	Actions     []Action          `json:"actions" yaml:"actions"`
	OnError     []Action          `json:"on_error,omitempty" yaml:"on_error,omitempty"`
}

// ScriptSettings holds script configuration
type ScriptSettings struct {
	Headless        bool   `json:"headless,omitempty" yaml:"headless,omitempty"`
	Timeout         string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Viewport        *Viewport `json:"viewport,omitempty" yaml:"viewport,omitempty"`
	UserAgent       string `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
	SlowMotion      string `json:"slow_motion,omitempty" yaml:"slow_motion,omitempty"`
	ScreenshotsDir  string `json:"screenshots_dir,omitempty" yaml:"screenshots_dir,omitempty"`
	RecordVideo     bool   `json:"record_video,omitempty" yaml:"record_video,omitempty"`
	IgnoreHTTPSErrs bool   `json:"ignore_https_errors,omitempty" yaml:"ignore_https_errors,omitempty"`
}

// Viewport defines browser viewport size
type Viewport struct {
	Width  int `json:"width" yaml:"width"`
	Height int `json:"height" yaml:"height"`
}

// Action represents a browser action
type Action struct {
	// Action identification
	ID   string `json:"id,omitempty" yaml:"id,omitempty"`
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	Type ActionType `json:"type" yaml:"type"`

	// Navigation actions
	URL string `json:"url,omitempty" yaml:"url,omitempty"`

	// Element selection
	Selector     string `json:"selector,omitempty" yaml:"selector,omitempty"`
	XPath        string `json:"xpath,omitempty" yaml:"xpath,omitempty"`
	Text         string `json:"text,omitempty" yaml:"text,omitempty"`
	ContainsText string `json:"contains_text,omitempty" yaml:"contains_text,omitempty"`

	// Input actions
	Value    string `json:"value,omitempty" yaml:"value,omitempty"`
	Keys     string `json:"keys,omitempty" yaml:"keys,omitempty"`
	Filename string `json:"filename,omitempty" yaml:"filename,omitempty"`

	// Wait actions
	Duration string `json:"duration,omitempty" yaml:"duration,omitempty"`
	State    string `json:"state,omitempty" yaml:"state,omitempty"` // visible, hidden, attached, detached

	// JavaScript execution
	Script     string `json:"script,omitempty" yaml:"script,omitempty"`
	Expression string `json:"expression,omitempty" yaml:"expression,omitempty"`

	// Screenshot/recording
	Path     string `json:"path,omitempty" yaml:"path,omitempty"`
	FullPage bool   `json:"full_page,omitempty" yaml:"full_page,omitempty"`

	// Assertions
	Expected  string `json:"expected,omitempty" yaml:"expected,omitempty"`
	Pattern   string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Attribute string `json:"attribute,omitempty" yaml:"attribute,omitempty"`

	// Control flow
	Condition string   `json:"condition,omitempty" yaml:"condition,omitempty"`
	Actions   []Action `json:"actions,omitempty" yaml:"actions,omitempty"` // for loop/if
	Count     int      `json:"count,omitempty" yaml:"count,omitempty"`     // for loop

	// Data extraction
	Variable string   `json:"variable,omitempty" yaml:"variable,omitempty"` // store result in variable
	Extract  []Extract `json:"extract,omitempty" yaml:"extract,omitempty"`

	// Options
	Timeout  string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Optional bool   `json:"optional,omitempty" yaml:"optional,omitempty"`
}

// Extract defines data extraction rules
type Extract struct {
	Name      string `json:"name" yaml:"name"`
	Selector  string `json:"selector,omitempty" yaml:"selector,omitempty"`
	XPath     string `json:"xpath,omitempty" yaml:"xpath,omitempty"`
	Attribute string `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	Regex     string `json:"regex,omitempty" yaml:"regex,omitempty"`
	All       bool   `json:"all,omitempty" yaml:"all,omitempty"` // extract all matches
}

// ActionType represents the type of browser action
type ActionType string

const (
	// Navigation
	ActionNavigate     ActionType = "navigate"
	ActionGoBack       ActionType = "go_back"
	ActionGoForward    ActionType = "go_forward"
	ActionReload       ActionType = "reload"

	// Element interaction
	ActionClick        ActionType = "click"
	ActionDoubleClick  ActionType = "double_click"
	ActionRightClick   ActionType = "right_click"
	ActionHover        ActionType = "hover"
	ActionFocus        ActionType = "focus"
	ActionBlur         ActionType = "blur"
	ActionScroll       ActionType = "scroll"
	ActionScrollIntoView ActionType = "scroll_into_view"

	// Input
	ActionType_        ActionType = "type"  // renamed to avoid conflict
	ActionFill         ActionType = "fill"
	ActionClear        ActionType = "clear"
	ActionPress        ActionType = "press"
	ActionUpload       ActionType = "upload"
	ActionSelect       ActionType = "select"
	ActionCheck        ActionType = "check"
	ActionUncheck      ActionType = "uncheck"

	// Waiting
	ActionWait         ActionType = "wait"
	ActionWaitFor      ActionType = "wait_for"
	ActionWaitForNav   ActionType = "wait_for_navigation"
	ActionWaitForLoad  ActionType = "wait_for_load"
	ActionWaitForIdle  ActionType = "wait_for_idle"

	// JavaScript
	ActionEvaluate     ActionType = "evaluate"
	ActionEvaluateAll  ActionType = "evaluate_all"

	// Screenshots/Recording
	ActionScreenshot   ActionType = "screenshot"
	ActionPDF          ActionType = "pdf"

	// Assertions
	ActionAssert       ActionType = "assert"
	ActionAssertText   ActionType = "assert_text"
	ActionAssertValue  ActionType = "assert_value"
	ActionAssertAttr   ActionType = "assert_attribute"
	ActionAssertURL    ActionType = "assert_url"
	ActionAssertTitle  ActionType = "assert_title"
	ActionAssertExists ActionType = "assert_exists"
	ActionAssertVisible ActionType = "assert_visible"

	// Data extraction
	ActionExtract      ActionType = "extract"
	ActionExtractText  ActionType = "extract_text"
	ActionExtractAttr  ActionType = "extract_attribute"
	ActionExtractHTML  ActionType = "extract_html"

	// Control flow
	ActionIf           ActionType = "if"
	ActionLoop         ActionType = "loop"
	ActionForEach      ActionType = "for_each"

	// Frame handling
	ActionSwitchFrame  ActionType = "switch_frame"
	ActionSwitchMain   ActionType = "switch_main"

	// Tab management
	ActionNewTab       ActionType = "new_tab"
	ActionSwitchTab    ActionType = "switch_tab"
	ActionCloseTab     ActionType = "close_tab"
	ActionGetTabs      ActionType = "get_tabs"

	// Dialogs
	ActionAcceptDialog ActionType = "accept_dialog"
	ActionDismissDialog ActionType = "dismiss_dialog"

	// Cookies
	ActionSetCookie    ActionType = "set_cookie"
	ActionGetCookies   ActionType = "get_cookies"
	ActionClearCookies ActionType = "clear_cookies"

	// Storage
	ActionSetStorage   ActionType = "set_storage"
	ActionGetStorage   ActionType = "get_storage"
	ActionClearStorage ActionType = "clear_storage"

	// Debug
	ActionPause        ActionType = "pause"
	ActionLog          ActionType = "log"
)

// ActionResult holds the result of an action execution
type ActionResult struct {
	ActionID   string        `json:"action_id,omitempty"`
	ActionName string        `json:"action_name,omitempty"`
	ActionType ActionType    `json:"action_type"`
	Status     string        `json:"status"` // success, failure, skipped
	Duration   time.Duration `json:"duration"`
	Output     interface{}   `json:"output,omitempty"`
	Error      string        `json:"error,omitempty"`
	Screenshot string        `json:"screenshot,omitempty"`
}

// ScriptResult holds the complete script execution result
type ScriptResult struct {
	ScriptName  string            `json:"script_name"`
	Status      string            `json:"status"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     time.Time         `json:"end_time"`
	Duration    time.Duration     `json:"duration"`
	Actions     []ActionResult    `json:"actions"`
	Variables   map[string]string `json:"variables"`
	Extracted   map[string]interface{} `json:"extracted,omitempty"`
	Screenshots []string          `json:"screenshots,omitempty"`
	Errors      []string          `json:"errors,omitempty"`
}

// Automator executes browser automation scripts
type Automator struct {
	browser      *rod.Browser
	page         *rod.Page
	tabs         map[string]*rod.Page  // named tabs for easy switching
	tabOrder     []string              // ordered list of tab names
	script       *Script
	variables    map[string]string
	extracted    map[string]interface{}
	screenshots  []string
	timeout      time.Duration
	slowMotion   time.Duration
	headless     bool
	verbose      bool
	screenshotsDir string
}

// AutomatorOption configures the automator
type AutomatorOption func(*Automator)

// WithHeadless sets headless mode
func WithHeadless(headless bool) AutomatorOption {
	return func(a *Automator) {
		a.headless = headless
	}
}

// WithTimeout sets the default timeout
func WithAutomatorTimeout(timeout time.Duration) AutomatorOption {
	return func(a *Automator) {
		a.timeout = timeout
	}
}

// WithSlowMotion sets slow motion delay between actions
func WithSlowMotion(delay time.Duration) AutomatorOption {
	return func(a *Automator) {
		a.slowMotion = delay
	}
}

// WithAutomatorVerbose enables verbose output
func WithAutomatorVerbose(verbose bool) AutomatorOption {
	return func(a *Automator) {
		a.verbose = verbose
	}
}

// WithScreenshotsDir sets the screenshots directory
func WithScreenshotsDir(dir string) AutomatorOption {
	return func(a *Automator) {
		a.screenshotsDir = dir
	}
}

// NewAutomator creates a new browser automator
func NewAutomator(opts ...AutomatorOption) *Automator {
	a := &Automator{
		variables:   make(map[string]string),
		extracted:   make(map[string]interface{}),
		tabs:        make(map[string]*rod.Page),
		tabOrder:    []string{},
		screenshots: []string{},
		timeout:     30 * time.Second,
		headless:    true,
		verbose:     false,
		screenshotsDir: "./screenshots",
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// LoadScript loads a script from a file
func LoadScript(path string) (*Script, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read script file: %w", err)
	}

	var script Script
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &script); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, &script); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(data, &script); err != nil {
			if err := json.Unmarshal(data, &script); err != nil {
				return nil, fmt.Errorf("failed to parse script (tried YAML and JSON)")
			}
		}
	}

	return &script, nil
}

// Run executes a browser automation script
func (a *Automator) Run(ctx context.Context, script *Script) (*ScriptResult, error) {
	a.script = script
	startTime := time.Now()

	result := &ScriptResult{
		ScriptName: script.Name,
		StartTime:  startTime,
		Variables:  make(map[string]string),
		Extracted:  make(map[string]interface{}),
	}

	// Apply script settings
	a.applySettings(script.Settings)

	// Initialize variables
	for k, v := range script.Variables {
		a.variables[k] = v
	}

	// Launch browser
	if err := a.launchBrowser(); err != nil {
		result.Status = "failure"
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	defer a.Close()

	if a.verbose {
		fmt.Printf("\n=== Running Script: %s ===\n\n", script.Name)
	}

	// Execute actions
	result.Status = "success"
	for i, action := range script.Actions {
		select {
		case <-ctx.Done():
			result.Status = "cancelled"
			result.Errors = append(result.Errors, "script cancelled")
			break
		default:
		}

		if a.slowMotion > 0 {
			time.Sleep(a.slowMotion)
		}

		actionResult := a.executeAction(ctx, action, i)
		result.Actions = append(result.Actions, actionResult)

		if actionResult.Status == "failure" && !action.Optional {
			result.Status = "failure"
			result.Errors = append(result.Errors, actionResult.Error)

			// Execute on_error actions
			if len(script.OnError) > 0 {
				for j, errAction := range script.OnError {
					a.executeAction(ctx, errAction, j)
				}
			}
			break
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)
	result.Variables = a.variables
	result.Extracted = a.extracted
	result.Screenshots = a.screenshots

	if a.verbose {
		fmt.Printf("\n=== Script Complete: %s (Status: %s, Duration: %s) ===\n",
			script.Name, result.Status, result.Duration)
	}

	return result, nil
}

func (a *Automator) applySettings(settings ScriptSettings) {
	if settings.Timeout != "" {
		if d, err := time.ParseDuration(settings.Timeout); err == nil {
			a.timeout = d
		}
	}
	if settings.SlowMotion != "" {
		if d, err := time.ParseDuration(settings.SlowMotion); err == nil {
			a.slowMotion = d
		}
	}
	if settings.ScreenshotsDir != "" {
		a.screenshotsDir = settings.ScreenshotsDir
	}
	if !settings.Headless {
		a.headless = false
	}
}

func (a *Automator) launchBrowser() error {
	l := launcher.New().
		Headless(a.headless).
		Set("disable-gpu").
		Set("no-sandbox")

	url, err := l.Launch()
	if err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}

	a.browser = rod.New().ControlURL(url)
	if err := a.browser.Connect(); err != nil {
		return fmt.Errorf("failed to connect to browser: %w", err)
	}

	a.page = a.browser.MustPage()

	// Track the main tab
	a.tabs["main"] = a.page
	a.tabOrder = append(a.tabOrder, "main")

	// Set viewport if specified
	if a.script != nil && a.script.Settings.Viewport != nil {
		a.page.MustSetViewport(
			a.script.Settings.Viewport.Width,
			a.script.Settings.Viewport.Height,
			1.0,
			false,
		)
	}

	// Set user agent if specified
	if a.script != nil && a.script.Settings.UserAgent != "" {
		a.page.MustSetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: a.script.Settings.UserAgent,
		})
	}

	return nil
}

// Close cleans up browser resources
func (a *Automator) Close() error {
	if a.page != nil {
		a.page.Close()
	}
	if a.browser != nil {
		return a.browser.Close()
	}
	return nil
}

func (a *Automator) executeAction(ctx context.Context, action Action, index int) ActionResult {
	startTime := time.Now()
	result := ActionResult{
		ActionID:   action.ID,
		ActionName: action.Name,
		ActionType: action.Type,
	}

	// Parse timeout
	timeout := a.timeout
	if action.Timeout != "" {
		if d, err := time.ParseDuration(action.Timeout); err == nil {
			timeout = d
		}
	}

	// Create context with timeout
	actionCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if a.verbose {
		name := action.Name
		if name == "" {
			name = string(action.Type)
		}
		fmt.Printf("[%d] %s", index+1, name)
	}

	var err error
	var output interface{}

	switch action.Type {
	// Navigation
	case ActionNavigate:
		err = a.navigate(actionCtx, action)
	case ActionGoBack:
		err = a.page.NavigateBack()
	case ActionGoForward:
		err = a.page.NavigateForward()
	case ActionReload:
		err = a.page.Reload()

	// Element interaction
	case ActionClick:
		err = a.click(actionCtx, action)
	case ActionDoubleClick:
		err = a.doubleClick(actionCtx, action)
	case ActionRightClick:
		err = a.rightClick(actionCtx, action)
	case ActionHover:
		err = a.hover(actionCtx, action)
	case ActionFocus:
		err = a.focus(actionCtx, action)
	case ActionScrollIntoView:
		err = a.scrollIntoView(actionCtx, action)

	// Input
	case ActionType_:
		err = a.typeText(actionCtx, action)
	case ActionFill:
		err = a.fill(actionCtx, action)
	case ActionClear:
		err = a.clear(actionCtx, action)
	case ActionPress:
		err = a.press(actionCtx, action)
	case ActionSelect:
		err = a.selectOption(actionCtx, action)
	case ActionCheck:
		err = a.check(actionCtx, action)
	case ActionUncheck:
		err = a.uncheck(actionCtx, action)
	case ActionUpload:
		err = a.upload(actionCtx, action)

	// Waiting
	case ActionWait:
		err = a.wait(actionCtx, action)
	case ActionWaitFor:
		err = a.waitFor(actionCtx, action)
	case ActionWaitForNav:
		err = a.waitForNavigation(actionCtx, action)
	case ActionWaitForLoad:
		err = a.page.WaitLoad()
	case ActionWaitForIdle:
		err = a.page.WaitIdle(time.Second * 30)

	// JavaScript
	case ActionEvaluate:
		output, err = a.evaluate(actionCtx, action)

	// Screenshots
	case ActionScreenshot:
		output, err = a.screenshot(actionCtx, action)

	// Assertions
	case ActionAssert, ActionAssertText:
		err = a.assertText(actionCtx, action)
	case ActionAssertValue:
		err = a.assertValue(actionCtx, action)
	case ActionAssertAttr:
		err = a.assertAttribute(actionCtx, action)
	case ActionAssertURL:
		err = a.assertURL(actionCtx, action)
	case ActionAssertTitle:
		err = a.assertTitle(actionCtx, action)
	case ActionAssertExists:
		err = a.assertExists(actionCtx, action)
	case ActionAssertVisible:
		err = a.assertVisible(actionCtx, action)

	// Data extraction
	case ActionExtract, ActionExtractText:
		output, err = a.extractText(actionCtx, action)
	case ActionExtractAttr:
		output, err = a.extractAttribute(actionCtx, action)
	case ActionExtractHTML:
		output, err = a.extractHTML(actionCtx, action)

	// Control flow
	case ActionIf:
		output, err = a.executeIf(actionCtx, action)
	case ActionLoop:
		output, err = a.executeLoop(actionCtx, action)

	// Cookies
	case ActionSetCookie:
		err = a.setCookie(actionCtx, action)
	case ActionGetCookies:
		output, err = a.getCookies(actionCtx, action)
	case ActionClearCookies:
		err = a.clearCookies(actionCtx, action)

	// Storage
	case ActionSetStorage:
		err = a.setStorage(actionCtx, action)
	case ActionGetStorage:
		output, err = a.getStorage(actionCtx, action)
	case ActionClearStorage:
		err = a.clearStorage(actionCtx, action)

	// Tab management
	case ActionNewTab:
		output, err = a.newTab(actionCtx, action)
	case ActionSwitchTab:
		err = a.switchTab(actionCtx, action)
	case ActionCloseTab:
		err = a.closeTab(actionCtx, action)
	case ActionGetTabs:
		output, err = a.getTabs(actionCtx, action)

	// Debug
	case ActionPause:
		if action.Duration != "" {
			if d, err := time.ParseDuration(action.Duration); err == nil {
				time.Sleep(d)
			}
		}
	case ActionLog:
		fmt.Printf("  LOG: %s\n", a.resolveVariable(action.Value))

	default:
		err = fmt.Errorf("unknown action type: %s", action.Type)
	}

	result.Duration = time.Since(startTime)

	if err != nil {
		result.Status = "failure"
		result.Error = err.Error()
		if a.verbose {
			fmt.Printf(" [FAILED: %s]\n", err.Error())
		}
	} else {
		result.Status = "success"
		result.Output = output
		if a.verbose {
			fmt.Printf(" [OK]\n")
		}

		// Store in variable if specified
		if action.Variable != "" && output != nil {
			if str, ok := output.(string); ok {
				a.variables[action.Variable] = str
			}
		}
	}

	return result
}

// resolveVariable replaces {{variable}} placeholders
func (a *Automator) resolveVariable(s string) string {
	result := s
	for k, v := range a.variables {
		result = strings.ReplaceAll(result, "{{"+k+"}}", v)
	}
	return result
}

// getElement finds an element using selector or xpath
func (a *Automator) getElement(ctx context.Context, action Action) (*rod.Element, error) {
	selector := a.resolveVariable(action.Selector)
	xpath := a.resolveVariable(action.XPath)
	text := a.resolveVariable(action.Text)
	containsText := a.resolveVariable(action.ContainsText)

	if selector != "" {
		return a.page.Context(ctx).Element(selector)
	}
	if xpath != "" {
		return a.page.Context(ctx).ElementX(xpath)
	}
	if text != "" {
		return a.page.Context(ctx).ElementR("*", text)
	}
	if containsText != "" {
		return a.page.Context(ctx).ElementR("*", containsText)
	}

	return nil, fmt.Errorf("no selector specified")
}

// Action implementations
func (a *Automator) navigate(ctx context.Context, action Action) error {
	url := a.resolveVariable(action.URL)
	return a.page.Context(ctx).Navigate(url)
}

func (a *Automator) click(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.Click(proto.InputMouseButtonLeft)
}

func (a *Automator) doubleClick(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	// Double click via two consecutive clicks
	if err := el.Click(proto.InputMouseButtonLeft); err != nil {
		return err
	}
	return el.Click(proto.InputMouseButtonLeft)
}

func (a *Automator) rightClick(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.Click(proto.InputMouseButtonRight)
}

func (a *Automator) hover(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.Hover()
}

func (a *Automator) focus(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.Focus()
}

func (a *Automator) scrollIntoView(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.ScrollIntoView()
}

func (a *Automator) typeText(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.Input(a.resolveVariable(action.Value))
}

func (a *Automator) fill(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	// Clear first, then type
	el.MustSelectAllText().MustInput("")
	return el.Input(a.resolveVariable(action.Value))
}

func (a *Automator) clear(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	el.MustSelectAllText().MustInput("")
	return nil
}

func (a *Automator) press(ctx context.Context, action Action) error {
	key := a.resolveVariable(action.Keys)
	// Handle common key names
	switch key {
	case "Enter":
		return a.page.Keyboard.Press(input.Enter)
	case "Tab":
		return a.page.Keyboard.Press(input.Tab)
	case "Escape":
		return a.page.Keyboard.Press(input.Escape)
	case "Backspace":
		return a.page.Keyboard.Press(input.Backspace)
	case "Delete":
		return a.page.Keyboard.Press(input.Delete)
	case "ArrowUp":
		return a.page.Keyboard.Press(input.ArrowUp)
	case "ArrowDown":
		return a.page.Keyboard.Press(input.ArrowDown)
	case "ArrowLeft":
		return a.page.Keyboard.Press(input.ArrowLeft)
	case "ArrowRight":
		return a.page.Keyboard.Press(input.ArrowRight)
	case "Space", " ":
		return a.page.Keyboard.Press(' ')
	case "Home":
		return a.page.Keyboard.Press(input.Home)
	case "End":
		return a.page.Keyboard.Press(input.End)
	case "PageUp":
		return a.page.Keyboard.Press(input.PageUp)
	case "PageDown":
		return a.page.Keyboard.Press(input.PageDown)
	default:
		// For single character keys, type them directly
		if len(key) == 1 {
			return a.page.Keyboard.Press(rune(key[0]))
		}
		return fmt.Errorf("unknown key: %s", key)
	}
}

func (a *Automator) selectOption(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.Select([]string{a.resolveVariable(action.Value)}, true, rod.SelectorTypeText)
}

func (a *Automator) check(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	checked, _ := el.Property("checked")
	if !checked.Bool() {
		return el.Click(proto.InputMouseButtonLeft)
	}
	return nil
}

func (a *Automator) uncheck(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	checked, _ := el.Property("checked")
	if checked.Bool() {
		return el.Click(proto.InputMouseButtonLeft)
	}
	return nil
}

func (a *Automator) upload(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}
	return el.SetFiles([]string{a.resolveVariable(action.Filename)})
}

func (a *Automator) wait(ctx context.Context, action Action) error {
	if action.Duration != "" {
		d, err := time.ParseDuration(action.Duration)
		if err != nil {
			return err
		}
		select {
		case <-time.After(d):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (a *Automator) waitFor(ctx context.Context, action Action) error {
	_, err := a.getElement(ctx, action)
	return err
}

func (a *Automator) waitForNavigation(ctx context.Context, action Action) error {
	wait := a.page.Context(ctx).WaitNavigation(proto.PageLifecycleEventNameNetworkAlmostIdle)
	wait()
	return nil
}

func (a *Automator) evaluate(ctx context.Context, action Action) (interface{}, error) {
	script := a.resolveVariable(action.Script)
	if script == "" {
		script = a.resolveVariable(action.Expression)
	}
	result, err := a.page.Eval(script)
	if err != nil {
		return nil, err
	}
	return result.Value.Val(), nil
}

func (a *Automator) screenshot(ctx context.Context, action Action) (string, error) {
	path := a.resolveVariable(action.Path)
	if path == "" {
		path = filepath.Join(a.screenshotsDir, fmt.Sprintf("screenshot_%d.png", time.Now().UnixNano()))
	}

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(path), 0755)

	var data []byte
	var err error

	if action.FullPage {
		data, err = a.page.Screenshot(true, nil)
	} else {
		data, err = a.page.Screenshot(false, nil)
	}

	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}

	a.screenshots = append(a.screenshots, path)
	return path, nil
}

func (a *Automator) assertText(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}

	text, err := el.Text()
	if err != nil {
		return err
	}

	expected := a.resolveVariable(action.Expected)
	pattern := a.resolveVariable(action.Pattern)

	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		if !re.MatchString(text) {
			return fmt.Errorf("text '%s' does not match pattern '%s'", text, pattern)
		}
	} else if expected != "" {
		if !strings.Contains(text, expected) {
			return fmt.Errorf("text '%s' does not contain expected '%s'", text, expected)
		}
	}

	return nil
}

func (a *Automator) assertValue(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}

	value, err := el.Property("value")
	if err != nil {
		return err
	}

	expected := a.resolveVariable(action.Expected)
	if value.Str() != expected {
		return fmt.Errorf("value '%s' does not match expected '%s'", value.Str(), expected)
	}

	return nil
}

func (a *Automator) assertAttribute(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}

	attr, err := el.Attribute(action.Attribute)
	if err != nil {
		return err
	}

	expected := a.resolveVariable(action.Expected)
	if attr == nil || *attr != expected {
		actual := ""
		if attr != nil {
			actual = *attr
		}
		return fmt.Errorf("attribute '%s' value '%s' does not match expected '%s'", action.Attribute, actual, expected)
	}

	return nil
}

func (a *Automator) assertURL(ctx context.Context, action Action) error {
	info, err := a.page.Info()
	if err != nil {
		return err
	}

	expected := a.resolveVariable(action.Expected)
	pattern := a.resolveVariable(action.Pattern)

	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		if !re.MatchString(info.URL) {
			return fmt.Errorf("URL '%s' does not match pattern '%s'", info.URL, pattern)
		}
	} else if expected != "" {
		if info.URL != expected && !strings.Contains(info.URL, expected) {
			return fmt.Errorf("URL '%s' does not match expected '%s'", info.URL, expected)
		}
	}

	return nil
}

func (a *Automator) assertTitle(ctx context.Context, action Action) error {
	info, err := a.page.Info()
	if err != nil {
		return err
	}

	expected := a.resolveVariable(action.Expected)
	if !strings.Contains(info.Title, expected) {
		return fmt.Errorf("title '%s' does not contain expected '%s'", info.Title, expected)
	}

	return nil
}

func (a *Automator) assertExists(ctx context.Context, action Action) error {
	_, err := a.getElement(ctx, action)
	return err
}

func (a *Automator) assertVisible(ctx context.Context, action Action) error {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return err
	}

	visible, err := el.Visible()
	if err != nil {
		return err
	}

	if !visible {
		return fmt.Errorf("element is not visible")
	}

	return nil
}

func (a *Automator) extractText(ctx context.Context, action Action) (string, error) {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return "", err
	}

	text, err := el.Text()
	if err != nil {
		return "", err
	}

	if action.Variable != "" {
		a.variables[action.Variable] = text
		a.extracted[action.Variable] = text
	}

	return text, nil
}

func (a *Automator) extractAttribute(ctx context.Context, action Action) (string, error) {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return "", err
	}

	attr, err := el.Attribute(action.Attribute)
	if err != nil {
		return "", err
	}

	value := ""
	if attr != nil {
		value = *attr
	}

	if action.Variable != "" {
		a.variables[action.Variable] = value
		a.extracted[action.Variable] = value
	}

	return value, nil
}

func (a *Automator) extractHTML(ctx context.Context, action Action) (string, error) {
	el, err := a.getElement(ctx, action)
	if err != nil {
		return "", err
	}

	html, err := el.HTML()
	if err != nil {
		return "", err
	}

	if action.Variable != "" {
		a.variables[action.Variable] = html
		a.extracted[action.Variable] = html
	}

	return html, nil
}

func (a *Automator) executeIf(ctx context.Context, action Action) (interface{}, error) {
	// Evaluate condition
	result, err := a.page.Eval(a.resolveVariable(action.Condition))
	if err != nil {
		return nil, err
	}

	if result.Value.Bool() {
		for i, subAction := range action.Actions {
			a.executeAction(ctx, subAction, i)
		}
	}

	return nil, nil
}

func (a *Automator) executeLoop(ctx context.Context, action Action) (interface{}, error) {
	count := action.Count
	if count == 0 {
		count = 1
	}

	for i := 0; i < count; i++ {
		a.variables["loop_index"] = fmt.Sprintf("%d", i)
		for j, subAction := range action.Actions {
			a.executeAction(ctx, subAction, j)
		}
	}

	return nil, nil
}

func (a *Automator) setCookie(ctx context.Context, action Action) error {
	// Parse cookie from action.Value (name=value format)
	parts := strings.SplitN(action.Value, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid cookie format, expected name=value")
	}

	return a.page.SetCookies([]*proto.NetworkCookieParam{
		{
			Name:  parts[0],
			Value: parts[1],
			URL:   a.page.MustInfo().URL,
		},
	})
}

func (a *Automator) getCookies(ctx context.Context, action Action) (interface{}, error) {
	cookies, err := a.page.Cookies(nil)
	if err != nil {
		return nil, err
	}
	return cookies, nil
}

func (a *Automator) clearCookies(ctx context.Context, action Action) error {
	// Clear all cookies by setting empty list
	return a.page.SetCookies(nil)
}

func (a *Automator) setStorage(ctx context.Context, action Action) error {
	key := a.resolveVariable(action.Selector)
	value := a.resolveVariable(action.Value)
	_, err := a.page.Eval(fmt.Sprintf(`localStorage.setItem(%q, %q)`, key, value))
	return err
}

func (a *Automator) getStorage(ctx context.Context, action Action) (interface{}, error) {
	key := a.resolveVariable(action.Selector)
	result, err := a.page.Eval(fmt.Sprintf(`localStorage.getItem(%q)`, key))
	if err != nil {
		return nil, err
	}

	value := result.Value.Str()
	if action.Variable != "" {
		a.variables[action.Variable] = value
	}

	return value, nil
}

func (a *Automator) clearStorage(ctx context.Context, action Action) error {
	_, err := a.page.Eval(`localStorage.clear()`)
	return err
}

// Tab management methods

// newTab creates a new browser tab
func (a *Automator) newTab(ctx context.Context, action Action) (interface{}, error) {
	// Create new page/tab
	page, err := a.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, fmt.Errorf("failed to create new tab: %w", err)
	}

	// Determine tab name
	tabName := action.Variable
	if tabName == "" {
		tabName = fmt.Sprintf("tab_%d", len(a.tabs)+1)
	}

	// Store the tab
	a.tabs[tabName] = page
	a.tabOrder = append(a.tabOrder, tabName)

	// Navigate to URL if specified
	if action.URL != "" {
		url := a.resolveVariable(action.URL)
		if err := page.Navigate(url); err != nil {
			return nil, fmt.Errorf("failed to navigate new tab to %s: %w", url, err)
		}
		page.MustWaitLoad()
	}

	// Switch to the new tab
	a.page = page

	if a.verbose {
		fmt.Printf(" (opened tab: %s)", tabName)
	}

	return map[string]interface{}{
		"tab_name": tabName,
		"url":      page.MustInfo().URL,
	}, nil
}

// switchTab switches to a named tab
func (a *Automator) switchTab(ctx context.Context, action Action) error {
	tabName := a.resolveVariable(action.Value)
	if tabName == "" {
		tabName = action.Variable
	}

	// Check if it's an index (number)
	if idx := 0; tabName != "" {
		if _, err := fmt.Sscanf(tabName, "%d", &idx); err == nil && idx >= 0 && idx < len(a.tabOrder) {
			tabName = a.tabOrder[idx]
		}
	}

	page, exists := a.tabs[tabName]
	if !exists {
		return fmt.Errorf("tab not found: %s (available: %v)", tabName, a.tabOrder)
	}

	// Bring tab to front
	page.MustActivate()
	a.page = page

	if a.verbose {
		fmt.Printf(" (switched to tab: %s)", tabName)
	}

	return nil
}

// closeTab closes a tab
func (a *Automator) closeTab(ctx context.Context, action Action) error {
	tabName := a.resolveVariable(action.Value)
	if tabName == "" {
		tabName = action.Variable
	}

	// If no tab specified, close current tab
	if tabName == "" {
		// Find current tab name
		for name, page := range a.tabs {
			if page == a.page {
				tabName = name
				break
			}
		}
	}

	page, exists := a.tabs[tabName]
	if !exists {
		return fmt.Errorf("tab not found: %s", tabName)
	}

	// Close the page
	if err := page.Close(); err != nil {
		return fmt.Errorf("failed to close tab: %w", err)
	}

	// Remove from tracking
	delete(a.tabs, tabName)
	for i, name := range a.tabOrder {
		if name == tabName {
			a.tabOrder = append(a.tabOrder[:i], a.tabOrder[i+1:]...)
			break
		}
	}

	// Switch to another tab if available
	if len(a.tabs) > 0 {
		for _, page := range a.tabs {
			a.page = page
			page.MustActivate()
			break
		}
	}

	if a.verbose {
		fmt.Printf(" (closed tab: %s)", tabName)
	}

	return nil
}

// getTabs returns information about all open tabs
func (a *Automator) getTabs(ctx context.Context, action Action) (interface{}, error) {
	tabs := make([]map[string]interface{}, 0, len(a.tabs))

	for _, name := range a.tabOrder {
		page, exists := a.tabs[name]
		if !exists {
			continue
		}

		info := page.MustInfo()
		isActive := page == a.page

		tabs = append(tabs, map[string]interface{}{
			"name":   name,
			"url":    info.URL,
			"title":  info.Title,
			"active": isActive,
		})
	}

	return tabs, nil
}

// SaveResult saves the script result to a file
func SaveScriptResult(result *ScriptResult, path string) error {
	var data []byte
	var err error

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(result, "", "  ")
	case ".yaml", ".yml":
		data, err = yaml.Marshal(result)
	default:
		data, err = json.MarshalIndent(result, "", "  ")
	}

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
