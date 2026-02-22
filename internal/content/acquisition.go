// Package content provides platform-aware content acquisition.
package content

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
)

// Content represents acquired web content
type Content struct {
	URL                string            `json:"url"`
	HTML               string            `json:"html"`
	Headers            map[string]string `json:"headers,omitempty"`
	StatusCode         int               `json:"status_code"`
	ContentType        string            `json:"content_type"`
	JavaScriptExecuted bool              `json:"javascript_executed"`
	RenderTime         time.Duration     `json:"render_time"`
	Assets             []string          `json:"assets,omitempty"`
	ConsoleLogs        []string          `json:"console_logs,omitempty"`
	NetworkCalls       []NetworkCall     `json:"network_calls,omitempty"`
}

// NetworkCall represents a network request made during rendering
type NetworkCall struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Type   string `json:"type"`
	Status int    `json:"status,omitempty"`
}

// AcquisitionStrategy determines how to acquire content
type AcquisitionStrategy int

const (
	AutoDetect AcquisitionStrategy = iota
	StaticOnly
	RenderAlways
)

// Acquirer handles content acquisition
type Acquirer struct {
	httpClient *http.Client
	browser    *rod.Browser
	launcher   *launcher.Launcher
	strategy   AcquisitionStrategy
	timeout    time.Duration
	useBrowser bool
	detector   *platform.Detector
}

// AcquirerOption configures the acquirer
type AcquirerOption func(*Acquirer)

// WithStrategy sets the acquisition strategy
func WithStrategy(strategy AcquisitionStrategy) AcquirerOption {
	return func(a *Acquirer) {
		a.strategy = strategy
	}
}

// WithTimeout sets the timeout
func WithTimeout(timeout time.Duration) AcquirerOption {
	return func(a *Acquirer) {
		a.timeout = timeout
	}
}

// NewAcquirer creates a new content acquirer
func NewAcquirer(opts ...AcquirerOption) (*Acquirer, error) {
	a := &Acquirer{
		strategy:   AutoDetect,
		timeout:    30 * time.Second,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		detector:   platform.NewDetector(30 * time.Second),
	}

	for _, opt := range opts {
		opt(a)
	}

	if a.strategy == RenderAlways || a.strategy == AutoDetect {
		if err := a.initBrowser(); err != nil {
			a.useBrowser = false
		}
	}

	return a, nil
}

// initBrowser initializes the headless browser
func (a *Acquirer) initBrowser() error {
	l := launcher.New().
		Headless(true).
		Set("no-sandbox", "true").
		Set("disable-gpu", "true")

	u, err := l.Launch()
	if err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}

	a.launcher = l
	a.browser = rod.New().ControlURL(u).MustConnect()
	a.useBrowser = true

	return nil
}

// Acquire fetches content from URL using appropriate method
func (a *Acquirer) Acquire(url string) (*Content, error) {
	switch a.strategy {
	case StaticOnly:
		return a.acquireStatic(url)
	case RenderAlways:
		if !a.useBrowser {
			return nil, fmt.Errorf("browser not available")
		}
		return a.acquireRendered(url)
	default:
		return a.acquireAutoDetect(url)
	}
}

// acquireAutoDetect automatically chooses the best acquisition method
func (a *Acquirer) acquireAutoDetect(url string) (*Content, error) {
	staticContent, err := a.acquireStatic(url)
	if err != nil {
		return nil, err
	}

	detection, err := a.detector.Detect(url)
	if err != nil {
		return staticContent, nil
	}

	if detection.IsSPA() && a.useBrowser {
		return a.acquireRendered(url)
	}

	return staticContent, nil
}

// acquireStatic fetches content using HTTP
func (a *Acquirer) acquireStatic(url string) (*Content, error) {
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return &Content{
		URL:                url,
		HTML:               string(body),
		Headers:            headers,
		StatusCode:         resp.StatusCode,
		ContentType:        resp.Header.Get("Content-Type"),
		JavaScriptExecuted: false,
		RenderTime:         time.Since(start),
	}, nil
}

// acquireRendered fetches content using headless browser
func (a *Acquirer) acquireRendered(url string) (*Content, error) {
	if !a.useBrowser || a.browser == nil {
		return nil, fmt.Errorf("browser not initialized")
	}

	start := time.Now()

	incognito, err := a.browser.Incognito()
	if err != nil {
		return nil, fmt.Errorf("failed to create incognito context: %w", err)
	}

	page := incognito.MustPage()

	if err := page.Navigate(url); err != nil {
		return nil, fmt.Errorf("failed to navigate: %w", err)
	}

	if err := page.WaitLoad(); err != nil {
		return nil, fmt.Errorf("failed to wait for load: %w", err)
	}

	time.Sleep(2 * time.Second)

	html, err := page.HTML()
	if err != nil {
		return nil, fmt.Errorf("failed to get HTML: %w", err)
	}

	page.Close()

	return &Content{
		URL:                url,
		HTML:               html,
		JavaScriptExecuted: true,
		RenderTime:         time.Since(start),
	}, nil
}

// Close cleans up resources
func (a *Acquirer) Close() error {
	if a.browser != nil {
		a.browser.Close()
	}
	if a.launcher != nil {
		a.launcher.Cleanup()
	}
	return nil
}

// ShouldRender checks if URL should use rendering
func (a *Acquirer) ShouldRender(url string) (bool, error) {
	detection, err := a.detector.Detect(url)
	if err != nil {
		return false, err
	}
	return detection.IsSPA(), nil
}