// Package crawler provides an authenticated web crawler with support for
// headless browser automation, session management, and artifact capture.
package crawler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
	"github.com/coppertone/bug-hunter/app/aegis/internal/rendercheck"
	"github.com/coppertone/bug-hunter/app/aegis/internal/scrape"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/coppertone/bug-hunter/app/aegis/internal/validator"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Config holds the crawler configuration settings including target,
// depth limits, and artifact capture options.
type Config struct {
	Target             string `yaml:"target"`             // Initial URL to start crawling from
	MaxDepth           int    `yaml:"maxDepth"`           // Maximum recursion depth for link discovery
	MaxPages           int    `yaml:"maxPages"`           // Maximum number of pages to crawl (0 = unlimited)
	UserAgent          string `yaml:"userAgent"`          // Custom User-Agent string for the browser
	Headless           bool   `yaml:"headless"`           // Whether to run browser in headless mode
	Scroll             bool   `yaml:"scroll"`             // Enable scrolling to trigger lazy loading
	WorkerCount        int    `yaml:"workerCount"`        // Number of concurrent worker goroutines
	IncludeExternal    bool   `yaml:"includeExternal"`    // Allow crawling external domains
	RenderVerify       string `yaml:"renderVerify"`       // Render verification mode: auto, never, always
	RenderBorderLow    int    `yaml:"renderBorderLow"`    // Rendercheck borderline low score
	RenderBorderHigh   int    `yaml:"renderBorderHigh"`   // Rendercheck borderline high score
	RenderTextDeltaMin int    `yaml:"renderTextDeltaMin"` // Rendercheck visible text delta threshold
	RenderMaxBytes     int64  `yaml:"renderMaxBytes"`     // Rendercheck/static HTML max bytes
	ScreenshotPath     string `yaml:"screenshotPath"`     // Directory to save screenshots
	DownloadPath       string `yaml:"downloadPath"`       // Directory to save downloaded files
	EnableScreenshot   bool   `yaml:"enableScreenshot"`   // Global toggle for screenshot capture
	EnableDownload     bool   `yaml:"enableDownload"`     // Global toggle for file downloads
	AllowPrivateHosts  bool   `yaml:"allowPrivateHosts"`  // Allow localhost/private IP targets
	PageTimeoutSeconds int    `yaml:"pageTimeoutSeconds"` // Page operation timeout in seconds
	SessionKey         []byte `yaml:"sessionKey"`         // 32-byte AES-256 key for session storage
}

// Crawler represents an authenticated web crawler instance that manages
// the browser lifecycle and job distribution.
type Crawler struct {
	browser     *rod.Browser
	config      Config
	client      *http.Client
	sessionPath string
	log         *slog.Logger
	visited     sync.Map
	downloads   sync.Map
	store       *crawlStore
	browserMu   sync.Mutex
}

func (c *Crawler) getBrowser() (*rod.Browser, error) {
	c.browserMu.Lock()
	defer c.browserMu.Unlock()

	if c.browser != nil {
		// Check if connection is still alive
		_, err := c.browser.Pages()
		if err == nil {
			return c.browser, nil
		}
		c.log.Warn("Browser connection lost, reconnecting...")
		_ = c.browser.Close()
		c.browser = nil
	}

	l := browser.NewLauncher(c.config.Headless)
	u, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("launch browser: %w", err)
	}

	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		return nil, fmt.Errorf("connect browser: %w", err)
	}

	c.browser = b
	return c.browser, nil
}

// job defines a specific URL to be crawled at a specific depth.
type job struct {
	url   string
	depth int
}

// result captures the outcome of a single page crawl.
type result struct {
	newLinks []string
	err      error
	depth    int
}

type assetStatus struct {
	path string
	ok   bool
}

const defaultMaxHTMLBytes = 20 * 1024 * 1024

// NewCrawler initializes a new Crawler instance with the provided configuration.
// If WorkerCount is not positive, it defaults to 1.
//
// Example:
//
//	c := crawler.NewCrawler(crawler.Config{Target: "https://example.com"}, "session.json")
func NewCrawler(config Config, sessionPath string) *Crawler {
	if config.WorkerCount <= 0 {
		config.WorkerCount = 1
	}
	return &Crawler{
		config:      config,
		sessionPath: sessionPath,
		log:         logger.New(),
	}
}

// Normalize validates and applies defaults to the crawler configuration.
func (c Config) Normalize() (Config, error) {
	c.Target = strings.TrimSpace(c.Target)
	if c.Target == "" {
		return c, fmt.Errorf("target is required")
	}
	normalizedTarget, err := normalizeURL(c.Target)
	if err != nil {
		return c, err
	}
	c.Target = normalizedTarget
	if c.AllowPrivateHosts {
		if err := validator.ValidateURL(c.Target); err != nil {
			return c, err
		}
	} else {
		if err := validator.ValidateTargetURL(c.Target); err != nil {
			return c, err
		}
	}
	if c.MaxDepth < 0 {
		return c, fmt.Errorf("maxDepth must be >= 0")
	}
	if c.MaxPages < 0 {
		return c, fmt.Errorf("maxPages must be >= 0")
	}
	if c.WorkerCount <= 0 {
		c.WorkerCount = 1
	}
	if c.PageTimeoutSeconds <= 0 {
		c.PageTimeoutSeconds = 30
	}
	if strings.TrimSpace(c.RenderVerify) == "" {
		c.RenderVerify = string(rendercheck.VerifyAuto)
	}
	switch rendercheck.VerifyMode(strings.ToLower(strings.TrimSpace(c.RenderVerify))) {
	case rendercheck.VerifyAuto, rendercheck.VerifyNever, rendercheck.VerifyAlways:
	default:
		return c, fmt.Errorf("renderVerify must be auto, never, or always")
	}
	if c.RenderBorderLow < 0 {
		return c, fmt.Errorf("renderBorderLow must be >= 0")
	}
	if c.RenderBorderHigh < 0 {
		return c, fmt.Errorf("renderBorderHigh must be >= 0")
	}
	if c.RenderBorderLow > 0 && c.RenderBorderHigh > 0 && c.RenderBorderLow >= c.RenderBorderHigh {
		return c, fmt.Errorf("renderBorderLow must be less than renderBorderHigh")
	}
	if c.RenderTextDeltaMin < 0 {
		return c, fmt.Errorf("renderTextDeltaMin must be >= 0")
	}
	if c.RenderMaxBytes < 0 {
		return c, fmt.Errorf("renderMaxBytes must be >= 0")
	}
	if len(c.SessionKey) > 0 && len(c.SessionKey) != 32 {
		return c, fmt.Errorf("sessionKey must be 32 bytes")
	}
	return c, nil
}

// Run executes the crawling process starting from the target URL.
// It manages the browser lifecycle, initializes storage directories,
// and starts the coordinator to handle job distribution.
//
// Parameters:
//   - dumpPath: Local directory where HTML mirrors will be stored.
//
// Returns an error if the browser fails to launch or directories cannot be created.
func (c *Crawler) Run(dumpPath string) error {
	cfg, err := c.config.Normalize()
	if err != nil {
		return err
	}
	c.config = cfg

	_, err = c.getBrowser()
	if err != nil {
		return err
	}
	defer func() {
		c.browserMu.Lock()
		if c.browser != nil {
			_ = c.browser.Close()
			c.browser = nil
		}
		c.browserMu.Unlock()
	}()

	// Ensure directories exist
	dirs := []string{dumpPath}
	if c.config.EnableScreenshot {
		if c.config.ScreenshotPath != "" && !filepath.IsAbs(c.config.ScreenshotPath) {
			c.config.ScreenshotPath = filepath.Join(dumpPath, c.config.ScreenshotPath)
		}
		if c.config.ScreenshotPath == "" {
			c.config.ScreenshotPath = filepath.Join(dumpPath, "screenshots")
		}
		dirs = append(dirs, c.config.ScreenshotPath)
	}
	if c.config.EnableDownload {
		if c.config.DownloadPath != "" && !filepath.IsAbs(c.config.DownloadPath) {
			c.config.DownloadPath = filepath.Join(dumpPath, c.config.DownloadPath)
		}
		if c.config.DownloadPath == "" {
			c.config.DownloadPath = filepath.Join(dumpPath, "downloads")
		}
		dirs = append(dirs, c.config.DownloadPath)
	}

	for _, dir := range dirs {
		if dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", dir, err)
			}
		}
	}

	store, err := newCrawlStore(filepath.Join(dumpPath, "crawl.db"), c.log)
	if err != nil {
		return err
	}
	c.store = store
	defer func() {
		if err := store.Close(); err != nil && c.log != nil {
			c.log.Error("failed to close crawl database", "error", err)
		}
	}()

	jar, _ := cookiejar.New(nil)
	c.client = &http.Client{
		Timeout: time.Duration(c.config.PageTimeoutSeconds) * time.Second,
		Jar:     jar,
	}
	c.applySessionCookies()

	return c.coordinator(dumpPath)
}

func (c *Crawler) coordinator(dumpPath string) error {
	jobs := make(chan job, 1000)
	results := make(chan result)

	// Initial job
	targetURL, err := normalizeURL(c.config.Target)
	if err != nil {
		return err
	}
	jobs <- job{url: targetURL, depth: 0}
	c.visited.Store(targetURL, true)
	pending := 1
	processed := 0
	limitReached := false

	// Start workers
	for i := 0; i < c.config.WorkerCount; i++ {
		go c.worker(jobs, results, dumpPath)
	}

	for pending > 0 {
		res := <-results
		pending--

		if res.err != nil {
			c.log.Error("Crawl failed", "error", res.err)
			continue
		}

		processed++
		if c.config.MaxPages > 0 && processed >= c.config.MaxPages {
			if !limitReached {
				c.log.Warn("Max pages reached; skipping new links", "maxPages", c.config.MaxPages)
				limitReached = true
			}
			continue
		}

		if res.depth < c.config.MaxDepth {
			for _, link := range res.newLinks {
				if !c.shouldEnqueue(link) {
					continue
				}
				if _, seen := c.visited.LoadOrStore(link, true); !seen {
					pending++
					jobs <- job{url: link, depth: res.depth + 1}
				}
			}
		}
	}

	close(jobs)
	return nil
}

func (c *Crawler) worker(jobs <-chan job, results chan<- result, dumpPath string) {
	for j := range jobs {
		links, err := c.processPage(j.url, j.depth, dumpPath)
		results <- result{newLinks: links, err: err, depth: j.depth}
	}
}

func (c *Crawler) processPage(urlStr string, depth int, dumpPath string) (links []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("panic while processing page", "url", urlStr, "error", r)
			err = fmt.Errorf("panic while processing %s: %v", urlStr, r)
			c.recordError(urlStr, "panic", err)
		}
	}()

	c.log.Info("Processing", "url", urlStr, "depth", depth)

	normalized, err := normalizeURL(urlStr)
	if err != nil {
		c.recordError(urlStr, "normalize", err)
		return nil, err
	}
	urlStr = normalized

	ctx := context.Background()
	if c.config.PageTimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.config.PageTimeoutSeconds)*time.Second)
		defer cancel()
	}

	useRod := c.config.EnableScreenshot
	if !useRod && c.sessionPath != "" {
		if _, err := os.Stat(c.sessionPath); err == nil {
			useRod = true
		}
	}
	if !useRod {
		useRod = c.shouldRenderWithRod(ctx, urlStr)
	}

	var content string
	if !useRod {
		htmlContent, fetchErr := c.fetchHTML(ctx, urlStr)
		if fetchErr != nil {
			c.recordError(urlStr, "fetch_html", fetchErr)
			useRod = true
		} else {
			content = htmlContent
		}
	}

	if useRod {
		b, err := c.getBrowser()
		if err != nil {
			wrapped := fmt.Errorf("get browser: %w", err)
			c.recordError(urlStr, "get_browser", wrapped)
			return nil, wrapped
		}
		page, err := b.Page(proto.TargetCreateTarget{})
		if err != nil {
			wrapped := fmt.Errorf("create page: %w", err)
			c.recordError(urlStr, "create_page", wrapped)
			return nil, wrapped
		}
		if c.config.PageTimeoutSeconds > 0 {
			page = page.Timeout(time.Duration(c.config.PageTimeoutSeconds) * time.Second)
		}
		defer page.Close()

		// Load session if available
		if c.sessionPath != "" {
			if _, err := os.Stat(c.sessionPath); err == nil {
				if len(c.config.SessionKey) == 0 {
					c.log.Warn("session key missing; skipping session load")
				} else {
					mgr := session.NewSessionManager(c.sessionPath, c.config.SessionKey)
					if err := mgr.Load(page); err != nil {
						c.log.Error("failed to load session", "error", err)
					}
				}
			}
		}

		if c.config.UserAgent != "" {
			err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
				UserAgent: c.config.UserAgent,
			})
			if err != nil {
				c.log.Warn("failed to set user agent", "error", err)
			}
		}

		// Navigate and wait for load
		if err := page.Navigate(urlStr); err != nil {
			wrapped := fmt.Errorf("navigate: %w", err)
			c.recordError(urlStr, "navigate", wrapped)
			return nil, wrapped
		}
		if err := page.WaitLoad(); err != nil {
			wrapped := fmt.Errorf("wait load: %w", err)
			c.recordError(urlStr, "wait_load", wrapped)
			return nil, wrapped
		}
		if c.client != nil {
			c.syncCookies(page, urlStr)
		}

		if c.config.Scroll {
			c.scrollToBottom(page)
			if c.client != nil {
				c.syncCookies(page, urlStr)
			}
		}

		// Capture Screenshot
		if c.config.EnableScreenshot {
			shotPath := filepath.Join(c.config.ScreenshotPath, generateFilename(urlStr, ".png"))
			img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
				Format: proto.PageCaptureScreenshotFormatPng,
			})
			if err == nil {
				if err := os.WriteFile(shotPath, img, 0644); err != nil {
					c.log.Error("failed to save screenshot", "error", err, "path", shotPath)
				}
			} else {
				c.log.Error("failed to capture screenshot", "error", err, "path", shotPath)
			}
		}

		html, err := page.HTML()
		if err != nil {
			wrapped := fmt.Errorf("get html: %w", err)
			c.recordError(urlStr, "get_html", wrapped)
			return nil, wrapped
		}
		content = html
	}

	if content == "" {
		return nil, fmt.Errorf("empty html content")
	}
	htmlPath, err := c.writeHTML(dumpPath, urlStr, content)
	if err != nil {
		wrapped := fmt.Errorf("save html: %w", err)
		c.recordError(urlStr, "save_html", wrapped)
		return nil, wrapped
	}
	if c.store != nil {
		if err := c.store.RecordPage(urlStr, depth, htmlPath); err != nil && c.log != nil {
			c.log.Error("failed to record page", "error", err, "url", urlStr)
		}
	}

	linkRefs, sources, imports := scrape.CollectResourcesFromHTML(urlStr, content)
	linkRefs = uniqueStrings(linkRefs)
	sources = uniqueStrings(sources)
	imports = uniqueStrings(imports)

	for _, link := range linkRefs {
		if c.store != nil {
			if err := c.store.RecordLink(urlStr, link); err != nil && c.log != nil {
				c.log.Error("failed to record link", "error", err, "from", urlStr, "to", link)
			}
		}
		links = append(links, link)
	}

	for _, src := range sources {
		if c.store != nil {
			_ = c.store.RecordAsset(src, "source", urlStr, "")
		}
		c.handleAsset(urlStr, src, "source", dumpPath)
	}
	for _, imp := range imports {
		if c.store != nil {
			_ = c.store.RecordAsset(imp, "import", urlStr, "")
		}
		c.handleAsset(urlStr, imp, "import", dumpPath)
	}

	return links, nil
}

func (c *Crawler) applySessionCookies() {
	if c.client == nil || c.client.Jar == nil {
		return
	}
	if c.sessionPath == "" {
		return
	}
	if len(c.config.SessionKey) == 0 {
		if c.log != nil {
			c.log.Warn("session key missing; skipping session cookie load")
		}
		return
	}
	if _, err := os.Stat(c.sessionPath); err != nil {
		return
	}
	mgr := session.NewSessionManager(c.sessionPath, c.config.SessionKey)
	if err := mgr.ApplyCookiesToJar(c.client.Jar, c.config.Target); err != nil && c.log != nil {
		c.log.Error("failed to apply session cookies", "error", err)
	}
}

func (c *Crawler) syncCookies(page *rod.Page, pageURL string) {
	if c.client == nil || c.client.Jar == nil {
		return
	}

	parsed, err := url.Parse(pageURL)
	if err != nil {
		return
	}

	cookies, err := page.Cookies([]string{pageURL})
	if err != nil {
		return
	}

	var jarCookies []*http.Cookie
	for _, cookie := range cookies {
		jarCookies = append(jarCookies, &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
		})
	}

	c.client.Jar.SetCookies(parsed, jarCookies)
}

func (c *Crawler) writeHTML(dumpPath string, pageURL string, html string) (string, error) {
	targetPath, err := scrape.BuildResourcePath(filepath.Join(dumpPath, "pages"), pageURL)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(strings.ToLower(targetPath), ".html") {
		targetPath += ".html"
	}
	if err := os.WriteFile(targetPath, []byte(html), 0644); err != nil {
		return "", err
	}
	return targetPath, nil
}

func (c *Crawler) shouldRenderWithRod(ctx context.Context, urlStr string) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(c.config.PageTimeoutSeconds) * time.Second
	verifyMode := rendercheck.VerifyMode(strings.ToLower(strings.TrimSpace(c.config.RenderVerify)))
	if verifyMode == "" {
		verifyMode = rendercheck.VerifyAuto
	}
	opts := rendercheck.Options{
		Timeout:      timeout,
		MaxBytes:     c.renderMaxBytes(),
		UserAgent:    c.config.UserAgent,
		Verify:       verifyMode,
		Headless:     c.config.Headless,
		Client:       c.client,
		BorderLow:    c.config.RenderBorderLow,
		BorderHigh:   c.config.RenderBorderHigh,
		TextDeltaMin: c.config.RenderTextDeltaMin,
	}

	res, err := rendercheck.NeedsRendering(ctx, urlStr, opts)
	if err != nil {
		if c.log != nil {
			c.log.Warn("Render check failed", "url", urlStr, "error", err)
		}
		return true
	}
	if res == nil {
		return true
	}
	if c.store != nil {
		if err := c.store.RecordRenderCheck(urlStr, res); err != nil && c.log != nil {
			c.log.Error("failed to record render check", "error", err, "url", urlStr)
		}
	}
	if c.log != nil {
		c.log.Info("Render check", "url", urlStr, "needsRendering", res.NeedsRendering, "method", res.Method, "score", res.Score, "confidence", res.Confidence)
	}
	return res.NeedsRendering
}

func (c *Crawler) fetchHTML(ctx context.Context, rawURL string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("http client not configured")
	}
	maxBytes := c.renderMaxBytes()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if c.config.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("fetch %s: status %d", rawURL, resp.StatusCode)
	}
	if resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		return "", fmt.Errorf("fetch %s: content length %d exceeds limit %d", rawURL, resp.ContentLength, maxBytes)
	}

	limit := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
	body, err := io.ReadAll(limit)
	if err != nil {
		return "", err
	}
	if int64(len(body)) > maxBytes {
		return "", fmt.Errorf("fetch %s: html exceeded limit %d", rawURL, maxBytes)
	}
	return string(body), nil
}

func (c *Crawler) renderMaxBytes() int64 {
	if c.config.RenderMaxBytes > 0 {
		return c.config.RenderMaxBytes
	}
	return defaultMaxHTMLBytes
}

func (c *Crawler) handleAsset(fromPage string, rawURL string, origin string, dumpPath string) {
	clean, err := normalizeURL(rawURL)
	if err != nil {
		return
	}
	if !scrape.IsHTTPURL(clean) {
		return
	}

	kind := classifyAssetKind(clean, origin)
	if c.store != nil {
		if err := c.store.RecordAsset(clean, kind, fromPage, ""); err != nil && c.log != nil {
			c.log.Error("failed to record asset", "error", err, "url", clean)
		}
	}

	if !c.config.EnableDownload {
		return
	}
	if !c.shouldDownload(clean) {
		return
	}
	if err := c.downloadAsset(clean, fromPage, dumpPath); err != nil {
		c.recordError(clean, "download", err)
		if c.log != nil {
			c.log.Error("failed to download asset", "error", err, "url", clean)
		}
	}
}

func (c *Crawler) downloadAsset(assetURL string, fromPage string, dumpPath string) error {
	if c.client == nil {
		return nil
	}

	if val, loaded := c.downloads.LoadOrStore(assetURL, assetStatus{}); loaded {
		if status, ok := val.(assetStatus); ok && status.ok && c.store != nil {
			_ = c.store.UpdateAssetLocalPath(assetURL, status.path)
		}
		return nil
	}

	path, err := c.assetPath(dumpPath, assetURL)
	if err != nil {
		c.downloads.Delete(assetURL)
		return err
	}

	if _, err := os.Stat(path); err == nil {
		c.downloads.Store(assetURL, assetStatus{path: path, ok: true})
		if c.store != nil {
			_ = c.store.UpdateAssetLocalPath(assetURL, path)
		}
		c.discoverAssetImports(assetURL, path, fromPage, dumpPath)
		return nil
	}

	if err := c.fetchToFile(assetURL, path); err != nil {
		c.downloads.Delete(assetURL)
		return err
	}

	c.downloads.Store(assetURL, assetStatus{path: path, ok: true})
	if c.store != nil {
		_ = c.store.UpdateAssetLocalPath(assetURL, path)
	}

	c.discoverAssetImports(assetURL, path, fromPage, dumpPath)
	return nil
}

func (c *Crawler) assetPath(dumpPath string, assetURL string) (string, error) {
	baseDir := c.config.DownloadPath
	if baseDir == "" {
		baseDir = filepath.Join(dumpPath, "downloads")
	}
	return scrape.BuildResourcePath(baseDir, assetURL)
}

func (c *Crawler) fetchToFile(rawURL string, dest string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if c.config.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("fetch %s: status %d", rawURL, resp.StatusCode)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.ReadFrom(resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

func (c *Crawler) discoverAssetImports(assetURL string, localPath string, fromPage string, dumpPath string) {
	ext := strings.ToLower(path.Ext(localPath))
	if ext != ".css" && ext != ".js" && ext != ".mjs" && ext != ".cjs" {
		return
	}

	content, err := os.ReadFile(localPath)
	if err != nil {
		return
	}

	var refs []string
	if ext == ".css" {
		refs = scrape.ParseCSSImports(string(content))
	} else if ext == ".js" || ext == ".mjs" || ext == ".cjs" {
		refs = scrape.ParseJSImport(string(content))
	}

	for _, ref := range refs {
		resolved, err := resolveURL(assetURL, ref)
		if err != nil {
			continue
		}
		c.handleAsset(fromPage, resolved, "import", dumpPath)
	}
}

func classifyAssetKind(rawURL string, origin string) string {
	baseKind := "asset"
	if parsed, err := url.Parse(rawURL); err == nil {
		ext := strings.ToLower(path.Ext(parsed.Path))
		switch ext {
		case ".js", ".mjs", ".cjs":
			baseKind = "script"
		case ".css":
			baseKind = "stylesheet"
		case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".bmp", ".tiff":
			baseKind = "image"
		case ".mp4", ".m4v", ".webm", ".mov", ".mp3", ".wav", ".ogg", ".aac", ".flac", ".m4a":
			baseKind = "media"
		case ".woff", ".woff2", ".ttf", ".otf", ".eot":
			baseKind = "font"
		}
	}

	if origin == "import" {
		if baseKind == "asset" {
			return "import"
		}
		return "import-" + baseKind
	}
	return baseKind
}

func (c *Crawler) shouldEnqueue(link string) bool {
	if link == "" {
		return false
	}
	if err := c.validateDiscoveredURL(link); err != nil {
		return false
	}
	if c.config.IncludeExternal {
		return true
	}
	return c.isSameDomain(link)
}

func (c *Crawler) shouldDownload(rawURL string) bool {
	if err := c.validateDiscoveredURL(rawURL); err != nil {
		return false
	}
	if c.config.IncludeExternal {
		return true
	}
	return c.isSameDomain(rawURL)
}

func (c *Crawler) validateDiscoveredURL(raw string) error {
	if c.config.AllowPrivateHosts {
		return validator.ValidateURL(raw)
	}
	return validator.ValidateTargetURL(raw)
}

func (c *Crawler) recordError(urlStr string, stage string, err error) {
	if err == nil || c.store == nil {
		return
	}
	if storeErr := c.store.RecordError(urlStr, stage, err); storeErr != nil && c.log != nil {
		c.log.Error("failed to record error", "error", storeErr, "url", urlStr)
	}
}

func (c *Crawler) isSameDomain(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}
	t, err := url.Parse(c.config.Target)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, t.Host)
}

func (c *Crawler) scrollToBottom(page *rod.Page) {
	res, err := page.Eval(`() => document.body.scrollHeight`)
	if err != nil {
		return
	}
	prevHeight := res.Value.Int()
	for i := 0; i < 5; i++ { // Limit scroll attempts
		_, err := page.Eval(`() => window.scrollTo(0, document.body.scrollHeight)`)
		if err != nil {
			break
		}
		time.Sleep(1 * time.Second)
		res, err := page.Eval(`() => document.body.scrollHeight`)
		if err != nil {
			break
		}
		newHeight := res.Value.Int()
		if newHeight == prevHeight {
			break
		}
		prevHeight = newHeight
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func generateFilename(rawURL string, ext string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "index" + ext
	}

	// Clean the path to prevent directory traversal
	pathStr := strings.Trim(u.Path, "/")
	if pathStr == "" {
		pathStr = "index"
	}

	// Replace path separators with underscores to flatten the path
	pathStr = strings.ReplaceAll(pathStr, "/", "_")

	var clean strings.Builder
	for _, r := range pathStr {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			clean.WriteRune(r)
		} else {
			clean.WriteRune('_')
		}
	}
	pathStr = clean.String()

	if u.RawQuery != "" {
		pathStr += "_" + url.QueryEscape(u.RawQuery)
	}

	// Limit length to prevent filesystem issues
	if len(pathStr) > 200 {
		pathStr = pathStr[:200]
	}

	return pathStr + ext
}

func resolveURL(base, ref string) (string, error) {
	return scrape.ResolveURL(base, ref)
}

func normalizeURL(raw string) (string, error) {
	return scrape.NormalizeURL(raw)
}
