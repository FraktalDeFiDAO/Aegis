// Package crawler provides an authenticated web crawler with support for
// headless browser automation, session management, and artifact capture.
package crawler

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// Config holds the crawler configuration settings including target,
// depth limits, and artifact capture options.
type Config struct {
	Target           string `yaml:"target"`           // Initial URL to start crawling from
	MaxDepth         int    `yaml:"maxDepth"`         // Maximum recursion depth for link discovery
	UserAgent        string `yaml:"userAgent"`        // Custom User-Agent string for the browser
	Headless         bool   `yaml:"headless"`         // Whether to run browser in headless mode
	Scroll           bool   `yaml:"scroll"`           // Enable scrolling to trigger lazy loading
	WorkerCount      int    `yaml:"workerCount"`      // Number of concurrent worker goroutines
	ScreenshotPath   string `yaml:"screenshotPath"`   // Directory to save screenshots
	DownloadPath     string `yaml:"downloadPath"`     // Directory to save downloaded files
	EnableScreenshot bool   `yaml:"enableScreenshot"` // Global toggle for screenshot capture
	EnableDownload   bool   `yaml:"enableDownload"`   // Global toggle for file downloads
}

// Crawler represents an authenticated web crawler instance that manages
// the browser lifecycle and job distribution.
type Crawler struct {
	browser     *rod.Browser
	config      Config
	sessionPath string
	log         *slog.Logger
	visited     sync.Map
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

// Run executes the crawling process starting from the target URL.
// It manages the browser lifecycle, initializes storage directories,
// and starts the coordinator to handle job distribution.
//
// Parameters:
//   - dumpPath: Local directory where HTML mirrors will be stored.
//
// Returns an error if the browser fails to launch or directories cannot be created.
func (c *Crawler) Run(dumpPath string) error {
	l := launcher.New().Headless(c.config.Headless)
	u, err := l.Launch()
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	c.browser = rod.New().ControlURL(u).MustConnect()
	defer c.browser.MustClose()

	// Ensure directories exist
	dirs := []string{dumpPath}
	if c.config.EnableScreenshot {
		dirs = append(dirs, c.config.ScreenshotPath)
	}
	if c.config.EnableDownload {
		dirs = append(dirs, c.config.DownloadPath)
	}

	for _, dir := range dirs {
		if dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("create directory %s: %w", dir, err)
			}
		}
	}

	return c.coordinator(dumpPath)
}

func (c *Crawler) coordinator(dumpPath string) error {
	jobs := make(chan job, 1000)
	results := make(chan result)
	
	// Initial job
	targetURL := c.config.Target
	jobs <- job{url: targetURL, depth: 0}
	c.visited.Store(targetURL, true)
	pending := 1

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

		if res.depth < c.config.MaxDepth {
			for _, link := range res.newLinks {
				if _, seen := c.visited.LoadOrStore(link, true); !seen {
					if c.isSameDomain(link) {
						pending++
						jobs <- job{url: link, depth: res.depth + 1}
					}
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

func (c *Crawler) processPage(urlStr string, depth int, dumpPath string) ([]string, error) {
	c.log.Info("Processing", "url", urlStr, "depth", depth)

	page := c.browser.MustPage(urlStr)
	defer page.MustClose()

	// Load session if available
	if c.sessionPath != "" {
		if _, err := os.Stat(c.sessionPath); err == nil {
			mgr := session.NewSessionManager(c.sessionPath, nil)
			if err := mgr.Load(page); err != nil {
				c.log.Error("failed to load session", "error", err)
			}
		}
	}

	if c.config.UserAgent != "" {
		page.MustSetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: c.config.UserAgent,
		})
	}

	// Navigate and wait for load
	if err := page.Navigate(urlStr); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}
	page.MustWaitLoad()

	if c.config.Scroll {
		c.scrollToBottom(page)
	}

	// Capture Screenshot
	if c.config.EnableScreenshot {
		shotPath := filepath.Join(c.config.ScreenshotPath, generateFilename(urlStr, ".png"))
		img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
			Format: proto.PageCaptureScreenshotFormatPng,
		})
		if err == nil {
			os.WriteFile(shotPath, img, 0644)
		}
	}

	// Handle Downloads (simplified: just log if we find downloadable files or implement rod.Download)
	// For now, we'll just extract links and if we wanted to download we could use rod's downloader.

	content := page.MustHTML()
	filename := generateFilename(urlStr, ".html")
	if err := os.WriteFile(filepath.Join(dumpPath, filename), []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("save html: %w", err)
	}

	// Extract links
	var links []string
	elements, _ := page.Elements("a[href]")
	for _, el := range elements {
		href, err := el.Attribute("href")
		if err == nil && href != nil {
			resolved, err := resolveURL(urlStr, *href)
			if err == nil {
				links = append(links, resolved)
			}
		}
	}

	return links, nil
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
	return u.Host == t.Host
}

func (c *Crawler) scrollToBottom(page *rod.Page) {
	prevHeight := page.MustEval(`() => document.body.scrollHeight`).Int()
	for i := 0; i < 5; i++ { // Limit scroll attempts
		page.MustEval(`() => window.scrollTo(0, document.body.scrollHeight)`)
		time.Sleep(1 * time.Second)
		newHeight := page.MustEval(`() => document.body.scrollHeight`).Int()
		if newHeight == prevHeight {
			break
		}
		prevHeight = newHeight
	}
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
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(refURL).String(), nil
}