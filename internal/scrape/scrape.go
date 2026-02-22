// Package scrape provides scope-based crawling and asset scraping.
package scrape

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
	"github.com/coppertone/bug-hunter/app/aegis/internal/scope"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/coppertone/bug-hunter/app/aegis/internal/validator"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/html"
	"gopkg.in/yaml.v3"
)

type Config struct {
	MaxDepth               int               `yaml:"maxDepth"`
	UserAgent              string            `yaml:"userAgent"`
	Headless               bool              `yaml:"headless"`
	Scroll                 bool              `yaml:"scroll"`
	WorkerCount            int               `yaml:"workerCount"`
	IncludeExternal        bool              `yaml:"includeExternal"`
	OutputDir              string            `yaml:"outputDir"`
	EnableScreenshot       bool              `yaml:"enableScreenshot"`
	ScreenshotPath         string            `yaml:"screenshotPath"`
	Headers                map[string]string `yaml:"headers"`
	MaxPages               int               `yaml:"maxPages"`
	MaxLinksPerPage        int               `yaml:"maxLinksPerPage"`
	RequestDelayMillis     int               `yaml:"requestDelayMillis"`
	SessionPath            string            `yaml:"sessionPath"`
	SessionKey             []byte            `yaml:"sessionKey"`
	ManifestFormat         string            `yaml:"manifestFormat"`         // json or yaml
	AllowPrivateHosts      bool              `yaml:"allowPrivateHosts"`      // Allow localhost/private IP targets
	PageTimeoutSeconds     int               `yaml:"pageTimeoutSeconds"`     // Page operation timeout in seconds
	DownloadTimeoutSeconds int               `yaml:"downloadTimeoutSeconds"` // HTTP download timeout in seconds
	MaxDownloadBytes       int64             `yaml:"maxDownloadBytes"`       // Max size per downloaded asset (0 = default)
}

type Manifest struct {
	GeneratedAt     string        `json:"generated_at" yaml:"generated_at"`
	ScopeFile       string        `json:"scope_file" yaml:"scope_file"`
	IncludeExternal bool          `json:"include_external" yaml:"include_external"`
	Targets         []string      `json:"targets" yaml:"targets"`
	Pages           []PageRecord  `json:"pages" yaml:"pages"`
	Downloads       []FileRecord  `json:"downloads" yaml:"downloads"`
	Errors          []ErrorRecord `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type PageRecord struct {
	URL              string   `json:"url" yaml:"url"`
	Depth            int      `json:"depth" yaml:"depth"`
	Renderer         string   `json:"renderer" yaml:"renderer"`
	RenderedDetected bool     `json:"rendered_detected" yaml:"rendered_detected"`
	RenderReason     string   `json:"render_reason,omitempty" yaml:"render_reason,omitempty"`
	HTMLPath         string   `json:"html_path" yaml:"html_path"`
	ScreenshotPath   string   `json:"screenshot_path,omitempty" yaml:"screenshot_path,omitempty"`
	Links            []string `json:"links" yaml:"links"`
	Sources          []string `json:"sources" yaml:"sources"`
	Imports          []string `json:"imports" yaml:"imports"`
}

type FileRecord struct {
	URL      string `json:"url" yaml:"url"`
	Path     string `json:"path" yaml:"path"`
	FromPage string `json:"from_page,omitempty" yaml:"from_page,omitempty"`
	Kind     string `json:"kind,omitempty" yaml:"kind,omitempty"`
}

type ErrorRecord struct {
	URL   string `json:"url" yaml:"url"`
	Error string `json:"error" yaml:"error"`
}

type Scraper struct {
	cfg         Config
	scopeFile   string
	scope       *scope.Scope
	downloads   sync.Map
	manifestMu  sync.Mutex
	manifest    Manifest
	client      *http.Client
	pageClient  *http.Client
	log         *slog.Logger
	store       *scrapeStore
	browserErr  error
	browser     *rod.Browser
	browserMu   sync.Mutex
}

func (s *Scraper) getBrowser() (*rod.Browser, error) {
	s.browserMu.Lock()
	defer s.browserMu.Unlock()

	if s.browser != nil {
		// Check if connection is still alive
		_, err := s.browser.Pages()
		if err == nil {
			return s.browser, nil
		}
		s.log.Warn("Browser connection lost, reconnecting...")
		_ = s.browser.Close()
		s.browser = nil
	}

	l := browser.NewLauncher(s.cfg.Headless)
	u, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("launch browser: %w", err)
	}

	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		return nil, fmt.Errorf("connect browser: %w", err)
	}

	s.browser = b
	return s.browser, nil
}

type job struct {
	url   string
	depth int
}

type result struct {
	page PageRecord
	err  error
}

type renderDecision struct {
	Rendered bool
	Reason   string
}

type htmlMetrics struct {
	BodyTextLen    int
	TotalTextLen   int
	ScriptCount    int
	ScriptSrcCount int
}

const defaultMaxDownloadBytes = 20 * 1024 * 1024

func (c Config) normalize() (Config, error) {
	if c.WorkerCount <= 0 {
		c.WorkerCount = 2
	}
	if c.MaxDepth <= 0 {
		c.MaxDepth = 2
	}
	if c.ManifestFormat == "" {
		c.ManifestFormat = "json"
	}
	if c.PageTimeoutSeconds <= 0 {
		c.PageTimeoutSeconds = 30
	}
	if c.DownloadTimeoutSeconds <= 0 {
		c.DownloadTimeoutSeconds = 30
	}
	if c.MaxDownloadBytes < 0 {
		return c, fmt.Errorf("maxDownloadBytes must be >= 0")
	}
	if c.MaxPages < 0 {
		return c, fmt.Errorf("maxPages must be >= 0")
	}
	if c.MaxLinksPerPage < 0 {
		return c, fmt.Errorf("maxLinksPerPage must be >= 0")
	}
	if c.RequestDelayMillis < 0 {
		return c, fmt.Errorf("requestDelayMillis must be >= 0")
	}
	if c.MaxDownloadBytes == 0 {
		c.MaxDownloadBytes = defaultMaxDownloadBytes
	}
	if len(c.SessionKey) > 0 && len(c.SessionKey) != 32 {
		return c, fmt.Errorf("sessionKey must be 32 bytes")
	}
	return c, nil
}

// ScrapeScope crawls every in-scope target and saves a manifest and assets.
func ScrapeScope(projectDir string, scopePath string, cfg Config) error {
	normalized, err := cfg.normalize()
	if err != nil {
		return err
	}
	cfg = normalized

	parsedScope, err := scope.ParseFile(scopePath)
	if err != nil {
		return err
	}

	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = filepath.Join(projectDir, "scrape", time.Now().UTC().Format("20060102_150405"))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	log := logger.New()
	store, err := newScrapeStore(filepath.Join(outputDir, "crawl.db"), log)
	if err != nil {
		return err
	}
	defer store.Close()

	if cfg.EnableScreenshot {
		if cfg.ScreenshotPath == "" {
			cfg.ScreenshotPath = filepath.Join(outputDir, "screenshots")
		}
		if err := os.MkdirAll(cfg.ScreenshotPath, 0o755); err != nil {
			return err
		}
	}

	jar, _ := cookiejar.New(nil)
	pageClient := &http.Client{
		Timeout: time.Duration(cfg.PageTimeoutSeconds) * time.Second,
		Jar:     jar,
	}
	downloadClient := &http.Client{
		Timeout: time.Duration(cfg.DownloadTimeoutSeconds) * time.Second,
		Jar:     jar,
	}

	s := &Scraper{
		cfg:        cfg,
		scopeFile:  scopePath,
		scope:      parsedScope,
		client:     downloadClient,
		pageClient: pageClient,
		log:        log,
		store:      store,
		manifest: Manifest{
			GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
			ScopeFile:       scopePath,
			IncludeExternal: cfg.IncludeExternal,
			Targets:         parsedScope.Targets(),
		},
	}

	for _, target := range s.manifest.Targets {
		if err := validateTarget(target, s.cfg.AllowPrivateHosts); err != nil {
			s.addError(target, err)
			continue
		}
		if err := s.scrapeTarget(target, outputDir); err != nil {
			s.addError(target, err)
		}
	}

	return s.writeManifest(outputDir)
}

func (s *Scraper) scrapeTarget(target string, outputDir string) error {
	_, err := s.getBrowser()
	if err != nil {
		s.browserErr = err
		s.addError(target, err)
	}
	defer func() {
		s.browserMu.Lock()
		if s.browser != nil {
			_ = s.browser.Close()
			s.browser = nil
		}
		s.browserMu.Unlock()
	}()

	if err := s.loadSessionCookies(target); err != nil {
		s.addError(target, err)
	}

	visited := sync.Map{}
	jobs := make(chan job, 256)
	results := make(chan result)

	normalized, err := normalizeURL(target)
	if err != nil {
		return err
	}
	target = normalized
	jobs <- job{url: target, depth: 0}
	visited.Store(target, true)
	pending := 1
	processed := 0
	limitReached := false

	for i := 0; i < s.cfg.WorkerCount; i++ {
		go s.worker(jobs, results, outputDir)
	}

	for pending > 0 {
		res := <-results
		pending--

		if res.err != nil {
			s.addError(res.page.URL, res.err)
			continue
		}

		s.addPage(res.page)
		processed++
		if s.cfg.MaxPages > 0 && processed >= s.cfg.MaxPages {
			if !limitReached {
				limitReached = true
				if s.log != nil {
					s.log.Warn("Max pages reached; skipping new links", "maxPages", s.cfg.MaxPages)
				}
			}
			continue
		}

		if res.page.Depth < s.cfg.MaxDepth {
			for _, link := range res.page.Links {
				if !s.cfg.IncludeExternal && !s.scope.IsInScope(link) {
					continue
				}
				if _, seen := visited.LoadOrStore(link, true); !seen {
					pending++
					jobs <- job{url: link, depth: res.page.Depth + 1}
				}
			}
		}
	}

	close(jobs)
	return nil
}

func (s *Scraper) worker(jobs <-chan job, results chan<- result, outputDir string) {
	for j := range jobs {
		pageRecord, err := s.processPage(j.url, j.depth, outputDir)
		results <- result{page: pageRecord, err: err}
	}
}

func (s *Scraper) processPage(pageURL string, depth int, outputDir string) (record PageRecord, err error) {
	record = PageRecord{URL: pageURL, Depth: depth}
	defer func() {
		if r := recover(); r != nil {
			s.addError(pageURL, fmt.Errorf("panic while processing %s: %v", pageURL, r))
			err = fmt.Errorf("panic while processing %s: %v", pageURL, r)
		}
	}()

	normalized, err := normalizeURL(pageURL)
	if err != nil {
		return record, err
	}
	pageURL = normalized
	record.URL = pageURL

	if err := validateTarget(pageURL, s.cfg.AllowPrivateHosts); err != nil {
		return record, err
	}

	rawHTML, fetchErr := fetchHTML(
		s.pageClient,
		pageURL,
		s.cfg.UserAgent,
		s.cfg.Headers,
		time.Duration(s.cfg.RequestDelayMillis)*time.Millisecond,
		s.cfg.MaxDownloadBytes,
	)

	// Baseline discovery from static HTML
	if fetchErr == nil && rawHTML != "" {
		_, _, _ = s.collectResourcesFromHTML(pageURL, rawHTML)
	}

	decision := renderDecision{Rendered: false, Reason: "static-content"}
	if fetchErr != nil {
		decision.Rendered = true
		decision.Reason = fmt.Sprintf("http_fetch_failed: %v", fetchErr)
	} else {
		decision = detectRendered(rawHTML)
	}

	record.RenderedDetected = decision.Rendered
	record.RenderReason = decision.Reason

	b, _ := s.getBrowser()

	if decision.Rendered && b == nil {
		record.Renderer = "http"
		record.RenderReason = fmt.Sprintf("rod_unavailable: %v", s.browserErr)
		if s.log != nil {
			s.log.Warn("Renderer fallback", "url", pageURL, "renderer", record.Renderer, "reason", record.RenderReason)
		}
		if rawHTML == "" {
			return record, fmt.Errorf("renderer fallback failed: %v", s.browserErr)
		}
		if err := s.processStaticPage(pageURL, outputDir, rawHTML, &record); err != nil {
			return record, err
		}
		return record, nil
	}

	if decision.Rendered {
		record.Renderer = "rod"
		if s.log != nil {
			s.log.Info("Renderer decision", "url", pageURL, "renderer", record.Renderer, "reason", decision.Reason)
		}
		if err := s.processRenderedPage(b, pageURL, outputDir, &record); err != nil {
			return record, err
		}
		return record, nil
	}

	record.Renderer = "http"
	if s.log != nil {
		s.log.Info("Renderer decision", "url", pageURL, "renderer", record.Renderer, "reason", decision.Reason)
	}
	if err := s.processStaticPage(pageURL, outputDir, rawHTML, &record); err != nil {
		return record, err
	}
	return record, nil
}

func (s *Scraper) processRenderedPage(browser *rod.Browser, pageURL string, outputDir string, record *PageRecord) error {
	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return fmt.Errorf("create page: %w", err)
	}
	if s.cfg.PageTimeoutSeconds > 0 {
		page = page.Timeout(time.Duration(s.cfg.PageTimeoutSeconds) * time.Second)
	}
	defer page.Close()

	if s.cfg.SessionPath != "" {
		if len(s.cfg.SessionKey) == 0 {
			if s.log != nil {
				s.log.Warn("session key missing; skipping session load", "url", pageURL)
			}
		} else if _, err := os.Stat(s.cfg.SessionPath); err == nil {
			mgr := session.NewSessionManager(s.cfg.SessionPath, s.cfg.SessionKey)
			if err := mgr.Load(page); err != nil {
				s.addError(pageURL, err)
			}
		}
	}

	userAgent := s.cfg.UserAgent
	if headerUA := headerValue(s.cfg.Headers, "User-Agent"); headerUA != "" {
		userAgent = headerUA
	}
	if userAgent != "" {
		err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: userAgent,
		})
		if err != nil {
			s.log.Warn("failed to set user agent", "error", err)
		}
	}
	if len(s.cfg.Headers) > 0 {
		cleanup := page.MustSetExtraHeaders(headerPairs(s.cfg.Headers)...)
		defer cleanup()
	}

	if err := page.Navigate(pageURL); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		return fmt.Errorf("wait load: %w", err)
	}
	s.syncCookies(page, pageURL)

	if s.cfg.Scroll {
		scrollToBottom(page)
	}

	if s.cfg.EnableScreenshot {
		if shotPath, err := s.captureScreenshotFromPage(page, pageURL, outputDir); err != nil {
			s.addError(pageURL, err)
		} else {
			record.ScreenshotPath = shotPath
		}
	}

	html, err := page.HTML()
	if err != nil {
		return fmt.Errorf("get html: %w", err)
	}
	htmlPath, err := writeHTML(outputDir, pageURL, html)
	if err != nil {
		return err
	}
	record.HTMLPath = htmlPath

	links, sources, imports := s.collectResources(pageURL, page)
	record.Links = uniqueStrings(links)
	record.Sources = uniqueStrings(sources)
	record.Imports = uniqueStrings(imports)

	// Record immediately to database
	if s.store != nil {
		for _, link := range record.Links {
			_ = s.store.RecordLink(pageURL, link)
		}
		for _, src := range record.Sources {
			_ = s.store.RecordAsset(src, "source", pageURL, "")
		}
		for _, imp := range record.Imports {
			_ = s.store.RecordAsset(imp, "import", pageURL, "")
		}
	}

	if s.cfg.MaxLinksPerPage > 0 && len(record.Links) > s.cfg.MaxLinksPerPage {
		record.Links = record.Links[:s.cfg.MaxLinksPerPage]
	}

	var discovered []string
	for _, src := range record.Sources {
		discovered = append(discovered, s.downloadResource(src, pageURL, outputDir, "source")...)
	}
	for _, imp := range record.Imports {
		discovered = append(discovered, s.downloadResource(imp, pageURL, outputDir, "import")...)
	}
	record.Imports = uniqueStrings(append(record.Imports, discovered...))
	if s.store != nil {
		for _, imp := range discovered {
			_ = s.store.RecordAsset(imp, "import", pageURL, "")
		}
	}

	return nil
}

func (s *Scraper) processStaticPage(pageURL string, outputDir string, htmlContent string, record *PageRecord) error {
	if htmlContent == "" {
		return fmt.Errorf("empty html content")
	}

	htmlPath, err := writeHTML(outputDir, pageURL, htmlContent)
	if err != nil {
		return err
	}
	record.HTMLPath = htmlPath

	links, sources, imports := s.collectResourcesFromHTML(pageURL, htmlContent)
	record.Links = uniqueStrings(links)
	record.Sources = uniqueStrings(sources)
	record.Imports = uniqueStrings(imports)

	if s.cfg.MaxLinksPerPage > 0 && len(record.Links) > s.cfg.MaxLinksPerPage {
		record.Links = record.Links[:s.cfg.MaxLinksPerPage]
	}

	var discovered []string
	for _, src := range record.Sources {
		discovered = append(discovered, s.downloadResource(src, pageURL, outputDir, "source")...)
	}
	for _, imp := range record.Imports {
		discovered = append(discovered, s.downloadResource(imp, pageURL, outputDir, "import")...)
	}
	record.Imports = uniqueStrings(append(record.Imports, discovered...))
	if s.store != nil {
		for _, imp := range discovered {
			_ = s.store.RecordAsset(imp, "import", pageURL, "")
		}
	}

	if s.cfg.EnableScreenshot {
		b, _ := s.getBrowser()
		if b == nil {
			s.addError(pageURL, fmt.Errorf("screenshot skipped: browser unavailable"))
		} else {
			if shotPath, err := s.captureScreenshot(b, pageURL, outputDir); err != nil {
				s.addError(pageURL, err)
			} else {
				record.ScreenshotPath = shotPath
			}
		}
	}

	return nil
}

func (s *Scraper) captureScreenshot(browser *rod.Browser, pageURL string, outputDir string) (string, error) {
	if browser == nil {
		return "", fmt.Errorf("browser not available")
	}

	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return "", fmt.Errorf("create page: %w", err)
	}
	if s.cfg.PageTimeoutSeconds > 0 {
		page = page.Timeout(time.Duration(s.cfg.PageTimeoutSeconds) * time.Second)
	}
	defer page.Close()

	if s.cfg.SessionPath != "" {
		if len(s.cfg.SessionKey) == 0 {
			if s.log != nil {
				s.log.Warn("session key missing; skipping session load", "url", pageURL)
			}
		} else if _, err := os.Stat(s.cfg.SessionPath); err == nil {
			mgr := session.NewSessionManager(s.cfg.SessionPath, s.cfg.SessionKey)
			if err := mgr.Load(page); err != nil {
				return "", err
			}
		}
	}

	userAgent := s.cfg.UserAgent
	if headerUA := headerValue(s.cfg.Headers, "User-Agent"); headerUA != "" {
		userAgent = headerUA
	}
	if userAgent != "" {
		err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: userAgent,
		})
		if err != nil {
			s.log.Warn("failed to set user agent", "error", err)
		}
	}

	if err := page.Navigate(pageURL); err != nil {
		return "", fmt.Errorf("navigate for screenshot: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		return "", fmt.Errorf("wait load for screenshot: %w", err)
	}
	s.syncCookies(page, pageURL)

	if s.cfg.Scroll {
		scrollToBottom(page)
	}

	return s.captureScreenshotFromPage(page, pageURL, outputDir)
}

func (s *Scraper) captureScreenshotFromPage(page *rod.Page, pageURL string, outputDir string) (string, error) {
	shotDir := s.cfg.ScreenshotPath
	if shotDir == "" {
		shotDir = filepath.Join(outputDir, "screenshots")
	}
	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format: proto.PageCaptureScreenshotFormatPng,
	})
	if err != nil {
		return "", fmt.Errorf("capture screenshot: %w", err)
	}
	return writeScreenshot(shotDir, pageURL, img)
}

func (s *Scraper) collectResources(pageURL string, page *rod.Page) ([]string, []string, []string) {
	var links []string
	var sources []string
	var imports []string

	add := func(raw string, list *[]string, kind string) {
		if raw == "" {
			return
		}
		resolved, err := resolveURL(pageURL, raw)
		if err != nil {
			return
		}
		clean, err := normalizeURL(resolved)
		if err != nil {
			return
		}
		if !isHTTPURL(clean) {
			return
		}
		*list = append(*list, clean)

		// Immediate sink to store
		if s.store != nil {
			if kind == "link" {
				_ = s.store.RecordLink(pageURL, clean)
			} else {
				_ = s.store.RecordAsset(clean, kind, pageURL, "")
			}
		}
	}

	elements, _ := page.Elements("a[href]")
	for _, el := range elements {
		if href, _ := el.Attribute("href"); href != nil {
			add(*href, &links, "link")
		}
	}
	formEls, _ := page.Elements("form[action]")
	for _, el := range formEls {
		if action, _ := el.Attribute("action"); action != nil {
			add(*action, &links, "link")
		}
	}

	linkEls, _ := page.Elements("link[href]")
	for _, el := range linkEls {
		if href, _ := el.Attribute("href"); href != nil {
			add(*href, &sources, "source")
		}
	}

	scriptEls, _ := page.Elements("script[src]")
	for _, el := range scriptEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources, "source")
		}
	}

	imgEls, _ := page.Elements("img[src]")
	for _, el := range imgEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources, "source")
		}
		if srcset, _ := el.Attribute("srcset"); srcset != nil {
			for _, candidate := range parseSrcSet(*srcset) {
				add(candidate, &sources, "source")
			}
		}
	}

	mediaEls, _ := page.Elements("video[src], audio[src]")
	for _, el := range mediaEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources, "source")
		}
	}

	frameEls, _ := page.Elements("iframe[src], frame[src]")
	for _, el := range frameEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources, "source")
		}
	}

	objEls, _ := page.Elements("object[data], embed[src]")
	for _, el := range objEls {
		if data, _ := el.Attribute("data"); data != nil {
			add(*data, &sources, "source")
		}
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources, "source")
		}
	}

	sourceEls, _ := page.Elements("source[src]")
	for _, el := range sourceEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources, "source")
		}
		if srcset, _ := el.Attribute("srcset"); srcset != nil {
			for _, candidate := range parseSrcSet(*srcset) {
				add(candidate, &sources, "source")
			}
		}
	}

	styleEls, _ := page.Elements("style")
	for _, el := range styleEls {
		if text, err := el.Text(); err == nil {
			for _, urlRef := range parseCSSImports(text) {
				add(urlRef, &imports, "import")
			}
		}
	}

	styleAttrEls, _ := page.Elements("[style]")
	for _, el := range styleAttrEls {
		if styleText, _ := el.Attribute("style"); styleText != nil {
			for _, urlRef := range parseCSSImports(*styleText) {
				add(urlRef, &imports, "import")
			}
		}
	}

	return links, sources, imports
}

func collectResourcesFromHTML(pageURL string, htmlContent string) ([]string, []string, []string) {
	var links []string
	var sources []string
	var imports []string
	baseURL := pageURL

	add := func(raw string, list *[]string) {
		if raw == "" {
			return
		}
		resolved, err := resolveURL(baseURL, raw)
		if err != nil {
			return
		}
		clean, err := normalizeURL(resolved)
		if err != nil {
			return
		}
		if !isHTTPURL(clean) {
			return
		}
		*list = append(*list, clean)
	}

	tokenizer := html.NewTokenizer(strings.NewReader(htmlContent))
	inStyle := false
	var styleContent strings.Builder

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return links, sources, imports
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(token.Data)

			if tag == "base" {
				if href, ok := attrValue(token.Attr, "href"); ok {
					if resolved, err := resolveURL(pageURL, href); err == nil {
						baseURL = resolved
					}
				}
			}

			if tag == "style" {
				inStyle = true
				styleContent.Reset()
			}

			if styleAttr, ok := attrValue(token.Attr, "style"); ok {
				for _, urlRef := range parseCSSImports(styleAttr) {
					add(urlRef, &imports)
				}
			}

			switch tag {
			case "a":
				if href, ok := attrValue(token.Attr, "href"); ok {
					add(href, &links)
				}
			case "form":
				if action, ok := attrValue(token.Attr, "action"); ok {
					add(action, &links)
				}
			case "link":
				if href, ok := attrValue(token.Attr, "href"); ok {
					add(href, &sources)
				}
			case "script":
				if src, ok := attrValue(token.Attr, "src"); ok {
					add(src, &sources)
				}
			case "img":
				if src, ok := attrValue(token.Attr, "src"); ok {
					add(src, &sources)
				}
				if srcset, ok := attrValue(token.Attr, "srcset"); ok {
					for _, candidate := range parseSrcSet(srcset) {
						add(candidate, &sources)
					}
				}
			case "source":
				if src, ok := attrValue(token.Attr, "src"); ok {
					add(src, &sources)
				}
				if srcset, ok := attrValue(token.Attr, "srcset"); ok {
					for _, candidate := range parseSrcSet(srcset) {
						add(candidate, &sources)
					}
				}
			case "video", "audio":
				if src, ok := attrValue(token.Attr, "src"); ok {
					add(src, &sources)
				}
			case "iframe", "frame":
				if src, ok := attrValue(token.Attr, "src"); ok {
					add(src, &sources)
				}
			case "object":
				if data, ok := attrValue(token.Attr, "data"); ok {
					add(data, &sources)
				}
			case "embed":
				if src, ok := attrValue(token.Attr, "src"); ok {
					add(src, &sources)
				}
			}
		case html.TextToken:
			if inStyle {
				styleContent.WriteString(tokenizer.Token().Data)
			}
		case html.EndTagToken:
			token := tokenizer.Token()
			if strings.EqualFold(token.Data, "style") {
				inStyle = false
				for _, urlRef := range parseCSSImports(styleContent.String()) {
					add(urlRef, &imports)
				}
				styleContent.Reset()
			}
		}
	}
}

func (s *Scraper) collectResourcesFromHTML(pageURL string, htmlContent string) ([]string, []string, []string) {
	links, sources, imports := collectResourcesFromHTML(pageURL, htmlContent)

	if s.store != nil {
		for _, link := range links {
			_ = s.store.RecordLink(pageURL, link)
		}
		for _, src := range sources {
			_ = s.store.RecordAsset(src, "source", pageURL, "")
		}
		for _, imp := range imports {
			_ = s.store.RecordAsset(imp, "import", pageURL, "")
		}
	}

	return links, sources, imports
}

func attrValue(attrs []html.Attribute, key string) (string, bool) {
	for _, attr := range attrs {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val, true
		}
	}
	return "", false
}

func (s *Scraper) downloadResource(rawURL string, fromPage string, outputDir string, kind string) []string {
	var discovered []string
	if rawURL == "" {
		return discovered
	}
	clean, err := normalizeURL(rawURL)
	if err != nil {
		return discovered
	}
	rawURL = clean
	if !isHTTPURL(rawURL) {
		return discovered
	}
	if err := validateTarget(rawURL, s.cfg.AllowPrivateHosts); err != nil {
		return discovered
	}
	if !s.cfg.IncludeExternal && !s.scope.IsInScope(rawURL) {
		return discovered
	}
	if _, seen := s.downloads.LoadOrStore(rawURL, true); seen {
		return discovered
	}

	path, err := buildResourcePath(outputDir, rawURL)
	if err != nil {
		s.addError(rawURL, err)
		return discovered
	}

	if err := fetchToFile(
		s.client,
		rawURL,
		path,
		s.cfg.UserAgent,
		s.cfg.Headers,
		time.Duration(s.cfg.RequestDelayMillis)*time.Millisecond,
		s.cfg.MaxDownloadBytes,
	); err != nil {
		s.addError(rawURL, err)
		return discovered
	}

	s.addDownload(FileRecord{
		URL:      rawURL,
		Path:     path,
		FromPage: fromPage,
		Kind:     kind,
	})

	if strings.HasSuffix(strings.ToLower(path), ".css") {
		if content, err := os.ReadFile(path); err == nil {
			for _, ref := range parseCSSImports(string(content)) {
				resolved, err := resolveURL(rawURL, ref)
				if err == nil {
					if isHTTPURL(resolved) {
						discovered = append(discovered, resolved)
						discovered = append(discovered, s.downloadResource(resolved, fromPage, outputDir, "import")...)
					}
				}
			}
		}
	}

	if strings.HasSuffix(strings.ToLower(path), ".js") {
		if content, err := os.ReadFile(path); err == nil {
			for _, ref := range parseJSImport(string(content)) {
				resolved, err := resolveURL(rawURL, ref)
				if err == nil {
					if isHTTPURL(resolved) {
						discovered = append(discovered, resolved)
						// If it looks like a route (no extension or .html), record as link
						if s.store != nil {
							ext := strings.ToLower(filepath.Ext(resolved))
							if ext == "" || ext == ".html" || ext == ".php" {
								_ = s.store.RecordLink(fromPage, resolved)
							}
						}
						discovered = append(discovered, s.downloadResource(resolved, fromPage, outputDir, "import")...)
					}
				}
			}
		}
	}

	return discovered
}

func (s *Scraper) loadSessionCookies(target string) error {
	if s.cfg.SessionPath == "" || s.client == nil || s.client.Jar == nil {
		return nil
	}
	if len(s.cfg.SessionKey) == 0 {
		if s.log != nil {
			s.log.Warn("session key missing; skipping session cookie load", "target", target)
		}
		return nil
	}
	if _, err := os.Stat(s.cfg.SessionPath); err != nil {
		return nil
	}
	mgr := session.NewSessionManager(s.cfg.SessionPath, s.cfg.SessionKey)
	return mgr.ApplyCookiesToJar(s.client.Jar, target)
}

func fetchHTML(client *http.Client, rawURL string, userAgent string, headers map[string]string, delay time.Duration, maxBytes int64) (string, error) {
	if client == nil {
		return "", fmt.Errorf("http client not configured")
	}
	if maxBytes == 0 {
		maxBytes = defaultMaxDownloadBytes
	}
	if delay > 0 {
		time.Sleep(delay)
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	applyHeaders(req, headers)

	resp, err := client.Do(req)
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

func applyHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		req.Header.Set(key, value)
	}
}

func headerValue(headers map[string]string, key string) string {
	for headerKey, value := range headers {
		if strings.EqualFold(headerKey, key) {
			return value
		}
	}
	return ""
}

func headerPairs(headers map[string]string) []string {
	if len(headers) == 0 {
		return nil
	}
	pairs := make([]string, 0, len(headers)*2)
	for key, value := range headers {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		pairs = append(pairs, key, value)
	}
	return pairs
}

var spaMarkers = []string{
	`id="root"`,
	`id='root'`,
	`id="app"`,
	`id='app'`,
	`data-reactroot`,
	`data-reactid`,
	`__next_data__`,
	`__nuxt`,
	`data-v-app`,
	`ng-app`,
	`data-ng-app`,
	`ng-version`,
	`sveltekit`,
}

func detectRendered(htmlContent string) renderDecision {
	trimmed := strings.TrimSpace(htmlContent)
	if trimmed == "" {
		return renderDecision{Rendered: true, Reason: "empty-html"}
	}

	lower := strings.ToLower(trimmed)
	for _, marker := range spaMarkers {
		if strings.Contains(lower, marker) {
			return renderDecision{Rendered: true, Reason: "spa-marker"}
		}
	}

	if strings.Contains(lower, "enable javascript") ||
		strings.Contains(lower, "enable js") ||
		strings.Contains(lower, "javascript required") ||
		strings.Contains(lower, "requires javascript") {
		return renderDecision{Rendered: true, Reason: "noscript-js-required"}
	}

	metrics := analyzeHTMLMetrics(trimmed)
	bodyText := metrics.BodyTextLen
	if bodyText == 0 {
		bodyText = metrics.TotalTextLen
	}
	textRatio := float64(bodyText) / float64(len(trimmed))

	if bodyText < 80 && len(trimmed) > 600 {
		return renderDecision{Rendered: true, Reason: "low-body-text"}
	}
	if textRatio < 0.02 && (metrics.ScriptSrcCount >= 2 || metrics.ScriptCount >= 3) {
		return renderDecision{Rendered: true, Reason: "low-text-script-heavy"}
	}
	if metrics.ScriptSrcCount >= 4 && bodyText < 200 {
		return renderDecision{Rendered: true, Reason: "script-heavy"}
	}

	return renderDecision{Rendered: false, Reason: "static-content"}
}

func analyzeHTMLMetrics(htmlContent string) htmlMetrics {
	var metrics htmlMetrics
	tokenizer := html.NewTokenizer(strings.NewReader(htmlContent))
	inBody := false
	inScript := false
	inStyle := false

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return metrics
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(token.Data)
			switch tag {
			case "body":
				inBody = true
			case "script":
				inScript = true
				metrics.ScriptCount++
				if _, ok := attrValue(token.Attr, "src"); ok {
					metrics.ScriptSrcCount++
				}
			case "style":
				inStyle = true
			}
		case html.EndTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(token.Data)
			switch tag {
			case "body":
				inBody = false
			case "script":
				inScript = false
			case "style":
				inStyle = false
			}
		case html.TextToken:
			if inScript || inStyle {
				continue
			}
			text := strings.TrimSpace(tokenizer.Token().Data)
			if text == "" {
				continue
			}
			metrics.TotalTextLen += len(text)
			if inBody {
				metrics.BodyTextLen += len(text)
			}
		}
	}
}

func (s *Scraper) syncCookies(page *rod.Page, pageURL string) {
	if s.client.Jar == nil {
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

	s.client.Jar.SetCookies(parsed, jarCookies)
}

func (s *Scraper) addPage(record PageRecord) {
	if s.store != nil {
		if err := s.store.RecordPage(record.URL, record.Depth, record.HTMLPath); err != nil && s.log != nil {
			s.log.Warn("scrape db: record page failed", "url", record.URL, "error", err)
		}
		for _, link := range record.Links {
			if err := s.store.RecordLink(record.URL, link); err != nil && s.log != nil {
				s.log.Warn("scrape db: record link failed", "from", record.URL, "to", link, "error", err)
			}
		}
		for _, src := range record.Sources {
			if err := s.store.RecordAsset(src, "source", record.URL, ""); err != nil && s.log != nil {
				s.log.Warn("scrape db: record asset failed", "url", src, "error", err)
			}
		}
		for _, imp := range record.Imports {
			if err := s.store.RecordAsset(imp, "import", record.URL, ""); err != nil && s.log != nil {
				s.log.Warn("scrape db: record import failed", "url", imp, "error", err)
			}
		}
	}
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	s.manifest.Pages = append(s.manifest.Pages, record)
}

func (s *Scraper) addDownload(record FileRecord) {
	if s.store != nil {
		if err := s.store.RecordAsset(record.URL, record.Kind, record.FromPage, record.Path); err != nil && s.log != nil {
			s.log.Warn("scrape db: record download failed", "url", record.URL, "error", err)
		}
	}
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	s.manifest.Downloads = append(s.manifest.Downloads, record)
}

func (s *Scraper) addError(target string, err error) {
	if s.store != nil {
		if dbErr := s.store.RecordError(target, "scrape", err); dbErr != nil && s.log != nil {
			s.log.Warn("scrape db: record error failed", "url", target, "error", dbErr)
		}
	}
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	s.manifest.Errors = append(s.manifest.Errors, ErrorRecord{
		URL:   target,
		Error: err.Error(),
	})
}

func (s *Scraper) writeManifest(outputDir string) error {
	filename := "manifest.json"
	if strings.EqualFold(s.cfg.ManifestFormat, "yaml") || strings.EqualFold(s.cfg.ManifestFormat, "yml") {
		filename = "manifest.yaml"
	}

	path := filepath.Join(outputDir, filename)
	var data []byte
	var err error
	if strings.HasSuffix(filename, ".yaml") {
		data, err = yaml.Marshal(&s.manifest)
	} else {
		data, err = json.MarshalIndent(&s.manifest, "", "  ")
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeHTML(outputDir string, pageURL string, html string) (string, error) {
	targetPath, err := buildResourcePath(filepath.Join(outputDir, "pages"), pageURL)
	if err != nil {
		return "", err
	}

	if !strings.HasSuffix(strings.ToLower(targetPath), ".html") {
		targetPath += ".html"
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", err
	}
	return targetPath, os.WriteFile(targetPath, []byte(html), 0o644)
}

func writeScreenshot(outputDir string, pageURL string, img []byte) (string, error) {
	targetPath, err := buildResourcePath(outputDir, pageURL)
	if err != nil {
		return "", err
	}

	if !strings.HasSuffix(strings.ToLower(targetPath), ".png") {
		targetPath += ".png"
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", err
	}
	return targetPath, os.WriteFile(targetPath, img, 0o644)
}

func buildResourcePath(baseDir string, rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("missing host")
	}

	host := sanitizeSegment(parsed.Hostname())
	cleanPath := path.Clean("/" + parsed.Path)
	if cleanPath == "/" {
		cleanPath = "/index"
	}
	relPath := filepath.FromSlash(cleanPath)

	dir := filepath.Join(baseDir, host, filepath.Dir(relPath))
	filename := sanitizeSegment(filepath.Base(relPath))

	if parsed.RawQuery != "" {
		hash := sha1.Sum([]byte(parsed.RawQuery))
		filename = filename + "__q_" + hex.EncodeToString(hash[:8])
	}

	finalDir, err := ensureDir(dir)
	if err != nil {
		return "", err
	}

	fullPath := filepath.Join(finalDir, filename)
	if fi, err := os.Stat(fullPath); err == nil && fi.IsDir() {
		fullPath = fullPath + "__file"
	}
	return fullPath, nil
}

func ensureDir(path string) (string, error) {
	candidate := path
	for i := 0; i < 5; i++ {
		fi, err := os.Stat(candidate)
		if err == nil {
			if fi.IsDir() {
				return candidate, nil
			}
			candidate = candidate + "__dir"
			continue
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		if err := os.MkdirAll(candidate, 0o755); err != nil {
			if os.IsExist(err) {
				candidate = candidate + "__dir"
				continue
			}
			return "", err
		}
		return candidate, nil
	}
	return "", fmt.Errorf("unable to create directory: %s", path)
}

func fetchToFile(client *http.Client, rawURL string, dest string, userAgent string, headers map[string]string, delay time.Duration, maxBytes int64) error {
	if delay > 0 {
		time.Sleep(delay)
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if userAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	applyHeaders(req, headers)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("fetch %s: status %d", rawURL, resp.StatusCode)
	}
	if maxBytes > 0 && resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		return fmt.Errorf("fetch %s: content length %d exceeds limit %d", rawURL, resp.ContentLength, maxBytes)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if maxBytes > 0 {
		limit := &io.LimitedReader{R: resp.Body, N: maxBytes + 1}
		written, err := io.Copy(f, limit)
		if err != nil {
			f.Close()
			return err
		}
		if written > maxBytes {
			f.Close()
			return fmt.Errorf("fetch %s: download exceeded limit %d", rawURL, maxBytes)
		}
	} else if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
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

func normalizeURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	parsed.Fragment = ""
	if parsed.Scheme != "" {
		parsed.Scheme = strings.ToLower(parsed.Scheme)
	}
	if parsed.Host != "" {
		parsed.Host = strings.ToLower(parsed.Host)
	}
	return parsed.String(), nil
}

func validateTarget(raw string, allowPrivate bool) error {
	if allowPrivate {
		return validator.ValidateURL(raw)
	}
	return validator.ValidateTargetURL(raw)
}

func parseSrcSet(value string) []string {
	var results []string
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) > 0 {
			results = append(results, fields[0])
		}
	}
	return results
}

var cssImportRe = regexp.MustCompile(`@import\s+(?:url\()?['"]?([^'")\s]+)`)
var cssURLRe = regexp.MustCompile(`url\(\s*['"]?([^'")\s]+)`)

func parseCSSImports(content string) []string {
	var results []string
	for _, match := range cssImportRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}
	for _, match := range cssURLRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}
	return results
}

var importRe = regexp.MustCompile(`(?m)^\s*import\s+(?:[^'"]+\s+from\s+)?["']([^"']+)["']`)
var dynamicImportRe = regexp.MustCompile(`import\(\s*["']([^"']+)["']\s*\)`)
var requireRe = regexp.MustCompile(`require\(\s*["']([^"']+)["']\s*\)`)
var pathRe = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-\./]+)["']`)
var nextChunkRe = regexp.MustCompile(`static/chunks/[a-zA-Z0-9_\-\.]+\.js`)

func parseJSImport(content string) []string {
	var results []string
	for _, match := range importRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}
	for _, match := range dynamicImportRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}
	for _, match := range requireRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}
	for _, match := range pathRe.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			p := match[1]
			if len(p) > 1 && !strings.Contains(p, "//") {
				results = append(results, p)
			}
		}
	}
	for _, match := range nextChunkRe.FindAllString(content, -1) {
		results = append(results, "/_next/"+match)
	}
	return results
}

func sanitizeSegment(value string) string {
	value = strings.ReplaceAll(value, "..", "")
	value = strings.ReplaceAll(value, "\\", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.TrimSpace(value)
	if value == "" {
		return "item"
	}
	return value
}

func scrollToBottom(page *rod.Page) {
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

func isHTTPURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}
