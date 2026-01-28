// Package scrape provides scope-based crawling and asset scraping.
package scrape

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/coppertone/bug-hunter/app/aegis/internal/scope"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"gopkg.in/yaml.v3"
)

type Config struct {
	MaxDepth        int
	UserAgent       string
	Headless        bool
	Scroll          bool
	WorkerCount     int
	IncludeExternal bool
	OutputDir       string
	SessionPath     string
	SessionKey      []byte
	ManifestFormat  string // json or yaml
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
	URL          string   `json:"url" yaml:"url"`
	Depth        int      `json:"depth" yaml:"depth"`
	HTMLPath     string   `json:"html_path" yaml:"html_path"`
	Links        []string `json:"links" yaml:"links"`
	Sources      []string `json:"sources" yaml:"sources"`
	Imports      []string `json:"imports" yaml:"imports"`
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
	cfg        Config
	scopeFile  string
	scope      *scope.Scope
	downloads  sync.Map
	manifestMu sync.Mutex
	manifest   Manifest
	client     *http.Client
}

type job struct {
	url   string
	depth int
}

type result struct {
	page PageRecord
	err  error
}

// ScrapeScope crawls every in-scope target and saves a manifest and assets.
func ScrapeScope(projectDir string, scopePath string, cfg Config) error {
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 2
	}
	if cfg.ManifestFormat == "" {
		cfg.ManifestFormat = "json"
	}

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

	s := &Scraper{
		cfg:       cfg,
		scopeFile: scopePath,
		scope:     parsedScope,
		client: func() *http.Client {
			jar, _ := cookiejar.New(nil)
			return &http.Client{
				Timeout: 30 * time.Second,
				Jar:     jar,
			}
		}(),
		manifest: Manifest{
			GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
			ScopeFile:       scopePath,
			IncludeExternal: cfg.IncludeExternal,
			Targets:         parsedScope.Targets(),
		},
	}

	for _, target := range s.manifest.Targets {
		if err := s.scrapeTarget(target, outputDir); err != nil {
			s.addError(target, err)
		}
	}

	return s.writeManifest(outputDir)
}

func (s *Scraper) scrapeTarget(target string, outputDir string) error {
	l := launcher.New().Headless(s.cfg.Headless)
	u, err := l.Launch()
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	visited := sync.Map{}
	jobs := make(chan job, 256)
	results := make(chan result)

	jobs <- job{url: target, depth: 0}
	visited.Store(target, true)
	pending := 1

	for i := 0; i < s.cfg.WorkerCount; i++ {
		go s.worker(browser, jobs, results, outputDir)
	}

	for pending > 0 {
		res := <-results
		pending--

		if res.err != nil {
			s.addError(res.page.URL, res.err)
			continue
		}

		s.addPage(res.page)

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

func (s *Scraper) worker(browser *rod.Browser, jobs <-chan job, results chan<- result, outputDir string) {
	for j := range jobs {
		pageRecord, err := s.processPage(browser, j.url, j.depth, outputDir)
		results <- result{page: pageRecord, err: err}
	}
}

func (s *Scraper) processPage(browser *rod.Browser, pageURL string, depth int, outputDir string) (PageRecord, error) {
	record := PageRecord{URL: pageURL, Depth: depth}

	page := browser.MustPage(pageURL)
	defer page.MustClose()

	if s.cfg.SessionPath != "" {
		if _, err := os.Stat(s.cfg.SessionPath); err == nil {
			mgr := session.NewSessionManager(s.cfg.SessionPath, s.cfg.SessionKey)
			if err := mgr.Load(page); err != nil {
				s.addError(pageURL, err)
			}
		}
	}

	if s.cfg.UserAgent != "" {
		page.MustSetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: s.cfg.UserAgent,
		})
	}

	if err := page.Navigate(pageURL); err != nil {
		return record, fmt.Errorf("navigate: %w", err)
	}
	page.MustWaitLoad()
	s.syncCookies(page, pageURL)

	if s.cfg.Scroll {
		scrollToBottom(page)
	}

	html := page.MustHTML()

	htmlPath, err := writeHTML(outputDir, pageURL, html)
	if err != nil {
		return record, err
	}
	record.HTMLPath = htmlPath

	links, sources, imports := s.collectResources(pageURL, page)
	record.Links = uniqueStrings(links)
	record.Sources = uniqueStrings(sources)
	record.Imports = uniqueStrings(imports)

	var discovered []string
	for _, src := range record.Sources {
		discovered = append(discovered, s.downloadResource(src, pageURL, outputDir, "source")...)
	}
	for _, imp := range record.Imports {
		discovered = append(discovered, s.downloadResource(imp, pageURL, outputDir, "import")...)
	}
	record.Imports = uniqueStrings(append(record.Imports, discovered...))

	return record, nil
}

func (s *Scraper) collectResources(pageURL string, page *rod.Page) ([]string, []string, []string) {
	var links []string
	var sources []string
	var imports []string

	add := func(raw string, list *[]string) {
		if raw == "" {
			return
		}
		resolved, err := resolveURL(pageURL, raw)
		if err != nil {
			return
		}
		if !isHTTPURL(resolved) {
			return
		}
		*list = append(*list, resolved)
	}

	elements, _ := page.Elements("a[href]")
	for _, el := range elements {
		if href, _ := el.Attribute("href"); href != nil {
			add(*href, &links)
		}
	}

	linkEls, _ := page.Elements("link[href]")
	for _, el := range linkEls {
		if href, _ := el.Attribute("href"); href != nil {
			add(*href, &sources)
		}
	}

	scriptEls, _ := page.Elements("script[src]")
	for _, el := range scriptEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources)
		}
	}

	imgEls, _ := page.Elements("img[src]")
	for _, el := range imgEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources)
		}
		if srcset, _ := el.Attribute("srcset"); srcset != nil {
			for _, candidate := range parseSrcSet(*srcset) {
				add(candidate, &sources)
			}
		}
	}

	mediaEls, _ := page.Elements("video[src], audio[src]")
	for _, el := range mediaEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources)
		}
	}

	frameEls, _ := page.Elements("iframe[src], frame[src]")
	for _, el := range frameEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources)
		}
	}

	objEls, _ := page.Elements("object[data], embed[src]")
	for _, el := range objEls {
		if data, _ := el.Attribute("data"); data != nil {
			add(*data, &sources)
		}
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources)
		}
	}

	sourceEls, _ := page.Elements("source[src]")
	for _, el := range sourceEls {
		if src, _ := el.Attribute("src"); src != nil {
			add(*src, &sources)
		}
		if srcset, _ := el.Attribute("srcset"); srcset != nil {
			for _, candidate := range parseSrcSet(*srcset) {
				add(candidate, &sources)
			}
		}
	}

	styleEls, _ := page.Elements("style")
	for _, el := range styleEls {
		if text, err := el.Text(); err == nil {
			for _, urlRef := range parseCSSImports(text) {
				add(urlRef, &imports)
			}
		}
	}

	return links, sources, imports
}

func (s *Scraper) downloadResource(rawURL string, fromPage string, outputDir string, kind string) []string {
	var discovered []string
	if rawURL == "" {
		return discovered
	}
	if !isHTTPURL(rawURL) {
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

	if err := fetchToFile(s.client, rawURL, path, s.cfg.UserAgent); err != nil {
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
						discovered = append(discovered, s.downloadResource(resolved, fromPage, outputDir, "import")...)
					}
				}
			}
		}
	}

	return discovered
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
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	s.manifest.Pages = append(s.manifest.Pages, record)
}

func (s *Scraper) addDownload(record FileRecord) {
	s.manifestMu.Lock()
	defer s.manifestMu.Unlock()
	s.manifest.Downloads = append(s.manifest.Downloads, record)
}

func (s *Scraper) addError(target string, err error) {
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

	fullPath := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return "", err
	}
	return fullPath, nil
}

func fetchToFile(client *http.Client, rawURL string, dest string, userAgent string) error {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
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
	if _, err := io.Copy(f, resp.Body); err != nil {
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
	prevHeight := page.MustEval(`() => document.body.scrollHeight`).Int()
	for i := 0; i < 5; i++ {
		page.MustEval(`() => window.scrollTo(0, document.body.scrollHeight)`)
		time.Sleep(1 * time.Second)
		newHeight := page.MustEval(`() => document.body.scrollHeight`).Int()
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
