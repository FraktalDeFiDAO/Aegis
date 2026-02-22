// Package crawler provides deep crawling capabilities
package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Page represents a discovered page
type Page struct {
	URL         string            `json:"url"`
	Title       string            `json:"title,omitempty"`
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type,omitempty"`
	Links       []string          `json:"links,omitempty"`
	Depth       int               `json:"depth"`
}

// DeepCrawler performs comprehensive page discovery
type DeepCrawler struct {
	httpClient *http.Client
	timeout    time.Duration
	maxDepth   int
	workers    int
	delay      time.Duration
	
	visited map[string]bool
	pages   []Page
	mu      sync.Mutex
}

// CrawlerOption configures the crawler
type CrawlerOption func(*DeepCrawler)

// WithTimeout sets request timeout
func WithTimeout(timeout time.Duration) CrawlerOption {
	return func(c *DeepCrawler) {
		c.timeout = timeout
	}
}

// WithMaxDepth sets maximum crawl depth
func WithMaxDepth(depth int) CrawlerOption {
	return func(c *DeepCrawler) {
		c.maxDepth = depth
	}
}

// WithWorkers sets concurrent workers
func WithWorkers(workers int) CrawlerOption {
	return func(c *DeepCrawler) {
		c.workers = workers
	}
}

// NewDeepCrawler creates a new deep crawler
func NewDeepCrawler(opts ...CrawlerOption) (*DeepCrawler, error) {
	c := &DeepCrawler{
		timeout:  30 * time.Second,
		maxDepth: 3,
		workers:  10,
		delay:    100 * time.Millisecond,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		visited: make(map[string]bool),
		pages:   []Page{},
	}
	
	for _, opt := range opts {
		opt(c)
	}
	
	return c, nil
}

// Crawl starts crawling from a base URL
func (c *DeepCrawler) Crawl(ctx context.Context, baseURL string) ([]Page, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	
	// Crawl first page
	c.crawlPage(ctx, baseURL, 0, base)
	
	return c.pages, nil
}

func (c *DeepCrawler) crawlPage(ctx context.Context, pageURL string, depth int, base *url.URL) {
	if depth > c.maxDepth {
		return
	}
	
	c.mu.Lock()
	if c.visited[pageURL] {
		c.mu.Unlock()
		return
	}
	c.visited[pageURL] = true
	c.mu.Unlock()
	
	time.Sleep(c.delay)
	
	resp, err := c.httpClient.Get(pageURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	page := Page{
		URL:        pageURL,
		StatusCode: resp.StatusCode,
		Depth:      depth,
	}
	
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		page.ContentType = ct
	}
	
	// Extract links if HTML
	if strings.Contains(page.ContentType, "text/html") {
		// Read limited content
		buf := make([]byte, 50000)
		n, _ := resp.Body.Read(buf)
		content := string(buf[:n])
		
		page.Links = c.extractLinks(content, base)
		
		// Extract title
		titlePattern := regexp.MustCompile(`<title>([^<]+)</title>`)
		if matches := titlePattern.FindStringSubmatch(content); len(matches) > 1 {
			page.Title = strings.TrimSpace(matches[1])
		}
	}
	
	c.mu.Lock()
	c.pages = append(c.pages, page)
	c.mu.Unlock()
	
	// Crawl linked pages
	for _, link := range page.Links {
		select {
		case <-ctx.Done():
			return
		default:
			c.crawlPage(ctx, link, depth+1, base)
		}
	}
}

func (c *DeepCrawler) extractLinks(content string, base *url.URL) []string {
	var links []string
	seen := make(map[string]bool)
	
	// Extract anchor tags
	pattern := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := pattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			ref := match[1]
			
			// Skip fragments, javascript, mailto
			if strings.HasPrefix(ref, "#") ||
				strings.HasPrefix(ref, "javascript:") ||
				strings.HasPrefix(ref, "mailto:") ||
				strings.HasPrefix(ref, "tel:") {
				continue
			}
			
			// Resolve URL
			resolved := c.resolveURL(base, ref)
			if resolved == "" {
				continue
			}
			
			// Only same host
			if !isSameOrigin(base, resolved) {
				continue
			}
			
			// Normalize
			resolved = strings.TrimSuffix(resolved, "/")
			
			if !seen[resolved] {
				seen[resolved] = true
				links = append(links, resolved)
			}
		}
	}
	
	return links
}

func (c *DeepCrawler) resolveURL(base *url.URL, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	
	return base.ResolveReference(r).String()
}

func isSameOrigin(base *url.URL, ref string) bool {
	r, err := url.Parse(ref)
	if err != nil {
		return false
	}
	
	return base.Scheme == r.Scheme && base.Host == r.Host
}

// Close cleans up resources
func (c *DeepCrawler) Close() error {
	return nil
}

// GenerateReport generates JSON report
func (c *DeepCrawler) GenerateReport() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.MarshalIndent(c.pages, "", "  ")
}