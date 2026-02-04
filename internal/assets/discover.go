// Package assets provides asset discovery capabilities
package assets

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// AssetType represents the type of discovered asset
type AssetType string

const (
	AssetJavaScript AssetType = "javascript"
	AssetCSS        AssetType = "css"
	AssetImage      AssetType = "image"
	AssetFont       AssetType = "font"
	AssetJSON       AssetType = "json"
	AssetOther      AssetType = "other"
)

// Asset represents a discovered asset
type Asset struct {
	URL         string    `json:"url"`
	Type        AssetType `json:"type"`
	Size        int64     `json:"size,omitempty"`
	StatusCode  int       `json:"status_code"`
	ContentType string    `json:"content_type,omitempty"`
}

// DiscoveryResult contains all discovered assets
type DiscoveryResult struct {
	BaseURL       string            `json:"base_url"`
	Assets        []Asset           `json:"assets"`
	TotalCount    int               `json:"total_count"`
	ByType        map[AssetType]int `json:"by_type"`
	TotalSize     int64             `json:"total_size"`
	ExternalHosts []string          `json:"external_hosts,omitempty"`
}

// Discoverer handles asset discovery
type Discoverer struct {
	httpClient *http.Client
	timeout    time.Duration
}

// DiscovererOption configures the discoverer
type DiscovererOption func(*Discoverer)

// WithTimeout sets the timeout
func WithTimeout(timeout time.Duration) DiscovererOption {
	return func(d *Discoverer) {
		d.timeout = timeout
	}
}

// NewDiscoverer creates a new asset discoverer
func NewDiscoverer(opts ...DiscovererOption) (*Discoverer, error) {
	d := &Discoverer{
		timeout: 30 * time.Second,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	
	for _, opt := range opts {
		opt(d)
	}
	
	return d, nil
}

// Discover performs comprehensive asset discovery
func (d *Discoverer) Discover(baseURL string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		BaseURL:       baseURL,
		Assets:        []Asset{},
		ByType:        make(map[AssetType]int),
		ExternalHosts: []string{},
	}
	
	discovered := make(map[string]bool)
	
	// Fetch main page
	resp, err := d.httpClient.Get(baseURL)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	content := string(body)
	
	// Extract JavaScript
	jsPattern := regexp.MustCompile(`src=["']([^"']+\.js[^"']*)["']`)
	jsMatches := jsPattern.FindAllStringSubmatch(content, -1)
	for _, match := range jsMatches {
		if len(match) > 1 && !discovered[match[1]] {
			discovered[match[1]] = true
			assetURL := resolveURL(baseURL, match[1])
			result.Assets = append(result.Assets, Asset{
				URL:  assetURL,
				Type: AssetJavaScript,
			})
		}
	}
	
	// Extract CSS
	cssPattern := regexp.MustCompile(`href=["']([^"']+\.css[^"']*)["']`)
	cssMatches := cssPattern.FindAllStringSubmatch(content, -1)
	for _, match := range cssMatches {
		if len(match) > 1 && !discovered[match[1]] {
			discovered[match[1]] = true
			assetURL := resolveURL(baseURL, match[1])
			result.Assets = append(result.Assets, Asset{
				URL:  assetURL,
				Type: AssetCSS,
			})
		}
	}
	
	// Extract Images
	imgPattern := regexp.MustCompile(`src=["']([^"']+\.(?:png|jpg|jpeg|gif|svg|webp))["']`)
	imgMatches := imgPattern.FindAllStringSubmatch(content, -1)
	for _, match := range imgMatches {
		if len(match) > 1 && !discovered[match[1]] {
			discovered[match[1]] = true
			assetURL := resolveURL(baseURL, match[1])
			result.Assets = append(result.Assets, Asset{
				URL:  assetURL,
				Type: AssetImage,
			})
		}
	}
	
	// Calculate stats
	result.TotalCount = len(result.Assets)
	for _, asset := range result.Assets {
		result.ByType[asset.Type]++
		
		if host := extractHost(asset.URL); host != "" && !isSameHost(baseURL, asset.URL) {
			if !contains(result.ExternalHosts, host) {
				result.ExternalHosts = append(result.ExternalHosts, host)
			}
		}
	}
	
	return result, nil
}

func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if strings.HasPrefix(ref, "data:") {
		return ""
	}
	
	b, _ := url.Parse(base)
	r, _ := url.Parse(ref)
	if b == nil || r == nil {
		return ""
	}
	
	return b.ResolveReference(r).String()
}

func extractHost(assetURL string) string {
	u, _ := url.Parse(assetURL)
	if u == nil {
		return ""
	}
	return u.Host
}

func isSameHost(baseURL, refURL string) bool {
	b, _ := url.Parse(baseURL)
	r, _ := url.Parse(refURL)
	if b == nil || r == nil {
		return false
	}
	return b.Host == r.Host
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Close cleans up resources
func (d *Discoverer) Close() error {
	return nil
}

// GenerateReport generates JSON report
func (d *Discoverer) GenerateReport(result *DiscoveryResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}