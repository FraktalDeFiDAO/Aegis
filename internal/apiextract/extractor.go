// Package apiextract provides API endpoint discovery
package apiextract

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	Source     string `json:"source"`
	Technology string `json:"technology,omitempty"`
}

// Extractor handles API endpoint extraction
type Extractor struct {
	httpClient *http.Client
}

// NewExtractor creates a new API endpoint extractor
func NewExtractor() *Extractor {
	return &Extractor{
		httpClient: &http.Client{},
	}
}

// ExtractResult contains all discovered endpoints
type ExtractResult struct {
	BaseURL       string        `json:"base_url"`
	Endpoints     []APIEndpoint `json:"endpoints"`
	REST          []APIEndpoint `json:"rest,omitempty"`
	GraphQL       []APIEndpoint `json:"graphql,omitempty"`
	WebSocket     []APIEndpoint `json:"websocket,omitempty"`
	TotalCount    int           `json:"total_count"`
	ExternalHosts []string      `json:"external_hosts,omitempty"`
}

// Extract performs API extraction
func (e *Extractor) Extract(baseURL string, page interface{}) (*ExtractResult, error) {
	result := &ExtractResult{
		BaseURL:       baseURL,
		Endpoints:     []APIEndpoint{},
		REST:          []APIEndpoint{},
		GraphQL:       []APIEndpoint{},
		WebSocket:     []APIEndpoint{},
		ExternalHosts: []string{},
	}
	
	// Fetch the page
	resp, err := e.httpClient.Get(baseURL)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	content := string(body)
	
	// Extract REST APIs
	restPattern := regexp.MustCompile(`["']([^"']*(?:/api/|/rest/|/v\d+/)[^"']*)["']`)
	matches := restPattern.FindAllStringSubmatch(content, -1)
	
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			endpoint := APIEndpoint{
				URL:        resolveURL(baseURL, match[1]),
				Method:     "GET",
				Source:     "html",
				Technology: "REST",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
			result.REST = append(result.REST, endpoint)
		}
	}
	
	// Extract GraphQL
	graphqlPattern := regexp.MustCompile(`["']([^"']*graphql[^"]*)["']`)
	gMatches := graphqlPattern.FindAllStringSubmatch(content, -1)
	for _, match := range gMatches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			endpoint := APIEndpoint{
				URL:        resolveURL(baseURL, match[1]),
				Method:     "POST",
				Source:     "html",
				Technology: "GraphQL",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
			result.GraphQL = append(result.GraphQL, endpoint)
		}
	}
	
	// Extract WebSockets
	wsPattern := regexp.MustCompile(`(wss?://[^"'\s]+)`)
	wsMatches := wsPattern.FindAllStringSubmatch(content, -1)
	for _, match := range wsMatches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			endpoint := APIEndpoint{
				URL:        match[1],
				Source:     "html",
				Technology: "WebSocket",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
			result.WebSocket = append(result.WebSocket, endpoint)
		}
	}
	
	result.TotalCount = len(result.Endpoints)
	return result, nil
}

func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "ws://") || strings.HasPrefix(ref, "wss://") {
		return ref
	}
	
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	
	return b.ResolveReference(r).String()
}

// GenerateReport generates JSON report
func (e *Extractor) GenerateReport(result *ExtractResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}