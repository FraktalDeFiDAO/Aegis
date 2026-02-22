// Package integration provides complete security scanning integration
// combining XSS, asset discovery, API extraction, and deep crawling
package integration

import (
	"context"
	"fmt"
	"sync"

	"github.com/coppertone/bug-hunter/app/aegis/internal/apiextract"
	"github.com/coppertone/bug-hunter/app/aegis/internal/assets"
	"github.com/coppertone/bug-hunter/app/aegis/internal/content"
	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/exploitable"
	"github.com/coppertone/bug-hunter/app/aegis/internal/owasp25"
	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
	"github.com/coppertone/bug-hunter/app/aegis/internal/xss"
	"github.com/go-rod/rod"
)

// CompleteScanResult contains all scan results
type CompleteScanResult struct {
	Target      string                        `json:"target"`
	XSS         []xss.XSSFinding              `json:"xss,omitempty"`
	Assets      *assets.DiscoveryResult       `json:"assets,omitempty"`
	APIs        *apiextract.ExtractResult     `json:"apis,omitempty"`
	Pages       []crawler.Page                `json:"pages,omitempty"`
	Platform    *platform.Detection           `json:"platform,omitempty"`
	Exploitable []UnifiedFinding              `json:"exploitable,omitempty"`
	OWASP       []owasp25.Finding             `json:"owasp,omitempty"`
	Secrets     []SecretFinding               `json:"secrets,omitempty"`
	Summary     ScanSummary                   `json:"summary"`
}

// ScanSummary provides overview of findings
type ScanSummary struct {
	TotalXSS            int `json:"total_xss"`
	TotalAssets         int `json:"total_assets"`
	TotalAPIs           int `json:"total_apis"`
	TotalPages          int `json:"total_pages"`
	TotalExploitable    int `json:"total_exploitable"`
	TotalOWASP          int `json:"total_owasp"`
	CriticalCount       int `json:"critical_count"`
	HighCount           int `json:"high_count"`
	MediumCount         int `json:"medium_count"`
	LowCount            int `json:"low_count"`
}

// SecretFinding represents a discovered secret
type SecretFinding struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	Severity string `json:"severity"`
}

// CompleteScanner orchestrates all scanning capabilities
type CompleteScanner struct {
	xssScanner       *xss.Scanner
	assetDiscoverer  *assets.Discoverer
	apiExtractor     *apiextract.Extractor
	deepCrawler      *crawler.DeepCrawler
	contentAcquirer  *content.Acquirer
	platformDetector *platform.Detector
	exploitableScan  *exploitable.Scanner
	owaspScanner     *owasp25.Scanner
	
	browser *rod.Browser
}

// NewCompleteScanner creates a new complete scanner
func NewCompleteScanner() (*CompleteScanner, error) {
	s := &CompleteScanner{}
	
	var err error
	
	// Initialize all scanners
	s.xssScanner, err = xss.NewScanner()
	if err != nil {
		return nil, fmt.Errorf("failed to create XSS scanner: %w", err)
	}
	
	s.assetDiscoverer, err = assets.NewDiscoverer()
	if err != nil {
		return nil, fmt.Errorf("failed to create asset discoverer: %w", err)
	}
	
	s.apiExtractor = apiextract.NewExtractor()
	
	s.deepCrawler, err = crawler.NewDeepCrawler()
	if err != nil {
		return nil, fmt.Errorf("failed to create deep crawler: %w", err)
	}
	
	s.contentAcquirer, err = content.NewAcquirer()
	if err != nil {
		return nil, fmt.Errorf("failed to create content acquirer: %w", err)
	}
	
	s.platformDetector = platform.NewDetector(30)
	s.exploitableScan = exploitable.NewScanner()
	s.owaspScanner = owasp25.NewScanner("")
	
	return s, nil
}

// Scan performs a complete security scan
func (s *CompleteScanner) Scan(target Target) (*CompleteScanResult, error) {
	result := &CompleteScanResult{
		Target: target.URL,
	}
	
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 1. Platform Detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		detection, err := s.platformDetector.Detect(target.URL)
		if err == nil {
			mu.Lock()
			result.Platform = detection
			mu.Unlock()
		}
	}()
	
	// 2. XSS Scanning
	wg.Add(1)
	go func() {
		defer wg.Done()
		findings := s.xssScanner.ScanTarget(target.URL)
		mu.Lock()
		result.XSS = findings
		mu.Unlock()
	}()
	
	// 3. Asset Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		assets, err := s.assetDiscoverer.Discover(target.URL)
		if err == nil {
			mu.Lock()
			result.Assets = assets
			mu.Unlock()
		}
	}()
	
	// 4. API Extraction (requires browser page)
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		// For now, do static extraction
		apis, err := s.apiExtractor.Extract(target.URL, nil)
		if err == nil {
			mu.Lock()
			result.APIs = apis
			mu.Unlock()
		}
	}()
	
	// 5. Exploitable Software Scan
	if len(target.Ports) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings := s.scanExploitable(target)
			mu.Lock()
			result.Exploitable = findings
			mu.Unlock()
		}()
	}
	
	// 6. OWASP Scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		acquired, err := s.contentAcquirer.Acquire(target.URL)
		if err != nil {
			return
		}
		findings := s.owaspScanner.ScanString(acquired.HTML, target.URL)
		mu.Lock()
		result.OWASP = findings
		mu.Unlock()
	}()
	
	wg.Wait()
	
	// Calculate summary
	result.Summary = s.calculateSummary(result)
	
	return result, nil
}

// ScanWithDeepCrawl performs deep crawling before scanning
func (s *CompleteScanner) ScanWithDeepCrawl(ctx context.Context, target Target, maxPages int) (*CompleteScanResult, error) {
	result := &CompleteScanResult{
		Target: target.URL,
	}
	
	// 1. Deep Crawl
	pages, err := s.deepCrawler.Crawl(ctx, target.URL)
	if err != nil {
		return nil, fmt.Errorf("deep crawl failed: %w", err)
	}
	
	// Limit pages
	if len(pages) > maxPages {
		pages = pages[:maxPages]
	}
	result.Pages = pages
	
	// 2. Scan each discovered page
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent scans
	
	for _, page := range pages {
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(p crawler.Page) {
			defer wg.Done()
			defer func() { <-semaphore }()
			
			// XSS scan
			xssFindings := s.xssScanner.ScanTarget(p.URL)
			mu.Lock()
			result.XSS = append(result.XSS, xssFindings...)
			mu.Unlock()
			
			// Asset discovery
			if pageAssets, err := s.assetDiscoverer.Discover(p.URL); err == nil {
				mu.Lock()
				if result.Assets == nil {
					result.Assets = pageAssets
				} else {
					// Merge assets
					for _, asset := range pageAssets.Assets {
						// Deduplicate
						found := false
						for _, existing := range result.Assets.Assets {
							if existing.URL == asset.URL {
								found = true
								break
							}
						}
						if !found {
							result.Assets.Assets = append(result.Assets.Assets, asset)
						}
					}
				}
				mu.Unlock()
			}
			
			// API extraction
			if apis, err := s.apiExtractor.Extract(p.URL, nil); err == nil {
				mu.Lock()
				if result.APIs == nil {
					result.APIs = apis
				} else {
					// Merge APIs
					result.APIs.Endpoints = append(result.APIs.Endpoints, apis.Endpoints...)
					result.APIs.TotalCount += apis.TotalCount
				}
				mu.Unlock()
			}
			
		}(page)
	}
	
	wg.Wait()
	
	// Calculate summary
	result.Summary = s.calculateSummary(result)
	
	return result, nil
}

// scanExploitable scans for exploitable software
func (s *CompleteScanner) scanExploitable(target Target) []UnifiedFinding {
	var findings []UnifiedFinding
	
	results := s.exploitableScan.ScanTarget(target.Host, target.Ports)
	
	for _, f := range results {
		switch finding := f.(type) {
		case *exploitable.RedisFinding:
			findings = append(findings, UnifiedFinding{
				Category:    "exploitable",
				Type:        finding.Type,
				Severity:    finding.Severity,
				CVSS:        finding.CVSS,
				Host:        finding.Host,
				Port:        finding.Port,
				Summary:     finding.Summary,
			})
		case *exploitable.MongoDBFinding:
			findings = append(findings, UnifiedFinding{
				Category:    "exploitable",
				Type:        finding.Type,
				Severity:    finding.Severity,
				CVSS:        finding.CVSS,
				Host:        finding.Host,
				Port:        finding.Port,
				Summary:     finding.Summary,
			})
		case *exploitable.ElasticsearchFinding:
			findings = append(findings, UnifiedFinding{
				Category:    "exploitable",
				Type:        finding.Type,
				Severity:    finding.Severity,
				CVSS:        finding.CVSS,
				Host:        finding.Host,
				Port:        finding.Port,
				Summary:     finding.Summary,
			})
		case *exploitable.JenkinsFinding:
			findings = append(findings, UnifiedFinding{
				Category:    "exploitable",
				Type:        finding.Type,
				Severity:    finding.Severity,
				CVSS:        finding.CVSS,
				Host:        finding.Host,
				Port:        finding.Port,
				Summary:     finding.Summary,
			})
		}
	}
	
	return findings
}

// calculateSummary calculates scan summary
func (s *CompleteScanner) calculateSummary(result *CompleteScanResult) ScanSummary {
	summary := ScanSummary{}
	
	// XSS
	summary.TotalXSS = len(result.XSS)
	for _, f := range result.XSS {
		switch f.Severity {
		case "CRITICAL":
			summary.CriticalCount++
		case "HIGH":
			summary.HighCount++
		case "MEDIUM":
			summary.MediumCount++
		case "LOW":
			summary.LowCount++
		}
	}
	
	// Assets
	if result.Assets != nil {
		summary.TotalAssets = result.Assets.TotalCount
	}
	
	// APIs
	if result.APIs != nil {
		summary.TotalAPIs = result.APIs.TotalCount
	}
	
	// Pages
	summary.TotalPages = len(result.Pages)
	
	// Exploitable
	summary.TotalExploitable = len(result.Exploitable)
	for _, f := range result.Exploitable {
		switch f.Severity {
		case "CRITICAL":
			summary.CriticalCount++
		case "HIGH":
			summary.HighCount++
		case "MEDIUM":
			summary.MediumCount++
		case "LOW":
			summary.LowCount++
		}
	}
	
	// OWASP
	summary.TotalOWASP = len(result.OWASP)
	for _, f := range result.OWASP {
		switch f.Severity {
		case "CRITICAL":
			summary.CriticalCount++
		case "HIGH":
			summary.HighCount++
		case "MEDIUM":
			summary.MediumCount++
		case "LOW":
			summary.LowCount++
		}
	}
	
	return summary
}

// Close cleans up all resources
func (s *CompleteScanner) Close() error {
	if s.xssScanner != nil {
		s.xssScanner.Close()
	}
	if s.assetDiscoverer != nil {
		s.assetDiscoverer.Close()
	}
	if s.deepCrawler != nil {
		s.deepCrawler.Close()
	}
	if s.contentAcquirer != nil {
		s.contentAcquirer.Close()
	}
	return nil
}