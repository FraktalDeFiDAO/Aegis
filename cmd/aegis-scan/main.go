// Aegis Complete Security Scanner
// Runs all scanning modules: XSS, Assets, APIs, Exploitable, OWASP, Platform detection
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/apiextract"
	"github.com/coppertone/bug-hunter/app/aegis/internal/assets"
	"github.com/coppertone/bug-hunter/app/aegis/internal/content"
	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/exploitable"
	"github.com/coppertone/bug-hunter/app/aegis/internal/owasp25"
	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
	"github.com/coppertone/bug-hunter/app/aegis/internal/xss"
)

// ScanConfig holds scan configuration
type ScanConfig struct {
	Target          string
	Host            string
	Ports           []int
	MaxPages        int
	MaxDepth        int
	Workers         int
	Timeout         time.Duration
	OutputDir       string
	ScanXSS         bool
	ScanAssets      bool
	ScanAPIs        bool
	ScanExploitable bool
	ScanOWASP       bool
	ScanPlatform    bool
	DeepCrawl       bool
	Verbose         bool
}

// CompleteReport holds all scan results
type CompleteReport struct {
	ScanInfo      ScanInfo                    `json:"scan_info"`
	Target        TargetInfo                  `json:"target"`
	XSS           []xss.XSSFinding            `json:"xss_findings,omitempty"`
	Assets        *assets.DiscoveryResult     `json:"asset_discovery,omitempty"`
	APIs          *apiextract.ExtractResult   `json:"api_endpoints,omitempty"`
	Pages         []crawler.Page              `json:"discovered_pages,omitempty"`
	Platform      *platform.Detection         `json:"platform_detection,omitempty"`
	EOL           []platform.EOLInfo          `json:"eol_findings,omitempty"`
	Exploitable   []ExploitableFinding        `json:"exploitable_findings,omitempty"`
	OWASP         []owasp25.Finding           `json:"owasp_findings,omitempty"`
	Summary       Summary                     `json:"summary"`
	GeneratedAt   time.Time                   `json:"generated_at"`
}

type ScanInfo struct {
	StartedAt   time.Time     `json:"started_at"`
	Duration    time.Duration `json:"duration"`
	ScannerVersion string     `json:"scanner_version"`
}

type TargetInfo struct {
	URL   string `json:"url"`
	Host  string `json:"host,omitempty"`
	Ports []int  `json:"ports,omitempty"`
}

type ExploitableFinding struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	CVE         string   `json:"cve,omitempty"`
	Host        string   `json:"host,omitempty"`
	Port        int      `json:"port,omitempty"`
	Service     string   `json:"service"`
	Version     string   `json:"version,omitempty"`
	Summary     string   `json:"summary"`
	Remediation string   `json:"remediation,omitempty"`
}

type Summary struct {
	TotalXSS          int            `json:"total_xss"`
	TotalAssets       int            `json:"total_assets"`
	TotalAPIs         int            `json:"total_apis"`
	TotalPages        int            `json:"total_pages"`
	TotalExploitable  int            `json:"total_exploitable"`
	TotalOWASP        int            `json:"total_owasp"`
	TotalEOL          int            `json:"total_eol"`
	SeverityCounts    SeverityCounts `json:"severity_counts"`
}

type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func main() {
	config := parseFlags()
	
	// Print banner
	printBanner()
	
	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\n[!] Interrupted, shutting down...")
		cancel()
		os.Exit(1)
	}()
	
	// Run scan
	startTime := time.Now()
	report := runCompleteScan(ctx, config)
	report.ScanInfo.StartedAt = startTime
	report.ScanInfo.Duration = time.Since(startTime)
	report.ScanInfo.ScannerVersion = "1.0.0"
	report.GeneratedAt = time.Now()
	
	// Output results
	if err := outputResults(report, config); err != nil {
		fmt.Fprintf(os.Stderr, "Error outputting results: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() ScanConfig {
	var config ScanConfig
	
	flag.StringVar(&config.Target, "target", "", "Target URL (required)")
	flag.StringVar(&config.Host, "host", "", "Target host for port scanning (optional)")
	portsStr := flag.String("ports", "", "Ports to scan (comma-separated, e.g., 80,443,8080)")
	flag.IntVar(&config.MaxPages, "max-pages", 50, "Maximum pages to crawl")
	flag.IntVar(&config.MaxDepth, "max-depth", 3, "Maximum crawl depth")
	flag.IntVar(&config.Workers, "workers", 10, "Number of concurrent workers")
	timeout := flag.Int("timeout", 30, "Timeout in seconds")
	flag.StringVar(&config.OutputDir, "output", "./scan-results", "Output directory")
	
	// Scan toggles
	flag.BoolVar(&config.ScanXSS, "xss", true, "Enable XSS scanning")
	flag.BoolVar(&config.ScanAssets, "assets", true, "Enable asset discovery")
	flag.BoolVar(&config.ScanAPIs, "apis", true, "Enable API extraction")
	flag.BoolVar(&config.ScanExploitable, "exploitable", true, "Enable exploitable software scanning")
	flag.BoolVar(&config.ScanOWASP, "owasp", true, "Enable OWASP Top 25 scanning")
	flag.BoolVar(&config.ScanPlatform, "platform", true, "Enable platform detection")
	flag.BoolVar(&config.DeepCrawl, "deep-crawl", true, "Enable deep crawling")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	
	flag.Parse()
	
	// Validation
	if config.Target == "" {
		fmt.Fprintln(os.Stderr, "Error: -target is required")
		flag.Usage()
		os.Exit(1)
	}
	
	// Parse ports
	if *portsStr != "" {
		for _, p := range strings.Split(*portsStr, ",") {
			var port int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &port); err == nil {
				config.Ports = append(config.Ports, port)
			}
		}
	} else {
		// Default ports
		config.Ports = []int{80, 443, 6379, 27017, 9200, 9300, 8080, 8443}
	}
	
	// Set host from target if not provided
	if config.Host == "" {
		config.Host = strings.TrimPrefix(config.Target, "https://")
		config.Host = strings.TrimPrefix(config.Host, "http://")
		config.Host = strings.Split(config.Host, "/")[0]
		config.Host = strings.Split(config.Host, ":")[0]
	}
	
	config.Timeout = time.Duration(*timeout) * time.Second
	
	return config
}

func printBanner() {
	fmt.Println(`
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     ÆGIS - COMPLETE SECURITY SCANNER                      ║
    ║     XSS • Assets • APIs • Exploitable • OWASP • EOL       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
`)
}

func runCompleteScan(ctx context.Context, config ScanConfig) CompleteReport {
	report := CompleteReport{
		Target: TargetInfo{
			URL:   config.Target,
			Host:  config.Host,
			Ports: config.Ports,
		},
	}
	
	// Create output directory
	os.MkdirAll(config.OutputDir, 0755)
	
	fmt.Printf("[*] Target: %s\n", config.Target)
	fmt.Printf("[*] Host: %s\n", config.Host)
	fmt.Printf("[*] Ports: %v\n", config.Ports)
	fmt.Printf("[*] Output: %s\n\n", config.OutputDir)
	
	// 1. Content Acquisition & Platform Detection
	fmt.Println("[1/8] Platform Detection & Content Acquisition...")
	if config.ScanPlatform {
		detector := platform.NewDetector(config.Timeout)
		detection, err := detector.Detect(config.Target)
		if err == nil {
			report.Platform = detection
			report.EOL = detection.EOLInfo
			fmt.Printf("    [+] Detected %d frameworks\n", len(detection.Frameworks))
			if len(detection.EOLInfo) > 0 {
				fmt.Printf("    [!] Found %d EOL frameworks\n", len(detection.EOLInfo))
			}
		}
	}
	
	// 2. Deep Crawling
	if config.DeepCrawl {
		fmt.Println("[2/8] Deep Crawling...")
		crawlerInstance, err := crawler.NewDeepCrawler(
			crawler.WithMaxDepth(config.MaxDepth),
			crawler.WithWorkers(config.Workers),
		)
		if err == nil {
			defer crawlerInstance.Close()
			pages, _ := crawlerInstance.Crawl(ctx, config.Target)
			if len(pages) > config.MaxPages {
				pages = pages[:config.MaxPages]
			}
			report.Pages = pages
			fmt.Printf("    [+] Discovered %d pages\n", len(pages))
		}
	}
	
	// 3. XSS Scanning
	if config.ScanXSS {
		fmt.Println("[3/8] XSS Scanning...")
		xssScanner, err := xss.NewScanner(xss.WithTimeout(config.Timeout))
		if err == nil {
			defer xssScanner.Close()
			
			// Scan main target
			findings := xssScanner.ScanTarget(config.Target)
			report.XSS = findings
			
			// Scan discovered pages
			for i, page := range report.Pages {
				if i >= 10 { // Limit XSS scans to first 10 pages
					break
				}
				pageFindings := xssScanner.ScanTarget(page.URL)
				report.XSS = append(report.XSS, pageFindings...)
			}
			
			fmt.Printf("    [+] Found %d XSS vulnerabilities\n", len(report.XSS))
		}
	}
	
	// 4. Asset Discovery
	if config.ScanAssets {
		fmt.Println("[4/8] Asset Discovery...")
		discoverer, err := assets.NewDiscoverer(assets.WithTimeout(config.Timeout))
		if err == nil {
			defer discoverer.Close()
			result, _ := discoverer.Discover(config.Target)
			report.Assets = result
			if result != nil {
				fmt.Printf("    [+] Found %d assets\n", result.TotalCount)
				for assetType, count := range result.ByType {
					fmt.Printf("        - %s: %d\n", assetType, count)
				}
			}
		}
	}
	
	// 5. API Extraction
	if config.ScanAPIs {
		fmt.Println("[5/8] API Endpoint Extraction...")
		extractor := apiextract.NewExtractor()
		
		// Extract from main target
		result, _ := extractor.Extract(config.Target, nil)
		report.APIs = result
		
		// Extract from discovered pages
		for _, page := range report.Pages {
			if page.ContentType == "" || strings.Contains(page.ContentType, "html") {
				pageAPIs, _ := extractor.Extract(page.URL, nil)
				if pageAPIs != nil && report.APIs != nil {
					report.APIs.Endpoints = append(report.APIs.Endpoints, pageAPIs.Endpoints...)
					report.APIs.TotalCount += pageAPIs.TotalCount
				}
			}
		}
		
		if report.APIs != nil {
			fmt.Printf("    [+] Found %d API endpoints\n", report.APIs.TotalCount)
			fmt.Printf("        - REST: %d\n", len(report.APIs.REST))
			fmt.Printf("        - GraphQL: %d\n", len(report.APIs.GraphQL))
			fmt.Printf("        - WebSocket: %d\n", len(report.APIs.WebSocket))
		}
	}
	
	// 6. Exploitable Software Scanning
	if config.ScanExploitable {
		fmt.Println("[6/8] Exploitable Software Scanning...")
		scanner := exploitable.NewScanner(
			exploitable.WithTimeout(config.Timeout),
			exploitable.WithWorkers(config.Workers),
		)
		
		findings := scanner.ScanTarget(config.Host, config.Ports)
		
		for _, f := range findings {
			switch finding := f.(type) {
			case *exploitable.RedisFinding:
				report.Exploitable = append(report.Exploitable, ExploitableFinding{
					Type:     finding.Type,
					Severity: finding.Severity,
					CVSS:     finding.CVSS,
					CVE:      finding.CVE,
					Host:     finding.Host,
					Port:     finding.Port,
					Service:  "Redis",
					Version:  finding.Version,
					Summary:  finding.Summary,
				})
			case *exploitable.MongoDBFinding:
				report.Exploitable = append(report.Exploitable, ExploitableFinding{
					Type:     finding.Type,
					Severity: finding.Severity,
					CVSS:     finding.CVSS,
					CVE:      finding.CVE,
					Host:     finding.Host,
					Port:     finding.Port,
					Service:  "MongoDB",
					Version:  finding.Version,
					Summary:  finding.Summary,
				})
			case *exploitable.ElasticsearchFinding:
				report.Exploitable = append(report.Exploitable, ExploitableFinding{
					Type:     finding.Type,
					Severity: finding.Severity,
					CVSS:     finding.CVSS,
					CVE:      finding.CVE,
					Host:     finding.Host,
					Port:     finding.Port,
					Service:  "Elasticsearch",
					Version:  finding.Version,
					Summary:  finding.Summary,
				})
			case *exploitable.JenkinsFinding:
				report.Exploitable = append(report.Exploitable, ExploitableFinding{
					Type:     finding.Type,
					Severity: finding.Severity,
					CVSS:     finding.CVSS,
					CVE:      finding.CVE,
					Host:     finding.Host,
					Port:     finding.Port,
					Service:  "Jenkins",
					Version:  finding.Version,
					Summary:  finding.Summary,
				})
			}
		}
		
		fmt.Printf("    [+] Found %d exploitable services\n", len(report.Exploitable))
	}
	
	// 7. OWASP Top 25 Scanning
	if config.ScanOWASP {
		fmt.Println("[7/8] OWASP Top 25 Scanning...")
		
		// Get content
		acquirer, _ := content.NewAcquirer(content.WithTimeout(config.Timeout))
		if acquirer != nil {
			defer acquirer.Close()
			acquired, _ := acquirer.Acquire(config.Target)
			
			if acquired != nil {
				scanner := owasp25.NewScanner("")
				findings := scanner.ScanString(acquired.HTML, config.Target)
				report.OWASP = findings
				
				// Scan discovered pages
				for _, page := range report.Pages {
					if page.ContentType == "" || strings.Contains(page.ContentType, "html") {
						content, _ := acquirer.Acquire(page.URL)
						if content != nil {
							pageFindings := scanner.ScanString(content.HTML, page.URL)
							report.OWASP = append(report.OWASP, pageFindings...)
						}
					}
				}
				
				fmt.Printf("    [+] Found %d OWASP violations\n", len(report.OWASP))
			}
		}
	}
	
	// 8. Calculate Summary
	fmt.Println("[8/8] Generating Summary...")
	report.Summary = calculateSummary(report)
	
	printSummary(report.Summary)
	
	return report
}

func calculateSummary(report CompleteReport) Summary {
	summary := Summary{}
	
	// Count XSS
	summary.TotalXSS = len(report.XSS)
	for _, f := range report.XSS {
		switch f.Severity {
		case "CRITICAL":
			summary.SeverityCounts.Critical++
		case "HIGH":
			summary.SeverityCounts.High++
		case "MEDIUM":
			summary.SeverityCounts.Medium++
		case "LOW":
			summary.SeverityCounts.Low++
		default:
			summary.SeverityCounts.Info++
		}
	}
	
	// Count Assets
	if report.Assets != nil {
		summary.TotalAssets = report.Assets.TotalCount
	}
	
	// Count APIs
	if report.APIs != nil {
		summary.TotalAPIs = report.APIs.TotalCount
	}
	
	// Count Pages
	summary.TotalPages = len(report.Pages)
	
	// Count Exploitable
	summary.TotalExploitable = len(report.Exploitable)
	for _, f := range report.Exploitable {
		switch f.Severity {
		case "CRITICAL":
			summary.SeverityCounts.Critical++
		case "HIGH":
			summary.SeverityCounts.High++
		case "MEDIUM":
			summary.SeverityCounts.Medium++
		case "LOW":
			summary.SeverityCounts.Low++
		default:
			summary.SeverityCounts.Info++
		}
	}
	
	// Count OWASP
	summary.TotalOWASP = len(report.OWASP)
	for _, f := range report.OWASP {
		switch f.Severity {
		case "CRITICAL":
			summary.SeverityCounts.Critical++
		case "HIGH":
			summary.SeverityCounts.High++
		case "MEDIUM":
			summary.SeverityCounts.Medium++
		case "LOW":
			summary.SeverityCounts.Low++
		default:
			summary.SeverityCounts.Info++
		}
	}
	
	// Count EOL
	summary.TotalEOL = len(report.EOL)
	
	return summary
}

func printSummary(summary Summary) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("XSS Vulnerabilities:       %d\n", summary.TotalXSS)
	fmt.Printf("Assets Discovered:         %d\n", summary.TotalAssets)
	fmt.Printf("API Endpoints:             %d\n", summary.TotalAPIs)
	fmt.Printf("Pages Crawled:             %d\n", summary.TotalPages)
	fmt.Printf("Exploitable Services:      %d\n", summary.TotalExploitable)
	fmt.Printf("OWASP Violations:          %d\n", summary.TotalOWASP)
	fmt.Printf("EOL Frameworks:            %d\n", summary.TotalEOL)
	fmt.Println(strings.Repeat("-", 60))
	fmt.Println("SEVERITY BREAKDOWN")
	fmt.Printf("  Critical: %d\n", summary.SeverityCounts.Critical)
	fmt.Printf("  High:     %d\n", summary.SeverityCounts.High)
	fmt.Printf("  Medium:   %d\n", summary.SeverityCounts.Medium)
	fmt.Printf("  Low:      %d\n", summary.SeverityCounts.Low)
	fmt.Printf("  Info:     %d\n", summary.SeverityCounts.Info)
	fmt.Println(strings.Repeat("=", 60))
}

func outputResults(report CompleteReport, config ScanConfig) error {
	// Create output directory if it doesn't exist
	if _, err := os.Stat(config.OutputDir); os.IsNotExist(err) {
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}
	
	// Generate filename
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("aegis-scan-%s-%s", strings.Replace(config.Host, ".", "-", -1), timestamp)
	
	// JSON output
	jsonPath := fmt.Sprintf("%s/%s.json", config.OutputDir, filename)
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return err
	}
	fmt.Printf("\n[+] JSON Report: %s\n", jsonPath)
	
	// HTML Report
	htmlPath := fmt.Sprintf("%s/%s.html", config.OutputDir, filename)
	htmlReport := generateHTMLReport(report)
	if err := os.WriteFile(htmlPath, []byte(htmlReport), 0644); err != nil {
		return err
	}
	fmt.Printf("[+] HTML Report: %s\n", htmlPath)
	
	// Markdown Summary
	mdPath := fmt.Sprintf("%s/%s.md", config.OutputDir, filename)
	mdReport := generateMarkdownReport(report)
	if err := os.WriteFile(mdPath, []byte(mdReport), 0644); err != nil {
		return err
	}
	fmt.Printf("[+] Markdown Report: %s\n", mdPath)
	
	return nil
}

func generateHTMLReport(report CompleteReport) string {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Aegis Scan Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; }
        .stat-value { font-size: 24px; font-weight: bold; color: #4CAF50; }
        .stat-label { color: #666; }
        .severity-critical { color: #d32f2f; }
        .severity-high { color: #f57c00; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #388e3c; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        tr:hover { background: #f5f5f5; }
        .finding { margin: 10px 0; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Aegis Security Scan Report</h1>
        
        <div class="summary">
            <h2>Target Information</h2>
            <p><strong>URL:</strong> %s</p>
            <p><strong>Host:</strong> %s</p>
            <p><strong>Scan Date:</strong> %s</p>
            <p><strong>Duration:</strong> %s</p>
        </div>
        
        <h2>📊 Summary Statistics</h2>
        <div class="summary">
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">XSS Findings</div>
            </div>
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">Assets</div>
            </div>
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">API Endpoints</div>
            </div>
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">Pages</div>
            </div>
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">Exploitable</div>
            </div>
            <div class="stat">
                <div class="stat-value">%d</div>
                <div class="stat-label">OWASP Issues</div>
            </div>
        </div>
        
        <h2>🎯 Severity Breakdown</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td class="severity-critical">Critical</td>
                <td>%d</td>
            </tr>
            <tr>
                <td class="severity-high">High</td>
                <td>%d</td>
            </tr>
            <tr>
                <td class="severity-medium">Medium</td>
                <td>%d</td>
            </tr>
            <tr>
                <td class="severity-low">Low</td>
                <td>%d</td>
            </tr>
        </table>
        
        <div class="footer">
            Generated by Aegis Security Scanner v%s
        </div>
    </div>
</body>
</html>`,
		report.Target.URL,
		report.Target.URL,
		report.Target.Host,
		report.ScanInfo.StartedAt.Format("2006-01-02 15:04:05"),
		report.ScanInfo.Duration,
		report.Summary.TotalXSS,
		report.Summary.TotalAssets,
		report.Summary.TotalAPIs,
		report.Summary.TotalPages,
		report.Summary.TotalExploitable,
		report.Summary.TotalOWASP,
		report.Summary.SeverityCounts.Critical,
		report.Summary.SeverityCounts.High,
		report.Summary.SeverityCounts.Medium,
		report.Summary.SeverityCounts.Low,
		report.ScanInfo.ScannerVersion,
	)
	
	return html
}

func generateMarkdownReport(report CompleteReport) string {
	md := fmt.Sprintf(`# Aegis Security Scan Report

## Target Information

- **URL:** %s
- **Host:** %s
- **Scan Date:** %s
- **Duration:** %s

## Summary Statistics

| Metric | Count |
|--------|-------|
| XSS Vulnerabilities | %d |
| Assets Discovered | %d |
| API Endpoints | %d |
| Pages Crawled | %d |
| Exploitable Services | %d |
| OWASP Violations | %d |
| EOL Frameworks | %d |

## Severity Breakdown

- **Critical:** %d
- **High:** %d
- **Medium:** %d
- **Low:** %d
- **Info:** %d

## Platform Detection

`,
		report.Target.URL,
		report.Target.Host,
		report.ScanInfo.StartedAt.Format("2006-01-02 15:04:05"),
		report.ScanInfo.Duration,
		report.Summary.TotalXSS,
		report.Summary.TotalAssets,
		report.Summary.TotalAPIs,
		report.Summary.TotalPages,
		report.Summary.TotalExploitable,
		report.Summary.TotalOWASP,
		report.Summary.TotalEOL,
		report.Summary.SeverityCounts.Critical,
		report.Summary.SeverityCounts.High,
		report.Summary.SeverityCounts.Medium,
		report.Summary.SeverityCounts.Low,
		report.Summary.SeverityCounts.Info,
	)
	
	if report.Platform != nil {
		md += "### Detected Frameworks\n\n"
		for _, fw := range report.Platform.Frameworks {
			md += fmt.Sprintf("- **%s** (confidence: %d%%)\n", fw.Name, fw.Confidence)
			if fw.Version != "" {
				md += fmt.Sprintf("  - Version: %s\n", fw.Version)
			}
		}
		md += "\n"
	}
	
	if len(report.EOL) > 0 {
		md += "### End-of-Life Frameworks\n\n"
		for _, eol := range report.EOL {
			if eol.IsEOL {
				md += fmt.Sprintf("- ⚠️ **%s %s** - EOL since %s\n", 
					eol.Framework, eol.Version, eol.EOLDate.Format("2006-01-02"))
			}
		}
		md += "\n"
	}
	
	if len(report.Exploitable) > 0 {
		md += "## Exploitable Services\n\n"
		for _, ex := range report.Exploitable {
			md += fmt.Sprintf("### [%s] %s\n\n", ex.Severity, ex.Type)
			md += fmt.Sprintf("- **Service:** %s\n", ex.Service)
			md += fmt.Sprintf("- **Host:** %s:%d\n", ex.Host, ex.Port)
			if ex.Version != "" {
				md += fmt.Sprintf("- **Version:** %s\n", ex.Version)
			}
			if ex.CVE != "" {
				md += fmt.Sprintf("- **CVE:** %s\n", ex.CVE)
			}
			md += fmt.Sprintf("- **CVSS:** %.1f\n", ex.CVSS)
			md += fmt.Sprintf("- **Summary:** %s\n\n", ex.Summary)
		}
	}
	
	md += "\n---\n\n"
	md += fmt.Sprintf("*Report generated by Aegis Security Scanner v%s*\n", report.ScanInfo.ScannerVersion)
	
	return md
}