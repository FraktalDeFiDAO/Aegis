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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/apiextract"
	"github.com/coppertone/bug-hunter/app/aegis/internal/assets"
	"github.com/coppertone/bug-hunter/app/aegis/internal/ato"
	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/coppertone/bug-hunter/app/aegis/internal/content"
	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/exploitable"
	"github.com/coppertone/bug-hunter/app/aegis/internal/owasp25"
	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
	"github.com/coppertone/bug-hunter/app/aegis/internal/waf"
	"github.com/coppertone/bug-hunter/app/aegis/internal/workflow"
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
	// WAF Bypass options
	WAFBypass       bool
	WAFType         string
	ElementFocus    string
	EncodingLevel   int
	ATOCheck        bool
	CWEAll          bool
	// Workflow options
	WorkflowFile    string
	WorkflowVars    map[string]string
	// Browser automation script options
	ScriptFile      string
	ScriptHeadless  bool
}

// CompleteReport holds all scan results
type CompleteReport struct {
	ScanInfo      ScanInfo                    `json:"scan_info"`
	Target        TargetInfo                  `json:"target"`
	XSS           []xss.XSSFinding            `json:"xss_findings,omitempty"`
	DOMXSS        *xss.DOMXSSReport           `json:"dom_xss_findings,omitempty"`
	EnhancedXSS   *xss.ScanResult             `json:"enhanced_xss_findings,omitempty"`
	WAFDetection  *waf.DetectionResult        `json:"waf_detection,omitempty"`
	ATOFindings   []ato.ATOFinding            `json:"ato_findings,omitempty"`
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
	TotalXSS           int            `json:"total_xss"`
	TotalDOMXSS        int            `json:"total_dom_xss"`
	TotalEnhancedXSS   int            `json:"total_enhanced_xss"`
	TotalATO           int            `json:"total_ato"`
	TotalAssets        int            `json:"total_assets"`
	TotalAPIs          int            `json:"total_apis"`
	TotalPages         int            `json:"total_pages"`
	TotalExploitable   int            `json:"total_exploitable"`
	TotalOWASP         int            `json:"total_owasp"`
	TotalEOL           int            `json:"total_eol"`
	WAFDetected        string         `json:"waf_detected,omitempty"`
	WAFBypassed        bool           `json:"waf_bypassed,omitempty"`
	SeverityCounts     SeverityCounts `json:"severity_counts"`
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

	// Check for workflow mode
	if config.WorkflowFile != "" {
		runWorkflow(ctx, config)
		return
	}

	// Check for browser automation script mode
	if config.ScriptFile != "" {
		runBrowserScript(ctx, config)
		return
	}

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

// runWorkflow executes a workflow file
func runWorkflow(ctx context.Context, config ScanConfig) {
	fmt.Printf("[*] Loading workflow: %s\n", config.WorkflowFile)

	// Load workflow
	wf, err := workflow.LoadWorkflow(config.WorkflowFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading workflow: %v\n", err)
		os.Exit(1)
	}

	// Validate workflow
	if err := wf.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Workflow validation error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Workflow: %s\n", wf.Name)
	if wf.Description != "" {
		fmt.Printf("[*] Description: %s\n", wf.Description)
	}
	fmt.Printf("[*] Steps: %d\n\n", len(wf.Steps))

	// Prepare variables
	vars := make(map[string]string)
	if config.Target != "" {
		vars["target"] = config.Target
	}
	if config.OutputDir != "" {
		vars["output_dir"] = config.OutputDir
	}
	// Merge command-line variables
	for k, v := range config.WorkflowVars {
		vars[k] = v
	}

	// Create runner
	runner := workflow.NewRunner(wf,
		workflow.WithVerbose(config.Verbose),
		workflow.WithVariables(vars),
	)

	// Run workflow
	result, err := runner.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Workflow execution error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("WORKFLOW RESULTS: %s\n", result.Status)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Steps: %d total\n", len(result.Steps))

	// Count step statuses
	success, failed, skipped := 0, 0, 0
	for _, step := range result.Steps {
		switch step.Status {
		case "success":
			success++
		case "failure":
			failed++
			fmt.Printf("  [FAILED] %s: %s\n", step.StepID, step.Error)
		case "skipped":
			skipped++
		}
	}
	fmt.Printf("  Success: %d, Failed: %d, Skipped: %d\n", success, failed, skipped)

	// Collect findings
	findings := result.GetFindings()
	if len(findings) > 0 {
		fmt.Printf("\nFindings: %d total\n", len(findings))
	}

	// Save results if output directory specified
	if config.OutputDir != "" {
		os.MkdirAll(config.OutputDir, 0755)
		resultPath := filepath.Join(config.OutputDir, "workflow-result.json")
		if err := runner.SaveResult(result, resultPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save result: %v\n", err)
		} else {
			fmt.Printf("\n[+] Results saved to: %s\n", resultPath)
		}
	}

	fmt.Println(strings.Repeat("=", 60))

	if result.Status == "failure" {
		os.Exit(1)
	}
}

// runBrowserScript executes a browser automation script
func runBrowserScript(ctx context.Context, config ScanConfig) {
	fmt.Printf("[*] Loading browser automation script: %s\n", config.ScriptFile)

	// Load script
	script, err := browser.LoadScript(config.ScriptFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading script: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Script: %s\n", script.Name)
	if script.Description != "" {
		fmt.Printf("[*] Description: %s\n", script.Description)
	}
	fmt.Printf("[*] Actions: %d\n\n", len(script.Actions))

	// Prepare variables from command line
	for k, v := range config.WorkflowVars {
		script.Variables[k] = v
	}
	// Add target if specified
	if config.Target != "" {
		script.Variables["target"] = config.Target
	}

	// Create automator
	automator := browser.NewAutomator(
		browser.WithHeadless(config.ScriptHeadless),
		browser.WithAutomatorVerbose(config.Verbose),
		browser.WithAutomatorTimeout(config.Timeout),
	)
	if config.OutputDir != "" {
		browser.WithScreenshotsDir(filepath.Join(config.OutputDir, "screenshots"))(automator)
	}

	// Run script
	result, err := automator.Run(ctx, script)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Script execution error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("SCRIPT RESULTS: %s\n", result.Status)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Duration: %s\n", result.Duration)
	fmt.Printf("Actions: %d executed\n", len(result.Actions))

	// Count action statuses
	success, failed, skipped := 0, 0, 0
	for _, action := range result.Actions {
		switch action.Status {
		case "success":
			success++
		case "failure":
			failed++
			name := action.ActionName
			if name == "" {
				name = string(action.ActionType)
			}
			fmt.Printf("  [FAILED] %s: %s\n", name, action.Error)
		case "skipped":
			skipped++
		}
	}
	fmt.Printf("  Success: %d, Failed: %d, Skipped: %d\n", success, failed, skipped)

	// Report extracted data
	if len(result.Extracted) > 0 {
		fmt.Println("\nExtracted Data:")
		for k, v := range result.Extracted {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}

	// Report screenshots
	if len(result.Screenshots) > 0 {
		fmt.Printf("\nScreenshots (%d):\n", len(result.Screenshots))
		for _, s := range result.Screenshots {
			fmt.Printf("  - %s\n", s)
		}
	}

	// Save results if output directory specified
	if config.OutputDir != "" {
		os.MkdirAll(config.OutputDir, 0755)
		resultPath := filepath.Join(config.OutputDir, "script-result.json")
		if err := browser.SaveScriptResult(result, resultPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save result: %v\n", err)
		} else {
			fmt.Printf("\n[+] Results saved to: %s\n", resultPath)
		}
	}

	fmt.Println(strings.Repeat("=", 60))

	if result.Status == "failure" {
		os.Exit(1)
	}
}

func parseFlags() ScanConfig {
	var config ScanConfig
	config.WorkflowVars = make(map[string]string)

	flag.StringVar(&config.Target, "target", "", "Target URL (required unless using workflow)")
	flag.StringVar(&config.Host, "host", "", "Target host for port scanning (optional)")
	portsStr := flag.String("ports", "", "Ports to scan (comma-separated, e.g., 80,443,8080)")
	flag.IntVar(&config.MaxPages, "max-pages", 50, "Maximum pages to crawl")
	flag.IntVar(&config.MaxDepth, "max-depth", 3, "Maximum crawl depth")
	flag.IntVar(&config.Workers, "workers", 10, "Number of concurrent workers")
	timeout := flag.Int("timeout", 30, "Timeout in seconds")
	flag.StringVar(&config.OutputDir, "output", "./scan-output", "Output directory")

	// Scan toggles
	flag.BoolVar(&config.ScanXSS, "xss", true, "Enable XSS scanning")
	flag.BoolVar(&config.ScanAssets, "assets", true, "Enable asset discovery")
	flag.BoolVar(&config.ScanAPIs, "apis", true, "Enable API extraction")
	flag.BoolVar(&config.ScanExploitable, "exploitable", true, "Enable exploitable software scanning")
	flag.BoolVar(&config.ScanOWASP, "owasp", true, "Enable OWASP Top 25 scanning")
	flag.BoolVar(&config.ScanPlatform, "platform", true, "Enable platform detection")
	flag.BoolVar(&config.DeepCrawl, "deep-crawl", true, "Enable deep crawling")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")

	// WAF Bypass options
	flag.BoolVar(&config.WAFBypass, "waf-bypass", false, "Enable WAF bypass mode with adaptive payloads")
	flag.StringVar(&config.WAFType, "waf-type", "", "Force specific WAF type (cloudflare, akamai, imperva, modsecurity, aws-waf, sucuri)")
	flag.StringVar(&config.ElementFocus, "element-focus", "", "Focus on specific elements (script,img,div,span)")
	flag.IntVar(&config.EncodingLevel, "encoding-level", 3, "Encoding aggressiveness (1-5, higher=more aggressive)")
	flag.BoolVar(&config.ATOCheck, "ato-check", false, "Include Account Takeover detection")
	flag.BoolVar(&config.CWEAll, "cwe-all", false, "Check all 25 CWEs")

	// Workflow options
	flag.StringVar(&config.WorkflowFile, "workflow", "", "Run a workflow file (YAML or JSON)")
	workflowVarsStr := flag.String("var", "", "Workflow variables (key=value,key2=value2)")

	// Browser automation script options
	flag.StringVar(&config.ScriptFile, "script", "", "Run a browser automation script (YAML or JSON)")
	flag.BoolVar(&config.ScriptHeadless, "headless", true, "Run browser in headless mode (default: true)")

	flag.Parse()

	// Parse workflow variables
	if *workflowVarsStr != "" {
		for _, kv := range strings.Split(*workflowVarsStr, ",") {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				config.WorkflowVars[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Validation - target required unless workflow or script mode
	if config.Target == "" && config.WorkflowFile == "" && config.ScriptFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -target is required (or use -workflow/-script for automation mode)")
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
	fmt.Print(`
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
	
	// 3a. DOM XSS Scanning (The Kitchen Sink)
	if config.ScanXSS {
		fmt.Println("[3a/8] DOM XSS Analysis (Kitchen Sink)...")
		domAnalyzer, err := xss.NewDOMXSSAnalyzer()
		if err == nil {
			// Get content for main target
			acquirer, _ := content.NewAcquirer(content.WithTimeout(config.Timeout))
			if acquirer != nil {
				defer acquirer.Close()
				acquired, _ := acquirer.Acquire(config.Target)
				if acquired != nil {
					findings := domAnalyzer.AnalyzeContent(acquired.HTML, config.Target)
					report.DOMXSS = &xss.DOMXSSReport{
						ScanDir:  config.Target,
						Findings: findings,
					}
					
					// Also scan other discovered pages
					for i, page := range report.Pages {
						if i >= 5 { break } // Limit to first 5 additional pages
						pContent, _ := acquirer.Acquire(page.URL)
						if pContent != nil {
							pFindings := domAnalyzer.AnalyzeContent(pContent.HTML, page.URL)
							report.DOMXSS.Findings = append(report.DOMXSS.Findings, pFindings...)
						}
					}
					
					// Calculate totals for reporting
					for _, f := range report.DOMXSS.Findings {
						if f.PatternType == "sink" {
							switch f.Severity {
							case "CRITICAL": report.DOMXSS.CriticalFindings++
							case "HIGH": report.DOMXSS.HighFindings++
							case "MEDIUM": report.DOMXSS.MediumFindings++
							}
						}
					}
					
					fmt.Printf("    [+] Found %d potential DOM XSS patterns\n", len(report.DOMXSS.Findings))
					fmt.Printf("        - Critical: %d, High: %d\n", report.DOMXSS.CriticalFindings, report.DOMXSS.HighFindings)
				}
			}
		}
	}

	// 3b. Enhanced XSS Scanning with WAF Bypass
	if config.ScanXSS && config.WAFBypass {
		fmt.Println("[3b/8] Enhanced XSS Scanning with WAF Bypass...")

		// Parse WAF type if specified
		var wafType waf.WAFType = waf.WAFUnknown
		if config.WAFType != "" {
			wafType = parseWAFType(config.WAFType)
		}

		// Parse element focus
		var elements []waf.ElementType
		if config.ElementFocus != "" {
			for _, e := range strings.Split(config.ElementFocus, ",") {
				elements = append(elements, waf.ElementType(strings.TrimSpace(e)))
			}
		}

		// Create enhanced scanner
		scannerOpts := []xss.EnhancedScannerOption{
			xss.WithEnhancedTimeout(config.Timeout),
			xss.WithWAFBypass(true),
			xss.WithEncodingLevel(waf.EncodingLevel(config.EncodingLevel)),
			xss.WithVerbose(config.Verbose),
		}
		if wafType != waf.WAFUnknown {
			scannerOpts = append(scannerOpts, xss.WithWAFType(wafType))
		}
		if len(elements) > 0 {
			scannerOpts = append(scannerOpts, xss.WithElements(elements...))
		}

		enhancedScanner, err := xss.NewEnhancedScanner(scannerOpts...)
		if err == nil {
			defer enhancedScanner.Close()
			scanResult, err := enhancedScanner.ScanWithBypassContext(ctx, config.Target)
			if err == nil {
				report.EnhancedXSS = scanResult
				report.WAFDetection = scanResult.WAFDetection
				fmt.Printf("    [+] Tested %d payloads\n", scanResult.TestedPayloads)
				fmt.Printf("    [+] Found %d XSS vulnerabilities with WAF bypass\n", len(scanResult.Findings))
				if scanResult.WAFDetection != nil {
					fmt.Printf("    [!] WAF Detected: %s (confidence: %d%%)\n",
						scanResult.WAFDetection.WAFType.String(), scanResult.WAFDetection.Confidence)
				}
			}
		}
	}

	// 3c. Account Takeover (ATO) Detection
	if config.ATOCheck {
		fmt.Println("[3c/8] Account Takeover Detection...")
		atoDetector := ato.NewDetector(ato.WithTimeout(config.Timeout))
		atoFindings := atoDetector.DetectAllWithContext(ctx, config.Target)
		report.ATOFindings = atoFindings
		if len(atoFindings) > 0 {
			fmt.Printf("    [!] Found %d ATO vulnerabilities\n", len(atoFindings))
			for _, f := range atoFindings {
				fmt.Printf("        - [%s] %s: %s\n", f.Severity, f.Type, f.Description)
			}
		} else {
			fmt.Println("    [+] No ATO vulnerabilities detected")
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
	
	// Count XSS (Reflected)
	summary.TotalXSS = len(report.XSS)
	for _, f := range report.XSS {
		switch f.Severity {
		case "CRITICAL": summary.SeverityCounts.Critical++
		case "HIGH":     summary.SeverityCounts.High++
		case "MEDIUM":   summary.SeverityCounts.Medium++
		case "LOW":      summary.SeverityCounts.Low++
		default:         summary.SeverityCounts.Info++
		}
	}
	
	// Count DOM XSS
	if report.DOMXSS != nil {
		summary.TotalDOMXSS = len(report.DOMXSS.Findings)
		summary.SeverityCounts.Critical += report.DOMXSS.CriticalFindings
		summary.SeverityCounts.High += report.DOMXSS.HighFindings
		summary.SeverityCounts.Medium += report.DOMXSS.MediumFindings
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

	// Count Enhanced XSS
	if report.EnhancedXSS != nil {
		summary.TotalEnhancedXSS = len(report.EnhancedXSS.Findings)
		for _, f := range report.EnhancedXSS.Findings {
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
		// Track WAF bypass success
		for _, f := range report.EnhancedXSS.Findings {
			if f.WAFBypassed {
				summary.WAFBypassed = true
				break
			}
		}
	}

	// Count ATO
	summary.TotalATO = len(report.ATOFindings)
	for _, f := range report.ATOFindings {
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

	// Record WAF detection
	if report.WAFDetection != nil && report.WAFDetection.WAFType != waf.WAFUnknown {
		summary.WAFDetected = report.WAFDetection.WAFType.String()
	}

	return summary
}

// parseWAFType converts a string to WAFType
func parseWAFType(s string) waf.WAFType {
	switch strings.ToLower(s) {
	case "cloudflare":
		return waf.WAFCloudflare
	case "akamai":
		return waf.WAFAkamai
	case "kona", "akamai-kona":
		return waf.WAFKona
	case "imperva":
		return waf.WAFImperva
	case "incapsula":
		return waf.WAFIncapsula
	case "modsecurity":
		return waf.WAFModSecurity
	case "aws-waf", "aws", "awswaf":
		return waf.WAFAFW
	case "sucuri":
		return waf.WAFSuccuri
	case "barracuda":
		return waf.WAFBarracuda
	case "citrix", "citrix-adc", "netscaler":
		return waf.WAFCitrix
	case "nginx", "naxsi", "nginx-naxsi":
		return waf.WAFNginx
	case "stackpath":
		return waf.WAFStackPath
	case "f5", "big-ip", "bigip", "asm":
		return waf.WAFBIG_IP_ASM
	case "fortiweb":
		return waf.WAFFortiWeb
	case "radware":
		return waf.WAFRadware
	case "wordfence":
		return waf.WAFWordfence
	default:
		return waf.WAFUnknown
	}
}

func printSummary(summary Summary) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Reflected XSS Findings:    %d\n", summary.TotalXSS)
	fmt.Printf("DOM XSS Patterns:          %d\n", summary.TotalDOMXSS)
	if summary.TotalEnhancedXSS > 0 {
		fmt.Printf("Enhanced XSS (WAF Bypass): %d\n", summary.TotalEnhancedXSS)
	}
	if summary.TotalATO > 0 {
		fmt.Printf("ATO Vulnerabilities:       %d\n", summary.TotalATO)
	}
	fmt.Printf("Assets Discovered:         %d\n", summary.TotalAssets)
	fmt.Printf("API Endpoints:             %d\n", summary.TotalAPIs)
	fmt.Printf("Pages Crawled:             %d\n", summary.TotalPages)
	fmt.Printf("Exploitable Services:      %d\n", summary.TotalExploitable)
	fmt.Printf("OWASP Violations:          %d\n", summary.TotalOWASP)
	fmt.Printf("EOL Frameworks:            %d\n", summary.TotalEOL)
	fmt.Println(strings.Repeat("-", 60))
	if summary.WAFDetected != "" {
		fmt.Printf("WAF Detected:              %s\n", summary.WAFDetected)
		if summary.WAFBypassed {
			fmt.Println("WAF Bypass:                SUCCESS")
		}
		fmt.Println(strings.Repeat("-", 60))
	}
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
			// If it still fails, try to use current directory as fallback
			fmt.Printf("[!] Warning: Failed to create output directory %s: %v. Using current directory.\n", config.OutputDir, err)
			config.OutputDir = "."
		}
	}
	
	// Final check - ensure we can write to whatever OutputDir is now
	testFile := filepath.Join(config.OutputDir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		fmt.Printf("[!] Warning: Cannot write to %s: %v. Falling back to /tmp.\n", config.OutputDir, err)
		config.OutputDir = os.TempDir()
	} else {
		os.Remove(testFile)
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
