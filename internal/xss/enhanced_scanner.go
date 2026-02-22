// Package xss provides XSS vulnerability detection
package xss

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/waf"
)

// EnhancedScanner provides advanced XSS scanning with WAF bypass
type EnhancedScanner struct {
	httpClient    *http.Client
	wafDetector   *waf.Detector
	payloadGen    *waf.PayloadGenerator
	encoder       *waf.Encoder
	timeout       time.Duration
	rateLimit     time.Duration
	userAgent     string
	wafBypass     bool
	wafType       waf.WAFType
	encodingLevel waf.EncodingLevel
	elements      []waf.ElementType
	verbose       bool
}

// EnhancedScannerOption configures the enhanced scanner
type EnhancedScannerOption func(*EnhancedScanner)

// WithEnhancedTimeout sets the scan timeout
func WithEnhancedTimeout(timeout time.Duration) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.timeout = timeout
	}
}

// WithRateLimit sets the rate limit between requests
func WithRateLimit(delay time.Duration) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.rateLimit = delay
	}
}

// WithUserAgent sets a custom user agent
func WithUserAgent(ua string) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.userAgent = ua
	}
}

// WithWAFBypass enables WAF bypass mode
func WithWAFBypass(enabled bool) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.wafBypass = enabled
	}
}

// WithWAFType forces a specific WAF type
func WithWAFType(wafType waf.WAFType) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.wafType = wafType
	}
}

// WithEncodingLevel sets the encoding aggressiveness
func WithEncodingLevel(level waf.EncodingLevel) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.encodingLevel = level
	}
}

// WithElements sets the element types to focus on
func WithElements(elements ...waf.ElementType) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.elements = elements
	}
}

// WithVerbose enables verbose output
func WithVerbose(verbose bool) EnhancedScannerOption {
	return func(s *EnhancedScanner) {
		s.verbose = verbose
	}
}

// NewEnhancedScanner creates a new enhanced XSS scanner
func NewEnhancedScanner(opts ...EnhancedScannerOption) (*EnhancedScanner, error) {
	s := &EnhancedScanner{
		timeout:       30 * time.Second,
		rateLimit:     100 * time.Millisecond,
		userAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		wafBypass:     false,
		wafType:       waf.WAFUnknown,
		encodingLevel: waf.EncodingLevelModerate,
		elements: []waf.ElementType{
			waf.ElementScript, waf.ElementImg,
			waf.ElementSVG, waf.ElementDiv,
		},
	}

	for _, opt := range opts {
		opt(s)
	}

	s.httpClient = &http.Client{
		Timeout: s.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	s.wafDetector = waf.NewDetector(waf.WithTimeout(s.timeout))
	s.payloadGen = waf.NewPayloadGenerator()
	s.encoder = waf.NewEncoder()
	s.encoder.SetLevel(s.encodingLevel)

	return s, nil
}

// EnhancedFinding extends XSSFinding with WAF bypass info
type EnhancedFinding struct {
	XSSFinding
	WAFType        waf.WAFType `json:"waf_type,omitempty"`
	WAFBypassed    bool        `json:"waf_bypassed,omitempty"`
	EncodingUsed   string      `json:"encoding_used,omitempty"`
	OriginalPayload string     `json:"original_payload,omitempty"`
	InjectionPoint string      `json:"injection_point"`
	RequestDetails *RequestDetails `json:"request_details,omitempty"`
}

// RequestDetails holds request/response information for evidence
type RequestDetails struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	StatusCode  int               `json:"status_code"`
	ResponseLen int               `json:"response_length"`
}

// ScanResult holds the complete scan results
type ScanResult struct {
	Target       string            `json:"target"`
	WAFDetection *waf.DetectionResult `json:"waf_detection,omitempty"`
	Findings     []EnhancedFinding `json:"findings"`
	TestedPayloads int             `json:"tested_payloads"`
	Duration     time.Duration     `json:"duration"`
}

// ScanWithBypass performs XSS scanning with WAF bypass
func (s *EnhancedScanner) ScanWithBypass(targetURL string) (*ScanResult, error) {
	return s.ScanWithBypassContext(context.Background(), targetURL)
}

// ScanWithBypassContext performs XSS scanning with context
func (s *EnhancedScanner) ScanWithBypassContext(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		Target: targetURL,
	}

	// Detect WAF if bypass mode enabled
	detectedWAF := s.wafType
	if s.wafBypass && s.wafType == waf.WAFUnknown {
		wafResult, err := s.wafDetector.DetectWithContext(ctx, targetURL)
		if err == nil {
			result.WAFDetection = wafResult
			detectedWAF = wafResult.WAFType
			if s.verbose {
				fmt.Printf("[*] WAF Detected: %s (confidence: %d%%)\n", detectedWAF.String(), wafResult.Confidence)
			}
		}
	}

	// Get payloads based on WAF and element types
	payloads := s.payloadGen.Generate(detectedWAF, s.elements...)

	// Add polyglot payloads
	payloads = append(payloads, s.payloadGen.GetPolyglotPayloads()...)

	if s.verbose {
		fmt.Printf("[*] Testing %d payloads against %s\n", len(payloads), targetURL)
	}

	// Parse URL for parameter injection
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return result, err
	}

	testedCount := 0

	// Test URL parameters
	if parsedURL.RawQuery != "" {
		params := parsedURL.Query()
		for param := range params {
			for _, payload := range payloads {
				select {
				case <-ctx.Done():
					result.TestedPayloads = testedCount
					result.Duration = time.Since(startTime)
					return result, ctx.Err()
				default:
				}

				// Generate encoded variants if WAF bypass enabled
				testPayloads := []string{payload.Value}
				if s.wafBypass {
					testPayloads = s.encoder.GenerateVariants(payload.Value, detectedWAF)
				}

				for _, testPayload := range testPayloads {
					testedCount++

					// Apply rate limiting
					time.Sleep(s.rateLimit)

					testURL := injectParameter(targetURL, param, testPayload)
					finding := s.testPayload(ctx, testURL, param, testPayload, payload.Value, detectedWAF)
					if finding != nil {
						result.Findings = append(result.Findings, *finding)
						break // Move to next parameter after finding
					}
				}
			}
		}
	}

	// Test URL path injection
	pathFindings := s.testPathInjection(ctx, targetURL, payloads, detectedWAF)
	result.Findings = append(result.Findings, pathFindings...)

	// Test fragment injection
	fragFindings := s.testFragmentInjection(ctx, targetURL, payloads, detectedWAF)
	result.Findings = append(result.Findings, fragFindings...)

	result.TestedPayloads = testedCount
	result.Duration = time.Since(startTime)

	return result, nil
}

// testPayload tests a single payload and returns finding if vulnerable
func (s *EnhancedScanner) testPayload(ctx context.Context, testURL, param, payload, origPayload string, wafType waf.WAFType) *EnhancedFinding {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	// Check if payload is reflected
	if s.isPayloadReflected(bodyStr, payload) {
		// Determine context
		context := s.detectContext(bodyStr, payload)
		xssType, severity, cvss := s.classifyXSS(context, payload)

		return &EnhancedFinding{
			XSSFinding: XSSFinding{
				Type:        xssType,
				Severity:    severity,
				CVSS:        cvss,
				CWE:         "CWE-79",
				URL:         testURL,
				Parameter:   param,
				Payload:     payload,
				Context:     context,
				Evidence:    s.extractEvidence(bodyStr, payload),
				Remediation: s.getRemediation(context),
				References:  []string{"https://owasp.org/www-community/attacks/xss/"},
				Hash:        hashFinding(testURL, param),
			},
			WAFType:         wafType,
			WAFBypassed:     wafType != waf.WAFUnknown,
			EncodingUsed:    s.detectEncoding(payload),
			OriginalPayload: origPayload,
			InjectionPoint:  "parameter:" + param,
			RequestDetails: &RequestDetails{
				Method:      "GET",
				URL:         testURL,
				StatusCode:  resp.StatusCode,
				ResponseLen: len(bodyStr),
			},
		}
	}

	return nil
}

// testPathInjection tests for XSS in URL path
func (s *EnhancedScanner) testPathInjection(ctx context.Context, targetURL string, payloads []waf.Payload, wafType waf.WAFType) []EnhancedFinding {
	var findings []EnhancedFinding

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return findings
	}

	// Test a subset of payloads in path
	testPayloads := payloads
	if len(testPayloads) > 10 {
		testPayloads = testPayloads[:10]
	}

	for _, payload := range testPayloads {
		// Inject at end of path
		newPath := parsedURL.Path + "/" + url.PathEscape(payload.Value)
		testURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, newPath)
		if parsedURL.RawQuery != "" {
			testURL += "?" + parsedURL.RawQuery
		}

		finding := s.testPayload(ctx, testURL, "path", payload.Value, payload.Value, wafType)
		if finding != nil {
			finding.InjectionPoint = "path"
			findings = append(findings, *finding)
		}

		time.Sleep(s.rateLimit)
	}

	return findings
}

// testFragmentInjection tests for DOM-based XSS via URL fragment
func (s *EnhancedScanner) testFragmentInjection(ctx context.Context, targetURL string, payloads []waf.Payload, wafType waf.WAFType) []EnhancedFinding {
	var findings []EnhancedFinding

	// Fragment-based XSS requires JavaScript analysis
	// Here we just check if the page might be vulnerable to DOM XSS
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", s.userAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)

	// Check for potential DOM XSS indicators
	domXSSIndicators := []string{
		"location.hash",
		"location.search",
		"document.URL",
		"document.referrer",
		"window.name",
		"innerHTML",
		"outerHTML",
		"document.write",
		"eval(",
	}

	for _, indicator := range domXSSIndicators {
		if strings.Contains(bodyStr, indicator) {
			findings = append(findings, EnhancedFinding{
				XSSFinding: XSSFinding{
					Type:        "Potential DOM XSS",
					Severity:    "MEDIUM",
					CVSS:        5.4,
					CWE:         "CWE-79",
					URL:         targetURL,
					Context:     "javascript",
					Evidence:    fmt.Sprintf("DOM sink detected: %s", indicator),
					Remediation: "Use safe DOM APIs like textContent instead of innerHTML",
					References:  []string{"https://owasp.org/www-community/attacks/DOM_Based_XSS"},
					Hash:        hashFinding(targetURL, "dom-"+indicator),
				},
				InjectionPoint: "fragment/dom",
			})
		}
	}

	return findings
}

// isPayloadReflected checks if the payload appears in the response
func (s *EnhancedScanner) isPayloadReflected(body, payload string) bool {
	// Direct match
	if strings.Contains(body, payload) {
		return true
	}

	// URL decoded match
	decoded, err := url.QueryUnescape(payload)
	if err == nil && decoded != payload && strings.Contains(body, decoded) {
		return true
	}

	// HTML entity decoded match
	decoded = s.encoder.DecodePayload(payload)
	if decoded != payload && strings.Contains(body, decoded) {
		return true
	}

	// Check for alert/prompt/confirm execution indicators
	execPatterns := []string{"alert(", "prompt(", "confirm(", "onerror=", "onload=", "onclick="}
	for _, pattern := range execPatterns {
		if strings.Contains(payload, pattern) && strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// detectContext determines the injection context
func (s *EnhancedScanner) detectContext(body, payload string) string {
	payloadIdx := strings.Index(body, payload)
	if payloadIdx == -1 {
		return "unknown"
	}

	// Get surrounding context
	start := payloadIdx - 100
	if start < 0 {
		start = 0
	}
	end := payloadIdx + len(payload) + 100
	if end > len(body) {
		end = len(body)
	}
	context := body[start:end]

	// Check for script context
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>.*?` + regexp.QuoteMeta(payload))
	if scriptPattern.MatchString(context) {
		return "javascript"
	}

	// Check for attribute context
	attrPattern := regexp.MustCompile(`(?i)\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(payload))
	if attrPattern.MatchString(context) {
		return "attribute"
	}

	// Check for URL context
	urlPattern := regexp.MustCompile(`(?i)(href|src|action|data)\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(payload))
	if urlPattern.MatchString(context) {
		return "url"
	}

	// Check for style context
	stylePattern := regexp.MustCompile(`(?i)style\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta(payload))
	if stylePattern.MatchString(context) {
		return "css"
	}

	return "html"
}

// classifyXSS returns the XSS type, severity, and CVSS based on context
func (s *EnhancedScanner) classifyXSS(context, payload string) (string, string, float64) {
	// Script context is most severe
	if context == "javascript" {
		if strings.Contains(payload, "eval") || strings.Contains(payload, "Function") {
			return "Reflected XSS (Code Execution)", "CRITICAL", 9.6
		}
		return "Reflected XSS (Script Context)", "HIGH", 7.5
	}

	// Event handler context
	if strings.Contains(payload, "on") && strings.Contains(payload, "=") {
		return "Reflected XSS (Event Handler)", "HIGH", 6.8
	}

	// URL context with javascript:
	if context == "url" && strings.Contains(strings.ToLower(payload), "javascript:") {
		return "Reflected XSS (JavaScript Protocol)", "HIGH", 6.5
	}

	// HTML context
	if strings.Contains(payload, "<script") || strings.Contains(payload, "<svg") {
		return "Reflected XSS (HTML Injection)", "HIGH", 6.1
	}

	return "Reflected XSS", "MEDIUM", 5.4
}

// extractEvidence extracts relevant evidence around the payload
func (s *EnhancedScanner) extractEvidence(body, payload string) string {
	idx := strings.Index(body, payload)
	if idx == -1 {
		return "Payload reflected (encoded)"
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(payload) + 50
	if end > len(body) {
		end = len(body)
	}

	evidence := body[start:end]
	// Clean up for readability
	evidence = strings.ReplaceAll(evidence, "\n", " ")
	evidence = strings.ReplaceAll(evidence, "\r", "")
	evidence = strings.ReplaceAll(evidence, "\t", " ")

	if len(evidence) > 200 {
		evidence = evidence[:200] + "..."
	}

	return evidence
}

// getRemediation returns context-specific remediation advice
func (s *EnhancedScanner) getRemediation(context string) string {
	remediations := map[string]string{
		"html":       "Encode < > & \" ' characters using HTML entities",
		"attribute":  "Quote attributes and encode < > & \" ' characters",
		"javascript": "Avoid inserting user data into JavaScript. Use JSON encoding if needed.",
		"url":        "Validate URLs against whitelist. Never allow javascript: protocol.",
		"css":        "Avoid user data in CSS. Use strict input validation.",
	}

	if r, ok := remediations[context]; ok {
		return r
	}
	return "Implement context-appropriate output encoding"
}

// detectEncoding identifies the encoding used in a payload
func (s *EnhancedScanner) detectEncoding(payload string) string {
	if strings.Contains(payload, "&#x") {
		return "html-hex"
	}
	if strings.Contains(payload, "&#") {
		return "html-decimal"
	}
	if strings.Contains(payload, "\\u") {
		return "unicode"
	}
	if strings.Contains(payload, "\\x") {
		return "hex"
	}
	if strings.Contains(payload, "%") {
		if strings.Contains(payload, "%25") {
			return "double-url"
		}
		return "url"
	}
	if strings.Contains(payload, "/*") {
		return "comment-insertion"
	}
	// Check for case variation
	hasUpper := false
	hasLower := false
	for _, r := range payload {
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
	}
	if hasUpper && hasLower {
		return "case-variation"
	}

	return "none"
}

// Close cleans up resources
func (s *EnhancedScanner) Close() error {
	return nil
}

// GetWAFStrategies returns bypass strategies for detected WAF
func (s *EnhancedScanner) GetWAFStrategies(wafType waf.WAFType) []string {
	return waf.GetBypassStrategies(wafType)
}
