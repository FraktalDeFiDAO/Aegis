// Package xss provides XSS vulnerability detection including DOM-based XSS
package xss

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed patterns/*.yaml
var embeddedPatterns embed.FS

// PatternConfig represents the YAML configuration structure
type PatternConfig struct {
	Version     string `yaml:"version"`
	LastUpdated string `yaml:"last_updated"`
	Sources     []struct {
		Name        string `yaml:"name"`
		Pattern     string `yaml:"pattern"`
		Description string `yaml:"description"`
		Severity    string `yaml:"severity"`
		Category    string `yaml:"category"`
	} `yaml:"sources"`
	Sinks []struct {
		Name        string `yaml:"name"`
		Pattern     string `yaml:"pattern"`
		Description string `yaml:"description"`
		Severity    string `yaml:"severity"`
		CWE         string `yaml:"cwe"`
		Category    string `yaml:"category"`
	} `yaml:"sinks"`
	Frameworks []struct {
		Name           string `yaml:"name"`
		Pattern        string `yaml:"pattern"`
		VersionPattern string `yaml:"version_pattern"`
	} `yaml:"frameworks"`
	Payloads struct {
		Basic            []string `yaml:"basic"`
		EventHandlers    []string `yaml:"event_handlers"`
		JavascriptProto  []string `yaml:"javascript_protocol"`
		Encoded          []string `yaml:"encoded"`
		TemplateInject   []string `yaml:"template_injection"`
		DOMClobbering    []string `yaml:"dom_clobbering"`
		FilterBypass     []string `yaml:"filter_bypass"`
		Polyglot         []string `yaml:"polyglot"`
	} `yaml:"payloads"`
}

// DOMXSSFinding represents a DOM-based XSS finding from static analysis
type DOMXSSFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	PatternName string `json:"pattern_name"`
	PatternType string `json:"pattern_type"` // "source" or "sink"
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	CWE         string `json:"cwe,omitempty"`
	Description string `json:"description"`
	Context     string `json:"context"`
	RawMatch    string `json:"raw_match"`
	Hash        string `json:"hash"`
}

// DOMXSSFlow represents a potential data flow from source to sink
type DOMXSSFlow struct {
	Source     DOMXSSFinding `json:"source"`
	Sink       DOMXSSFinding `json:"sink"`
	Distance   int           `json:"distance"`
	Confidence string        `json:"confidence"` // "HIGH", "MEDIUM", "LOW"
}

// DOMXSSReport contains analysis results for a directory
type DOMXSSReport struct {
	ScanDir             string              `json:"scan_dir"`
	FilesScanned        int                 `json:"files_scanned"`
	TotalSources        int                 `json:"total_sources"`
	TotalSinks          int                 `json:"total_sinks"`
	TotalFlows          int                 `json:"total_flows"`
	CriticalFindings    int                 `json:"critical_findings"`
	HighFindings        int                 `json:"high_findings"`
	MediumFindings      int                 `json:"medium_findings"`
	Frameworks          map[string]int      `json:"frameworks_detected"`
	Findings            []DOMXSSFinding     `json:"findings"`
	HighConfidenceFlows []DOMXSSFlow        `json:"high_confidence_flows"`
	TestPayloads        map[string][]string `json:"test_payloads"`
}

// sourcePattern holds compiled source pattern info
type sourcePattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
	Category    string
}

// sinkPattern holds compiled sink pattern info
type sinkPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    string
	CWE         string
	Description string
	Category    string
}

// frameworkPattern holds compiled framework detection pattern
type frameworkPattern struct {
	Name         string
	Regex        *regexp.Regexp
	VersionRegex *regexp.Regexp
}

// DOMXSSAnalyzer analyzes HTML/JS files for DOM XSS
type DOMXSSAnalyzer struct {
	config            *PatternConfig
	sourcePatterns    []sourcePattern
	sinkPatterns      []sinkPattern
	frameworkPatterns []frameworkPattern
}

// NewDOMXSSAnalyzer creates a new DOM XSS analyzer
func NewDOMXSSAnalyzer() (*DOMXSSAnalyzer, error) {
	return NewDOMXSSAnalyzerWithConfig("")
}

// NewDOMXSSAnalyzerWithConfig creates analyzer with custom config path
func NewDOMXSSAnalyzerWithConfig(configPath string) (*DOMXSSAnalyzer, error) {
	a := &DOMXSSAnalyzer{}

	var configData []byte
	var err error

	if configPath != "" {
		// Load from specified path
		configData, err = os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	} else {
		// Try embedded patterns first, then fallback to default config location
		configData, err = embeddedPatterns.ReadFile("patterns/domxss-patterns.yaml")
		if err != nil {
			// Try configs directory relative to binary
			configData, err = os.ReadFile("configs/domxss-patterns.yaml")
			if err != nil {
				// Use hardcoded defaults as final fallback
				return newDOMXSSAnalyzerWithDefaults()
			}
		}
	}

	if err := yaml.Unmarshal(configData, &a.config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := a.compilePatterns(); err != nil {
		return nil, err
	}

	return a, nil
}

// compilePatterns compiles all regex patterns from config
func (a *DOMXSSAnalyzer) compilePatterns() error {
	// Compile source patterns
	for _, src := range a.config.Sources {
		re, err := regexp.Compile("(?i)" + src.Pattern)
		if err != nil {
			return fmt.Errorf("invalid source pattern %s: %w", src.Name, err)
		}
		a.sourcePatterns = append(a.sourcePatterns, sourcePattern{
			Name:        src.Name,
			Regex:       re,
			Description: src.Description,
			Category:    src.Category,
		})
	}

	// Compile sink patterns
	for _, sink := range a.config.Sinks {
		// Only use case-insensitive if it doesn't start with a letter (e.g. .innerHTML)
		// but for Function/eval we want case sensitivity to avoid matching 'function'
		pattern := sink.Pattern
		if !strings.HasPrefix(pattern, `\b`) && !regexp.MustCompile(`^[A-Za-z]`).MatchString(pattern) {
			pattern = "(?i)" + pattern
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid sink pattern %s: %w", sink.Name, err)
		}
		a.sinkPatterns = append(a.sinkPatterns, sinkPattern{
			Name:        sink.Name,
			Regex:       re,
			Severity:    sink.Severity,
			CWE:         sink.CWE,
			Description: sink.Description,
			Category:    sink.Category,
		})
	}

	// Compile framework patterns
	for _, fw := range a.config.Frameworks {
		re, err := regexp.Compile("(?i)" + fw.Pattern)
		if err != nil {
			return fmt.Errorf("invalid framework pattern %s: %w", fw.Name, err)
		}

		var versionRe *regexp.Regexp
		if fw.VersionPattern != "" {
			versionRe, _ = regexp.Compile("(?i)" + fw.VersionPattern)
		}

		a.frameworkPatterns = append(a.frameworkPatterns, frameworkPattern{
			Name:         fw.Name,
			Regex:        re,
			VersionRegex: versionRe,
		})
	}

	return nil
}

// newDOMXSSAnalyzerWithDefaults creates analyzer with hardcoded defaults
// "Kitchen Sink" fallback edition
func newDOMXSSAnalyzerWithDefaults() (*DOMXSSAnalyzer, error) {
	a := &DOMXSSAnalyzer{
		config: &PatternConfig{
			Version: "2.0-defaults",
		},
	}

	// Comprehensive default sources
	defaultSources := map[string]string{
		"location.hash":          `location\.hash`,
		"location.search":        `location\.search`,
		"location.href":          `location\.href`,
		"location.pathname":      `location\.pathname`,
		"document.URL":           `document\.URL`,
		"document.documentURI":   `document\.documentURI`,
		"document.baseURI":       `document\.baseURI`,
		"document.referrer":      `document\.referrer`,
		"document.cookie":        `document\.cookie`,
		"window.name":            `window\.name`,
		"window.location":        `window\.location`,
		"localStorage.getItem":   `localStorage\.getItem\s*\(`,
		"sessionStorage.getItem": `sessionStorage\.getItem\s*\(`,
		"localStorage[]":         `localStorage\s*\[`,
		"sessionStorage[]":       `sessionStorage\s*\[`,
		"URLSearchParams":        `URLSearchParams\s*\(`,
		"new URL":                `new\s+URL\s*\(`,
		"postMessage.data":       `\.data`,
		"event.data":             `event\.data`,
		"input.value":            `\.value`,
		"document.forms":         `document\.forms`,
		"$.param":                `\$\.param\s*\(`,
		".val()":                 `\.val\s*\(\s*\)`,
		".data()":                `\.data\s*\(\s*[''"]`,
		".attr()":                `\.attr\s*\(\s*[''"]`,
		"getParameter":           `getParameter\s*\(`,
		"getParam":               `getParam\s*\(`,
		"getQuery":               `getQuery\s*\(`,
		"getUrlParam":            `getUrlParam\s*\(`,
	}

	for name, pattern := range defaultSources {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		a.sourcePatterns = append(a.sourcePatterns, sourcePattern{
			Name:        name,
			Regex:       re,
			Description: "Potential XSS source",
			Category:    "default",
		})
	}

	// Comprehensive default sinks
	defaultSinks := []struct {
		Name     string
		Pattern  string
		Severity string
		CWE      string
	}{
		{"innerHTML=", `\.innerHTML\s*=`, "HIGH", "CWE-79"},
		{"outerHTML=", `\.outerHTML\s*=`, "HIGH", "CWE-79"},
		{"document.write", `document\.write\s*\(`, "HIGH", "CWE-79"},
		{"document.writeln", `document\.writeln\s*\(`, "HIGH", "CWE-79"},
		{"insertAdjacentHTML", `\.insertAdjacentHTML\s*\(`, "HIGH", "CWE-79"},
		{"eval", `\beval\s*\(`, "CRITICAL", "CWE-95"},
		{"Function", `\bFunction\s*\(`, "CRITICAL", "CWE-95"},
		{"new Function", `new\s+Function\s*\(`, "CRITICAL", "CWE-95"},
		{"setTimeout-string", `setTimeout\s*\(\s*['" \x60]`, "HIGH", "CWE-95"},
		{"setInterval-string", `setInterval\s*\(\s*['" \x60]`, "HIGH", "CWE-95"},
		{"setImmediate-string", `setImmediate\s*\(\s*['" \x60]`, "HIGH", "CWE-95"},
		{"script.src=", `script\.src\s*=`, "HIGH", "CWE-79"},
		{"script.text=", `script\.text\s*=`, "CRITICAL", "CWE-79"},
		{"script.textContent=", `script\.textContent\s*=`, "CRITICAL", "CWE-79"},
		{"script.innerText=", `script\.innerText\s*=`, "CRITICAL", "CWE-79"},
		{"iframe.srcdoc=", `\.srcdoc\s*=`, "HIGH", "CWE-79"},
		{"setAttribute-on*", `setAttribute\s*\(\s*[''"]on`, "HIGH", "CWE-79"},
		{"setAttribute-src", `setAttribute\s*\(\s*[''"]src[''"]`, "MEDIUM", "CWE-79"},
		{"setAttribute-href", `setAttribute\s*\(\s*[''"]href[''"]`, "MEDIUM", "CWE-79"},
		{"location=", `\blocation\s*=`, "MEDIUM", "CWE-601"},
		{"location.href=", `location\.href\s*=`, "MEDIUM", "CWE-601"},
		{"location.assign", `location\.assign\s*\(`, "MEDIUM", "CWE-601"},
		{"location.replace", `location\.replace\s*\(`, "MEDIUM", "CWE-601"},
		{"window.open", `window\.open\s*\(`, "MEDIUM", "CWE-601"},
		{"$.html()", `\.html\s*\([^)]+\)`, "HIGH", "CWE-79"},
		{"$.append()", `\.append\s*\([^)]+\)`, "MEDIUM", "CWE-79"},
		{"$.prepend()", `\.prepend\s*\([^)]+\)`, "MEDIUM", "CWE-79"},
		{"$.after()", `\.after\s*\([^)]+\)`, "MEDIUM", "CWE-79"},
		{"$.before()", `\.before\s*\([^)]+\)`, "MEDIUM", "CWE-79"},
		{"$.replaceWith()", `\.replaceWith\s*\([^)]+\)`, "MEDIUM", "CWE-79"},
		{"$.wrap()", `\.wrap\s*\([^)]+\)`, "MEDIUM", "CWE-79"},
		{"$.globalEval()", `\$\.globalEval\s*\(`, "CRITICAL", "CWE-95"},
		{"v-html", `v-html\s*=`, "HIGH", "CWE-79"},
		{"dangerouslySetInnerHTML", `dangerouslySetInnerHTML`, "HIGH", "CWE-79"},
		{"[innerHTML]", `\[innerHTML\]\s*=`, "HIGH", "CWE-79"},
		{"ng-bind-html", `ng-bind-html\s*=`, "HIGH", "CWE-79"},
		{"bypassSecurityTrust", `bypassSecurityTrust`, "HIGH", "CWE-79"},
		{"trustAsHtml", `trustAsHtml\s*\(`, "HIGH", "CWE-79"},
		{"m.trust", `m\.trust\s*\(`, "HIGH", "CWE-79"},
		{"Ractive.unescaped", `Ractive\.unescaped`, "HIGH", "CWE-79"},
	}

	for _, sink := range defaultSinks {
		re, err := regexp.Compile("(?i)" + sink.Pattern)
		if err != nil {
			continue
		}
		a.sinkPatterns = append(a.sinkPatterns, sinkPattern{
			Name:        sink.Name,
			Regex:       re,
			Severity:    sink.Severity,
			CWE:         sink.CWE,
			Description: "Potential XSS sink",
			Category:    "default",
		})
	}

	return a, nil
}

// AnalyzeDirectory scans all HTML/JS files in a directory
func (a *DOMXSSAnalyzer) AnalyzeDirectory(dir string) (*DOMXSSReport, error) {
	report := &DOMXSSReport{
		ScanDir:      dir,
		Frameworks:   make(map[string]int),
		TestPayloads: a.getTestPayloads(),
	}

	extensions := []string{".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".php", ".asp", ".aspx"}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		validExt := false
		for _, e := range extensions {
			if ext == e {
				validExt = true
				break
			}
		}
		if !validExt {
			return nil
		}

		findings, frameworks := a.AnalyzeFile(path)
		report.FilesScanned++
		report.Findings = append(report.Findings, findings...)

		for _, fw := range frameworks {
			report.Frameworks[fw]++
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Calculate flows and stats
	a.calculateFlows(report)
	a.calculateStats(report)

	return report, nil
}

// AnalyzeFile analyzes a single file for DOM XSS patterns
func (a *DOMXSSAnalyzer) AnalyzeFile(path string) ([]DOMXSSFinding, []string) {
	var findings []DOMXSSFinding
	var frameworks []string

	content, err := os.ReadFile(path)
	if err != nil {
		return findings, frameworks
	}

	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	// Detect frameworks
	for _, fw := range a.frameworkPatterns {
		if fw.Regex.MatchString(contentStr) {
			frameworks = append(frameworks, fw.Name)
		}
	}

	// Find sources and sinks
	for lineNum, line := range lines {
		// Find sources
		for _, src := range a.sourcePatterns {
			matches := src.Regex.FindAllStringIndex(line, -1)
			for _, match := range matches {
				findings = append(findings, DOMXSSFinding{
					File:        path,
					Line:        lineNum + 1,
					Column:      match[0],
					PatternName: src.Name,
					PatternType: "source",
					Severity:    "INFO",
					Category:    src.Category,
					Description: src.Description,
					Context:     truncateContext(line, 200),
					RawMatch:    line[match[0]:match[1]],
					Hash:        hashDOMFinding(path, lineNum+1, src.Name),
				})
			}
		}

		// Find sinks
		for _, sink := range a.sinkPatterns {
			matches := sink.Regex.FindAllStringIndex(line, -1)
			for _, match := range matches {
				if isStaticLiteralAssignment(line, match[1]) {
					continue
				}
				findings = append(findings, DOMXSSFinding{
					File:        path,
					Line:        lineNum + 1,
					Column:      match[0],
					PatternName: sink.Name,
					PatternType: "sink",
					Severity:    sink.Severity,
					CWE:         sink.CWE,
					Category:    sink.Category,
					Description: sink.Description,
					Context:     truncateContext(line, 200),
					RawMatch:    line[match[0]:match[1]],
					Hash:        hashDOMFinding(path, lineNum+1, sink.Name),
				})
			}
		}
	}

	return findings, frameworks
}

// AnalyzeContent analyzes content string directly (for crawled pages)
func (a *DOMXSSAnalyzer) AnalyzeContent(content, identifier string) []DOMXSSFinding {
	var findings []DOMXSSFinding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Find sources
		for _, src := range a.sourcePatterns {
			matches := src.Regex.FindAllStringIndex(line, -1)
			for _, match := range matches {
				findings = append(findings, DOMXSSFinding{
					File:        identifier,
					Line:        lineNum + 1,
					Column:      match[0],
					PatternName: src.Name,
					PatternType: "source",
					Severity:    "INFO",
					Category:    src.Category,
					Description: src.Description,
					Context:     truncateContext(line, 200),
					RawMatch:    line[match[0]:match[1]],
					Hash:        hashDOMFinding(identifier, lineNum+1, src.Name),
				})
			}
		}

		// Find sinks
		for _, sink := range a.sinkPatterns {
			matches := sink.Regex.FindAllStringIndex(line, -1)
			for _, match := range matches {
				if isStaticLiteralAssignment(line, match[1]) {
					continue
				}
				findings = append(findings, DOMXSSFinding{
					File:        identifier,
					Line:        lineNum + 1,
					Column:      match[0],
					PatternName: sink.Name,
					PatternType: "sink",
					Severity:    sink.Severity,
					CWE:         sink.CWE,
					Category:    sink.Category,
					Description: sink.Description,
					Context:     truncateContext(line, 200),
					RawMatch:    line[match[0]:match[1]],
					Hash:        hashDOMFinding(identifier, lineNum+1, sink.Name),
				})
			}
		}
	}

	return findings
}

// GetPayloads returns test payloads for a specific category
func (a *DOMXSSAnalyzer) GetPayloads(category string) []string {
	if a.config == nil || a.config.Payloads.Basic == nil {
		return defaultPayloads()
	}

	switch category {
	case "basic":
		return a.config.Payloads.Basic
	case "event_handlers":
		return a.config.Payloads.EventHandlers
	case "javascript_protocol":
		return a.config.Payloads.JavascriptProto
	case "encoded":
		return a.config.Payloads.Encoded
	case "template_injection":
		return a.config.Payloads.TemplateInject
	case "dom_clobbering":
		return a.config.Payloads.DOMClobbering
	case "filter_bypass":
		return a.config.Payloads.FilterBypass
	case "polyglot":
		return a.config.Payloads.Polyglot
	case "all":
		return a.getAllPayloads()
	default:
		return a.config.Payloads.Basic
	}
}

func (a *DOMXSSAnalyzer) getAllPayloads() []string {
	var all []string
	all = append(all, a.config.Payloads.Basic...)
	all = append(all, a.config.Payloads.EventHandlers...)
	all = append(all, a.config.Payloads.JavascriptProto...)
	all = append(all, a.config.Payloads.Encoded...)
	all = append(all, a.config.Payloads.TemplateInject...)
	all = append(all, a.config.Payloads.DOMClobbering...)
	all = append(all, a.config.Payloads.FilterBypass...)
	all = append(all, a.config.Payloads.Polyglot...)
	return all
}

func (a *DOMXSSAnalyzer) getTestPayloads() map[string][]string {
	if a.config == nil {
		return map[string][]string{"basic": defaultPayloads()}
	}

	return map[string][]string{
		"basic":             a.config.Payloads.Basic,
		"event_handlers":    a.config.Payloads.EventHandlers,
		"javascript_protocol": a.config.Payloads.JavascriptProto,
		"encoded":           a.config.Payloads.Encoded,
		"template_injection": a.config.Payloads.TemplateInject,
		"dom_clobbering":    a.config.Payloads.DOMClobbering,
		"filter_bypass":     a.config.Payloads.FilterBypass,
		"polyglot":          a.config.Payloads.Polyglot,
	}
}

func defaultPayloads() []string {
	return []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
	}
}

func (a *DOMXSSAnalyzer) calculateFlows(report *DOMXSSReport) {
	// Group findings by file
	byFile := make(map[string][]DOMXSSFinding)
	for _, f := range report.Findings {
		byFile[f.File] = append(byFile[f.File], f)
	}

	for _, findings := range byFile {
		var sources, sinks []DOMXSSFinding
		for _, f := range findings {
			if f.PatternType == "source" {
				sources = append(sources, f)
			} else if f.PatternType == "sink" {
				sinks = append(sinks, f)
			}
		}

		// Check for flows between sources and sinks
		for _, source := range sources {
			for _, sink := range sinks {
				distance := abs(source.Line - sink.Line)
				if distance > 100 {
					continue // Too far
				}

				var confidence string
				if distance < 10 {
					confidence = "HIGH"
				} else if distance < 30 {
					confidence = "MEDIUM"
				} else {
					confidence = "LOW"
				}
                
                // Heuristic: If they are on the same line, it's very likely a direct flow
                if distance == 0 {
                    confidence = "CRITICAL"
                }

				// Only keep high/medium confidence flows
				if confidence == "CRITICAL" || confidence == "HIGH" || confidence == "MEDIUM" {
					report.HighConfidenceFlows = append(report.HighConfidenceFlows, DOMXSSFlow{
						Source:     source,
						Sink:       sink,
						Distance:   distance,
						Confidence: confidence,
					})
				}

				report.TotalFlows++
			}
		}
	}
}

func (a *DOMXSSAnalyzer) calculateStats(report *DOMXSSReport) {
	for _, f := range report.Findings {
		if f.PatternType == "source" {
			report.TotalSources++
		} else if f.PatternType == "sink" {
			report.TotalSinks++
			switch f.Severity {
			case "CRITICAL":
				report.CriticalFindings++
			case "HIGH":
				report.HighFindings++
			case "MEDIUM":
				report.MediumFindings++
			}
		}
	}
}

func truncateContext(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func hashDOMFinding(file string, line int, pattern string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%d:%s", file, line, pattern)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// isStaticLiteralAssignment checks if the value following a sink match is a static string literal
func isStaticLiteralAssignment(line string, matchEnd int) bool {
	remaining := strings.TrimSpace(line[matchEnd:])
	if len(remaining) == 0 {
		return false
	}

	// Check for simple string assignments: = "..." or = '...' or = `...`
	// Also handle function calls with literals: ("...")
	firstChar := remaining[0]
	if firstChar == '=' {
		val := strings.TrimSpace(remaining[1:])
		if len(val) > 0 {
			c := val[0]
			// If it starts with a quote and ends with a quote on the same line, it's a literal
			if c == '"' || c == '\'' || c == '`' {
				endQuote := strings.LastIndexByte(val, c)
				if endQuote > 0 && endQuote == len(val)-1 {
					return true
				}
				// Also check if it's a literal followed by a semicolon
				if endQuote > 0 && endQuote == len(val)-2 && val[len(val)-1] == ';' {
					return true
				}
			}
		}
	} else if firstChar == '(' {
		val := strings.TrimSpace(remaining[1:])
		if len(val) > 0 {
			c := val[0]
			if c == '"' || c == '\'' || c == '`' {
				// Rough check for closing paren after literal
				if strings.Contains(val, string(c)+")") {
					return true
				}
			}
		}
	}

	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}