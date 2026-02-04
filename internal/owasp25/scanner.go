package owasp25

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Finding represents an OWASP Top 25 vulnerability finding
 type Finding struct {
	Category    Category `json:"category"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	CWE         string   `json:"cwe"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column,omitempty"`
	Summary     string   `json:"summary"`
	Value       string   `json:"value"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	Hash        string   `json:"hash"`
	Context     string   `json:"context,omitempty"` // Surrounding lines
}

// Scanner scans for OWASP Top 25 vulnerabilities
 type Scanner struct {
	scanPath       string
	workers        int
	enabledCategories []Category
}

// ScannerOption configures the scanner
 type ScannerOption func(*Scanner)

// WithWorkers sets the number of concurrent workers
 func WithWorkers(workers int) ScannerOption {
	return func(s *Scanner) {
		s.workers = workers
	}
}

// WithCategories limits scanning to specific OWASP categories
 func WithCategories(cats ...Category) ScannerOption {
	return func(s *Scanner) {
		s.enabledCategories = cats
	}
}

// NewScanner creates a new OWASP Top 25 scanner
 func NewScanner(scanPath string, opts ...ScannerOption) *Scanner {
	s := &Scanner{
		scanPath:          scanPath,
		workers:           10,
		enabledCategories: GetAllCategories(),
	}
	
	for _, opt := range opts {
		opt(s)
	}
	
	return s
}

// Scan performs a full OWASP Top 25 scan
 func (s *Scanner) Scan() ([]Finding, error) {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	filesChan := make(chan string, 100)

	// Start workers
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range filesChan {
				content, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				fileFindings := s.scanContent(string(content), path)
				if len(fileFindings) > 0 {
					mu.Lock()
					findings = append(findings, fileFindings...)
					mu.Unlock()
				}
			}
		}()
	}

	// Walk directory
	err := filepath.WalkDir(s.scanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(path))
		if isValidTextFile(ext) {
			filesChan <- path
		}
		return nil
	})

	close(filesChan)
	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}

	// Deduplicate findings
	findings = deduplicateFindings(findings)

	return findings, nil
}

// ScanString scans a string for OWASP vulnerabilities (useful for dynamic content)
 func (s *Scanner) ScanString(content, source string) []Finding {
	return s.scanContent(content, source)
}

// scanContent scans file content for all enabled OWASP categories
 func (s *Scanner) scanContent(content, filePath string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for catIdx, cat := range s.enabledCategories {
		_ = catIdx
		info, ok := CategoryDatabase[cat]
		if !ok {
			continue
		}

		for _, pattern := range info.DetectionPatterns {
			for lineNum, line := range lines {
				if match := pattern.Regex.FindStringIndex(line); match != nil {
					finding := Finding{
						Category:    cat,
						Type:        pattern.Name,
						Severity:    pattern.Severity,
						CVSS:        pattern.CVSS,
						CWE:         pattern.CWE,
						File:        filePath,
						Line:        lineNum + 1,
						Column:      match[0] + 1,
						Summary:     pattern.Description,
						Value:       truncateString(line[match[0]:match[1]], 100),
						Remediation: pattern.Remediation,
						References:  pattern.References,
						Context:     getContext(lines, lineNum),
					}
					finding.Hash = hashFinding(finding)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// ScanCategory scans for a specific OWASP category
 func (s *Scanner) ScanCategory(content, filePath string, cat Category) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	info, ok := CategoryDatabase[cat]
	if !ok {
		return findings
	}

	for _, pattern := range info.DetectionPatterns {
		for lineNum, line := range lines {
			if match := pattern.Regex.FindStringIndex(line); match != nil {
				finding := Finding{
					Category:    cat,
					Type:        pattern.Name,
					Severity:    pattern.Severity,
					CVSS:        pattern.CVSS,
					CWE:         pattern.CWE,
					File:        filePath,
					Line:        lineNum + 1,
					Column:      match[0] + 1,
					Summary:     pattern.Description,
					Value:       truncateString(line[match[0]:match[1]], 100),
					Remediation: pattern.Remediation,
					References:  pattern.References,
					Context:     getContext(lines, lineNum),
				}
				finding.Hash = hashFinding(finding)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// GetCategoryStats returns statistics for each category
 func (s *Scanner) GetCategoryStats(findings []Finding) map[Category]int {
	stats := make(map[Category]int)
	for _, f := range findings {
		stats[f.Category]++
	}
	return stats
}

// GetSeverityStats returns statistics by severity
 func (s *Scanner) GetSeverityStats(findings []Finding) map[string]int {
	stats := make(map[string]int)
	for _, f := range findings {
		stats[f.Severity]++
	}
	return stats
}

// deduplicateFindings removes duplicate findings
 func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding
	
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s:%d:%s", f.Category.String(), f.File, f.Line, f.Type)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	
	return unique
}

// hashFinding creates a unique hash for a finding
 func hashFinding(f Finding) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%s", 
		f.Category.String(), f.File, f.Line, f.Type)))
	return fmt.Sprintf("%x", hash[:8])
}

// truncateString truncates a string to max length
 func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// getContext returns surrounding lines for context
 func getContext(lines []string, lineNum int) string {
	start := lineNum - 2
	if start < 0 {
		start = 0
	}
	end := lineNum + 3
	if end > len(lines) {
		end = len(lines)
	}
	
	return strings.Join(lines[start:end], "\n")
}

// isValidTextFile checks if file extension should be scanned
 func isValidTextFile(ext string) bool {
	ext = strings.ToLower(ext)
	textExtensions := []string{
		// Web files
		".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".css", ".json", ".xml", ".txt", ".md",
		// Config files
		".yaml", ".yml", ".conf", ".config", ".env", ".ini", ".toml",
		// Source code
		".php", ".jsp", ".asp", ".aspx", ".py", ".rb", ".go", ".java",
		".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".rs",
		// Template files
		".vue", ".svelte", ".ejs", ".hbs", ".pug", ".jade", ".mustache",
		// Data files
		".csv", ".sql", ".graphql", ".gql",
		// Mobile
		".plist", ".gradle", ".xml",
	}
	for _, validExt := range textExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

// AddCustomPattern adds a custom detection pattern to a category
 func (s *Scanner) AddCustomPattern(cat Category, pattern Pattern) error {
	info, ok := CategoryDatabase[cat]
	if !ok {
		return fmt.Errorf("invalid category: %v", cat)
	}
	
	info.DetectionPatterns = append(info.DetectionPatterns, pattern)
	CategoryDatabase[cat] = info
	
	return nil
}

// Report generates a summary report of findings
 func (s *Scanner) Report(findings []Finding) string {
	var sb strings.Builder
	
	sb.WriteString("=== OWASP Top 25 Security Scan Report ===\n\n")
	
	// Overall stats
	sb.WriteString(fmt.Sprintf("Total Findings: %d\n\n", len(findings)))
	
	// By severity
	sb.WriteString("Findings by Severity:\n")
	severityStats := s.GetSeverityStats(findings)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if count := severityStats[sev]; count > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", sev, count))
		}
	}
	sb.WriteString("\n")
	
	// By category
	sb.WriteString("Findings by OWASP Category:\n")
	catStats := s.GetCategoryStats(findings)
	for cat, count := range catStats {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", cat.String(), count))
	}
	sb.WriteString("\n")
	
	// Top findings
	if len(findings) > 0 {
		sb.WriteString("Critical/High Priority Findings:\n")
		for _, f := range findings {
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				sb.WriteString(fmt.Sprintf("  [%s] %s:%d - %s (%s)\n",
					f.Severity, f.File, f.Line, f.Type, f.CWE))
			}
		}
	}
	
	return sb.String()
}