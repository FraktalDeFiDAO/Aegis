// Package scanner provides tools for analyzing mirrored web content for
// security vulnerabilities, secrets, and dangerous patterns.
package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Scanner analyzes mirrored content for potential security issues
// by performing pattern matching across files in a directory.
type Scanner struct {
	dumpPath string
}

// Finding represents a single security issue discovered during a scan,
// containing metadata about the location, severity, and nature of the issue.
type Finding struct {
	Type     string `json:"type"`     // Type of vulnerability (e.g., "Secret Found", "XSS")
	Severity string `json:"severity"` // Severity level (HIGH, MEDIUM, LOW)
	File     string `json:"file"`     // Path to the file containing the finding
	Line     int    `json:"line"`     // Line number where the issue was detected
	Summary  string `json:"summary"`  // Brief description of the issue
	Value    string `json:"value"`    // The actual text that triggered the finding
}

// NewScanner initializes a new Scanner targeting the provided directory.
func NewScanner(dumpPath string) *Scanner {
	return &Scanner{
		dumpPath: dumpPath,
	}
}

// Scan performs a recursive analysis of all valid text files within the
// dump directory. It uses a worker pool for parallel processing.
//
// Returns a slice of Findings and an error if the directory walk fails.
func (s *Scanner) Scan() ([]Finding, error) {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	filesChan := make(chan string, 100)

	// Worker pool
	for i := 0; i < 10; i++ {
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

	err := filepath.WalkDir(s.dumpPath, func(path string, d fs.DirEntry, err error) error {
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
		return nil, fmt.Errorf("error walking dump directory: %w", err)
	}

	return findings, nil
}

func isValidTextFile(ext string) bool {
	ext = strings.ToLower(ext)
	textExtensions := []string{".html", ".htm", ".js", ".css", ".json", ".xml", ".txt", ".md", ".yaml", ".yml", ".conf", ".config"}
	for _, validExt := range textExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

func (s *Scanner) scanContent(content, filePath string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Secret Checks
		for desc, pattern := range secretPatterns {
			if match := pattern.FindStringSubmatch(line); len(match) > 1 {
				findings = append(findings, Finding{
					Type:     "Secret Found",
					Severity: "HIGH",
					File:     filePath,
					Line:     lineNum + 1,
					Summary:  fmt.Sprintf("%s detected", desc),
					Value:    match[1],
				})
			}
		}

		// Vulnerability Checks
		for name, info := range vulnPatterns {
			if match := info.regex.FindString(line); match != "" {
				findings = append(findings, Finding{
					Type:     name,
					Severity: info.severity,
					File:     filePath,
					Line:     lineNum + 1,
					Summary:  info.desc,
					Value:    match,
				})
			}
		}
	}

	return findings
}

var secretPatterns = map[string]*regexp.Regexp{
	"API Key":         regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)["\s:=]+[\"\s]*([A-Za-z0-9_\-]{32,})[\"\s]*`),
	"Password":        regexp.MustCompile(`(?i)(?:password|pwd|pass)\s*[=:]\s*["']?([^"';\s]{5,})["']?`),
	"JWT Token":       regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
	"AWS Access Key":  regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
	"Private Key":     regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[
\s]*?-----END (?:RSA|EC|DSA)? PRIVATE KEY-----)`),
}

var vulnPatterns = map[string]struct {
	regex    *regexp.Regexp
	severity string
	desc     string
}{
	"Eval Usage": {
		regexp.MustCompile(`(?i)\beval\s*\(`),
		"HIGH",
		"Potential eval() usage found",
	},
	"Unsafe Redirect": {
		regexp.MustCompile(`(?i)window\.location\s*=|document\.location\s*=|top\.location\s*=`),
		"HIGH",
		"Potential unsafe redirect found",
	},
	"Potential XSS": {
		regexp.MustCompile(`(?i)<script[^>]*>[^<]*alert\([^)]*\)[^<]*</script>|<[^>]*on\w+=[^>]*>`),
		"HIGH",
		"Potential XSS vulnerability found",
	},
	"ATO - Session in URL": {
		regexp.MustCompile(`(?i)(?:sid|session|token|auth)=[a-zA-Z0-9\-_]{16,}`),
		"HIGH",
		"Potential session token exposed in URL or script",
	},
	"Insecure Cookie Configuration": {
		regexp.MustCompile(`(?i)document\.cookie\s*=\s*['"][^'"]*(?:secure|httponly)['"]`),
		"MEDIUM",
		"Cookie set via JS might lack secure/httponly flags",
	},
}
