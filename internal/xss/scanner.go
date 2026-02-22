// Package xss provides XSS vulnerability detection
package xss

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// XSSFinding represents an XSS vulnerability finding
type XSSFinding struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	CWE         string   `json:"cwe"`
	URL         string   `json:"url"`
	Parameter   string   `json:"parameter,omitempty"`
	Payload     string   `json:"payload"`
	Context     string   `json:"context"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	Hash        string   `json:"hash"`
}

// Scanner provides XSS scanning
type Scanner struct {
	httpClient *http.Client
	timeout    time.Duration
	
	payloads []string
}

// ScannerOption configures the XSS scanner
type ScannerOption func(*Scanner)

// WithTimeout sets the scan timeout
func WithTimeout(timeout time.Duration) ScannerOption {
	return func(s *Scanner) {
		s.timeout = timeout
	}
}

// NewScanner creates a new XSS scanner
func NewScanner(opts ...ScannerOption) (*Scanner, error) {
	s := &Scanner{
		timeout: 30 * time.Second,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	
	for _, opt := range opts {
		opt(s)
	}
	
	s.initPayloads()
	return s, nil
}

func (s *Scanner) initPayloads() {
	s.payloads = []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"'><script>alert('XSS')</script>",
		"javascript:alert('XSS')",
	}
}

// ScanTarget scans a URL for XSS vulnerabilities
func (s *Scanner) ScanTarget(targetURL string) []XSSFinding {
	var findings []XSSFinding
	
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return findings
	}
	
	// Test URL parameters
	if parsedURL.RawQuery != "" {
		params := parsedURL.Query()
		for param := range params {
			for _, payload := range s.payloads {
				testURL := injectParameter(targetURL, param, payload)
				
				resp, err := s.httpClient.Get(testURL)
				if err != nil {
					continue
				}
				
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				
				if strings.Contains(string(body), payload) || strings.Contains(string(body), "alert") {
					findings = append(findings, XSSFinding{
						Type:        "Reflected XSS",
						Severity:    "HIGH",
						CVSS:        6.1,
						CWE:         "CWE-79",
						URL:         targetURL,
						Parameter:   param,
						Payload:     payload,
						Context:     "html",
						Evidence:    truncate(string(body), 100),
						Remediation: "Implement proper output encoding",
						References:  []string{"https://owasp.org/www-community/attacks/xss/"},
						Hash:        hashFinding(targetURL, param),
					})
					break
				}
			}
		}
	}
	
	return findings
}

func injectParameter(targetURL, param, value string) string {
	u, _ := url.Parse(targetURL)
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func hashFinding(url, param string) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s", url, param)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Close cleans up resources
func (s *Scanner) Close() error {
	return nil
}

// GenerateReport generates a JSON report
func (s *Scanner) GenerateReport(findings []XSSFinding) ([]byte, error) {
	return json.MarshalIndent(findings, "", "  ")
}