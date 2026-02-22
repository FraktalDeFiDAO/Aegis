// Package integration provides the unified security scanner
package integration

import (
	"fmt"
	"sync"

	"github.com/coppertone/bug-hunter/app/aegis/internal/content"
	"github.com/coppertone/bug-hunter/app/aegis/internal/exploitable"
	"github.com/coppertone/bug-hunter/app/aegis/internal/owasp25"
	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
)

// UnifiedFinding represents a finding from any scanner type
type UnifiedFinding struct {
	Category      string   `json:"category"`
	Type          string   `json:"type"`
	Severity      string   `json:"severity"`
	CVSS          float64  `json:"cvss"`
	CWE           string   `json:"cwe,omitempty"`
	CVE           string   `json:"cve,omitempty"`
	Host          string   `json:"host,omitempty"`
	Port          int      `json:"port,omitempty"`
	URL           string   `json:"url,omitempty"`
	File          string   `json:"file,omitempty"`
	Line          int      `json:"line,omitempty"`
	Summary       string   `json:"summary"`
	Details       string   `json:"details"`
	Remediation   string   `json:"remediation"`
	References    []string `json:"references,omitempty"`
	OWASPCategory string   `json:"owasp_category,omitempty"`
}

// Target represents a scan target
type Target struct {
	URL       string
	Host      string
	Ports     []int
	Depth     int
	AuthToken string
}

// UnifiedScanner orchestrates all scanning capabilities
type UnifiedScanner struct {
	exploitableScanner *exploitable.Scanner
	owaspScanner       *owasp25.Scanner
	platformDetector   *platform.Detector
	contentAcquirer    *content.Acquirer

	enableExploitable bool
	enableOWASP       bool
	enableContent     bool
}

// NewUnifiedScanner creates a new unified scanner
func NewUnifiedScanner(opts ...func(*UnifiedScanner)) (*UnifiedScanner, error) {
	s := &UnifiedScanner{
		enableExploitable: true,
		enableOWASP:       true,
		enableContent:     true,
	}

	for _, opt := range opts {
		opt(s)
	}

	if s.enableExploitable {
		s.exploitableScanner = exploitable.NewScanner()
	}

	if s.enableOWASP {
		s.owaspScanner = owasp25.NewScanner("")
	}

	if s.enableContent {
		acquirer, err := content.NewAcquirer()
		if err != nil {
			return nil, fmt.Errorf("failed to create content acquirer: %w", err)
		}
		s.contentAcquirer = acquirer
	}

	s.platformDetector = platform.NewDetector(30)

	return s, nil
}

// ScanTarget performs a comprehensive scan of a target
func (s *UnifiedScanner) ScanTarget(target Target) ([]UnifiedFinding, error) {
	var allFindings []UnifiedFinding
	var mu sync.Mutex
	var wg sync.WaitGroup

	if s.enableExploitable && len(target.Ports) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings := s.scanExploitable(target)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}()
	}

	if s.enableContent && target.URL != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings := s.scanContentAndOWASP(target)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	return allFindings, nil
}

func (s *UnifiedScanner) scanExploitable(target Target) []UnifiedFinding {
	var findings []UnifiedFinding

	if target.Host == "" {
		return findings
	}

	// Scan Redis
	redisFindings := s.exploitableScanner.ScanRedis(target.Host, target.Ports)
	for _, finding := range redisFindings {
		findings = append(findings, UnifiedFinding{
			Category:    "exploitable",
			Type:        finding.Type,
			Severity:    finding.Severity,
			CVSS:        finding.CVSS,
			CWE:         finding.CWE,
			CVE:         finding.CVE,
			Host:        finding.Host,
			Port:        finding.Port,
			Summary:     finding.Summary,
			Details:     finding.Details,
			Remediation: finding.Remediation,
			References:  finding.References,
		})
	}

	// Scan MongoDB
	mongoFindings := s.exploitableScanner.ScanMongoDB(target.Host, target.Ports)
	for _, finding := range mongoFindings {
		findings = append(findings, UnifiedFinding{
			Category:    "exploitable",
			Type:        finding.Type,
			Severity:    finding.Severity,
			CVSS:        finding.CVSS,
			CWE:         finding.CWE,
			CVE:         finding.CVE,
			Host:        finding.Host,
			Port:        finding.Port,
			Summary:     finding.Summary,
			Details:     finding.Details,
			Remediation: finding.Remediation,
			References:  finding.References,
		})
	}

	return findings
}

func (s *UnifiedScanner) scanContentAndOWASP(target Target) []UnifiedFinding {
	var findings []UnifiedFinding

	acquiredContent, err := s.contentAcquirer.Acquire(target.URL)
	if err != nil {
		return findings
	}

	detection, err := s.platformDetector.Detect(target.URL)
	if err == nil {
		for _, fw := range detection.Frameworks {
			findings = append(findings, UnifiedFinding{
				Category: "platform",
				Type:     "Framework Detected",
				Severity: "INFO",
				CVSS:     0.0,
				URL:      target.URL,
				Summary:  fmt.Sprintf("Detected %s framework", fw.Name),
				Details:  fmt.Sprintf("Framework: %s, Version: %s", fw.Name, fw.Version),
			})
		}
	}

	if s.enableOWASP {
		owaspFindings := s.owaspScanner.ScanString(acquiredContent.HTML, target.URL)
		for _, f := range owaspFindings {
			findings = append(findings, UnifiedFinding{
				Category:      "owasp25",
				Type:          f.Type,
				Severity:      f.Severity,
				CVSS:          f.CVSS,
				CWE:           f.CWE,
				URL:           target.URL,
				File:          f.File,
				Line:          f.Line,
				Summary:       f.Summary,
				Details:       f.Value,
				Remediation:   f.Remediation,
				References:    f.References,
				OWASPCategory: f.Category.String(),
			})
		}
	}

	return findings
}

// Close cleans up resources
func (s *UnifiedScanner) Close() error {
	if s.contentAcquirer != nil {
		s.contentAcquirer.Close()
	}
	return nil
}