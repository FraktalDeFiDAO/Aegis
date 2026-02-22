// Package scanner provides tools for analyzing mirrored web content for
// security vulnerabilities, secrets, and dangerous patterns.
package scanner

import (
	"crypto/sha256"
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
	Type        string   `json:"type"`        // Type of vulnerability (e.g., "Secret Found", "XSS")
	Severity    string   `json:"severity"`    // Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
	CVSS        float64  `json:"cvss"`        // CVSS v3.1 score (0.0-10.0)
	CWE         string   `json:"cwe"`         // CWE identifier (e.g., "CWE-79")
	File        string   `json:"file"`        // Path to the file containing the finding
	Line        int      `json:"line"`        // Line number where the issue was detected
	Summary     string   `json:"summary"`     // Brief description of the issue
	Value       string   `json:"value"`       // The actual text that triggered the finding
	Remediation string   `json:"remediation"` // Suggested fix
	References  []string `json:"references"`  // External references
	Hash        string   `json:"hash"`        // Unique hash for deduplication
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

	// Deduplicate findings
	findings = deduplicateFindings(findings)

	return findings, nil
}

func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding
	for _, f := range findings {
		// Create hash based on type, summary, and truncated value to deduplicate identical code patterns across files
		hashKey := fmt.Sprintf("%s:%s:%s", f.Type, f.Summary, f.Value)
		hashBytes := sha256.Sum256([]byte(hashKey))
		f.Hash = fmt.Sprintf("%x", hashBytes[:8])
		if !seen[hashKey] {
			seen[hashKey] = true
			unique = append(unique, f)
		}
	}
	return unique
}

func isValidTextFile(ext string) bool {
	ext = strings.ToLower(ext)
	textExtensions := []string{
		// Web files
		".html", ".htm", ".js", ".css", ".json", ".xml", ".txt", ".md",
		// Config files
		".yaml", ".yml", ".conf", ".config", ".env", ".ini", ".toml",
		// Source code
		".php", ".jsp", ".asp", ".aspx", ".py", ".rb", ".go", ".java",
		".cs", ".cpp", ".c", ".h", ".swift", ".kt", ".rs", ".ts", ".jsx", ".tsx",
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

func (s *Scanner) scanContent(content, filePath string) []Finding {
	var findings []Finding
	lines := strings.Split(content, "\n")
	isHTML := strings.HasSuffix(filePath, ".html") || strings.HasSuffix(filePath, ".htm")
	inScript := false

	for lineNum, line := range lines {
		lineLower := strings.ToLower(line)
		lineHasScriptOpen := isHTML && strings.Contains(lineLower, "<script")
		lineHasScriptClose := isHTML && strings.Contains(lineLower, "</script")
		inlineScript := !isHTML || inScript || lineHasScriptOpen

		// Secret Checks
		for desc, pattern := range secretPatterns {
			if match := pattern.FindStringSubmatch(line); len(match) > 1 {
				findings = append(findings, Finding{
					Type:        "Secret Found",
					Severity:    "HIGH",
					CVSS:        7.5,
					CWE:         "CWE-798",
					File:        filePath,
					Line:        lineNum + 1,
					Summary:     fmt.Sprintf("%s detected", desc),
					Value:       truncateString(match[1], 50),
					Remediation: "Remove hardcoded secrets and use environment variables or secret management services",
					References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
				})
			}
		}

		// Vulnerability Checks
		for name, info := range vulnPatterns {
			// Skip JS-specific patterns in HTML unless they are very likely to be inline scripts.
			if isHTML && !inlineScript {
				if name == "DOM-based XSS (innerHTML)" || name == "Insecure Random" {
					continue
				}
			}

			if match := info.regex.FindString(line); match != "" {
				finding := Finding{
					Type:        name,
					Severity:    info.severity,
					CVSS:        info.cvss,
					CWE:         info.cwe,
					File:        filePath,
					Line:        lineNum + 1,
					Summary:     info.desc,
					Value:       truncateString(match, 100),
					Remediation: info.remediation,
					References:  info.references,
				}
				findings = append(findings, finding)
			}
		}

		if isHTML {
			if lineHasScriptOpen {
				inScript = true
			}
			if lineHasScriptClose {
				inScript = false
			}
		}

		// Check for interesting patterns
		for name, info := range interestingPatterns {
			if match := info.regex.FindString(line); match != "" {
				findings = append(findings, Finding{
					Type:        name,
					Severity:    info.severity,
					CVSS:        info.cvss,
					CWE:         info.cwe,
					File:        filePath,
					Line:        lineNum + 1,
					Summary:     info.desc,
					Value:       truncateString(match, 100),
					Remediation: info.remediation,
					References:  info.references,
				})
			}
		}
	}

	return findings
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// Secret Detection Patterns
var secretPatterns = map[string]*regexp.Regexp{
	// API Keys
	"Generic API Key": regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)["\s:=]+[\s]*["']?([A-Za-z0-9_\-]{32,})["']?`),
	"AWS Access Key":  regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
	"AWS Secret Key":  regexp.MustCompile(`(?i)aws[_-]?(?:secret|session)[_-]?key["\s:=]+[\s]*["']?([A-Za-z0-9/+=]{40})["']?`),

	// Tokens
	"JWT Token":    regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
	"Bearer Token": regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.=]{20,})`),
	"OAuth Token":  regexp.MustCompile(`(?i)oauth[_-]?token["\s:=]+[\s]*["']?([a-zA-Z0-9_\-]{20,})["']?`),

	// Cloud Provider Keys
	"Google API Key":  regexp.MustCompile(`(AIza[0-9A-Za-z_-]{35})`),
	"Azure Key":       regexp.MustCompile(`(?i)azure[_-]?key["\s:=]+[\s]*["']?([A-Za-z0-9_\-]{32,})["']?`),
	"GitHub Token":    regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})`),
		"Slack Token":     regexp.MustCompile(`(xox[baprs]-[0-9a-zA-Z-]{10,100})`),
	"Slack Webhook":   regexp.MustCompile(`(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})`),
	"Discord Webhook": regexp.MustCompile(`(https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[a-zA-Z0-9_-]{68})`),
	"Stripe Key":      regexp.MustCompile(`(sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24})`),
	"Private Key":     regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----)`),

	// Database Connection Strings
	"MongoDB URI":    regexp.MustCompile(`(mongodb(?:\+srv)?://[\w\-]+:[\w\-]+@[\w\-.]+)`),
	"PostgreSQL URI": regexp.MustCompile(`(postgres(?:ql)?://[\w\-]+:[\w\-]+@[\w\-.]+)`),
	"MySQL URI":      regexp.MustCompile(`(mysql://[\w\-]+:[\w\-]+@[\w\-.]+)`),

	// Passwords
	"Password Assignment": regexp.MustCompile(`(?i)\b(?:password|pwd|passwd)\s*[=:]\s*["']([^"'\s;]{8,})["']`),
	"Secret Assignment":   regexp.MustCompile(`(?i)\b(?:secret|auth[_-]?token)\s*[=:]\s*["']([^"'\s;]{8,})["']`),
}

// Vulnerability Detection Patterns
type vulnInfo struct {
	regex       *regexp.Regexp
	severity    string
	cvss        float64
	cwe         string
	desc        string
	remediation string
	references  []string
}

var vulnPatterns = map[string]vulnInfo{
	"Eval Usage": {
		regex:       regexp.MustCompile(`(?i)\beval\s*\(`),
		severity:    "HIGH",
		cvss:        8.0,
		cwe:         "CWE-95",
		desc:        "Dangerous eval() usage detected - potential code injection",
		remediation: "Avoid using eval(). Use JSON.parse() for JSON or safer alternatives",
		references:  []string{"https://cwe.mitre.org/data/definitions/95.html"},
	},
	"Unsafe Redirect": {
		regex:       regexp.MustCompile(`(?i)(?:window|document|top|self|location)\.(?:location|href|replace|assign)\s*=`),
		severity:    "HIGH",
		cvss:        7.5,
		cwe:         "CWE-601",
		desc:        "Potential unsafe redirect - may allow open redirect attacks",
		remediation: "Validate and whitelist redirect URLs before assignment",
		references:  []string{"https://cwe.mitre.org/data/definitions/601.html"},
	},
	"Potential XSS (Script Tag)": {
		regex:       regexp.MustCompile(`(?i)<script[^>]*>[^<]*(?:alert|prompt|confirm|console\.log)\s*\(`),
		severity:    "HIGH",
		cvss:        6.1,
		cwe:         "CWE-79",
		desc:        "Potential reflected XSS via script tag",
		remediation: "Sanitize user input and use Content Security Policy (CSP)",
		references:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
	},
	"Potential XSS (Event Handler)": {
		regex:       regexp.MustCompile(`(?i)<[^>]+\s+on\w+\s*=\s*["']?[^"'>\s]+["']?`),
		severity:    "HIGH",
		cvss:        6.1,
		cwe:         "CWE-79",
		desc:        "Potential XSS via event handler",
		remediation: "Sanitize HTML and remove dangerous event handlers",
		references:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
	},
	"DOM-based XSS (innerHTML)": {
		regex:       regexp.MustCompile(`(?i)\.innerHTML\s*=`),
		severity:    "MEDIUM",
		cvss:        5.4,
		cwe:         "CWE-79",
		desc:        "Potential DOM-based XSS via innerHTML assignment",
		remediation: "Use textContent instead of innerHTML for user-controlled data",
		references:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
	},
	"DOM-based XSS (document.write)": {
		regex:       regexp.MustCompile(`(?i)document\.write\s*\(`),
		severity:    "MEDIUM",
		cvss:        5.4,
		cwe:         "CWE-79",
		desc:        "Potential DOM-based XSS via document.write",
		remediation: "Avoid document.write(). Use safer DOM manipulation methods",
		references:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
	},
	"Session in URL": {
		regex:       regexp.MustCompile(`(?i)(?:sid|sessionid|session[_-]?token|auth[_-]?token)=[a-zA-Z0-9\-_]{16,}`),
		severity:    "HIGH",
		cvss:        7.5,
		cwe:         "CWE-598",
		desc:        "Session token exposed in URL - may be logged in browser history/proxies",
		remediation: "Use secure HTTP-only cookies for session management",
		references:  []string{"https://cwe.mitre.org/data/definitions/598.html"},
	},
	"Insecure Cookie (Missing Flags)": {
		regex:       regexp.MustCompile(`(?i)document\.cookie\s*=\s*[^;]*;?[^;]*$`),
		severity:    "MEDIUM",
		cvss:        5.0,
		cwe:         "CWE-614",
		desc:        "Cookie set without Secure or HttpOnly flags",
		remediation: "Always set Secure, HttpOnly, and SameSite flags on cookies",
		references:  []string{"https://cwe.mitre.org/data/definitions/614.html"},
	},
		"SQL Injection Pattern": {
			regex:       regexp.MustCompile(`(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*(?:\$_(?:GET|POST|REQUEST)|req\.|request\.|params|query|db\.)`),
		severity:    "CRITICAL",
		cvss:        9.8,
		cwe:         "CWE-89",
		desc:        "Potential SQL injection - dynamic query construction",
		remediation: "Use parameterized queries or prepared statements",
		references:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
	},
	"Command Injection": {
		regex:       regexp.MustCompile(`(?i)(?:exec|system|shell_exec|popen|proc_open|spawn)\s*\([^)]*(?:\$|req\.|request\.|params)`),
		severity:    "CRITICAL",
		cvss:        9.8,
		cwe:         "CWE-78",
		desc:        "Potential command injection - user input in command execution",
		remediation: "Avoid command execution with user input. Use parameterized APIs",
		references:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
	},
	"Path Traversal": {
		regex:       regexp.MustCompile(`(?i)(?:\.(?:\/|\\)\.{2}|%(?:2e|2E){2}|\.{2}(?:\/|\\)).*(?:req\.|request\.|params)`),
		severity:    "HIGH",
		cvss:        7.5,
		cwe:         "CWE-22",
		desc:        "Potential path traversal vulnerability",
		remediation: "Validate and sanitize file paths, use allowlists",
		references:  []string{"https://cwe.mitre.org/data/definitions/22.html"},
	},
	"SSRF Pattern": {
		regex:       regexp.MustCompile(`(?i)(?:curl|wget|fetch|axios|request)\s*\([^)]*(?:req\.|request\.|params)`),
		severity:    "HIGH",
		cvss:        8.0,
		cwe:         "CWE-918",
		desc:        "Potential SSRF - user input in outbound request",
		remediation: "Validate URLs against allowlist, disable redirects",
		references:  []string{"https://cwe.mitre.org/data/definitions/918.html"},
	},
	"Insecure Random": {
		regex:       regexp.MustCompile(`(?i)Math\.random\s*\(`),
		severity:    "MEDIUM",
		cvss:        5.3,
		cwe:         "CWE-338",
		desc:        "Math.random() used - not cryptographically secure",
		remediation: "Use crypto.getRandomValues() for security-sensitive operations",
		references:  []string{"https://cwe.mitre.org/data/definitions/338.html"},
	},
	"Weak Hash Algorithm": {
		regex:       regexp.MustCompile(`(?i)(?:md5|sha1)\s*\(`),
		severity:    "MEDIUM",
		cvss:        5.3,
		cwe:         "CWE-327",
		desc:        "Weak hash algorithm detected - MD5/SHA1 are cryptographically broken",
		remediation: "Use SHA-256 or stronger for cryptographic operations",
		references:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
	},
	"Hardcoded IP Address": {
		regex:       regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		severity:    "INFO",
		cvss:        0.0,
		cwe:         "CWE-798",
		desc:        "Hardcoded IP address found",
		remediation: "Use DNS names or configuration for IP addresses",
		references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
	},
	"Debug Mode Enabled": {
		regex:       regexp.MustCompile(`(?i)(?:debug\s*=\s*true|DEBUG\s*=\s*True|enableDebug\(\))`),
		severity:    "MEDIUM",
		cvss:        5.3,
		cwe:         "CWE-489",
		desc:        "Debug mode enabled - may expose sensitive information",
		remediation: "Disable debug mode in production environments",
		references:  []string{"https://cwe.mitre.org/data/definitions/489.html"},
	},
	"CORS Misconfiguration": {
		regex:       regexp.MustCompile(`(?i)Access-Control-Allow-Origin["\s:=]*["']?\*["']?`),
		severity:    "MEDIUM",
		cvss:        5.3,
		cwe:         "CWE-942",
		desc:        "Overly permissive CORS - allows any origin",
		remediation: "Specify explicit allowed origins instead of wildcard",
		references:  []string{"https://cwe.mitre.org/data/definitions/942.html"},
	},
	"postMessage Without Origin Check": {
		regex:       regexp.MustCompile(`(?i)window\.addEventListener\s*\(\s*["']message["']\s*,\s*function\s*\([^)]*\)\s*\{[^}]*\}`),
		severity:    "MEDIUM",
		cvss:        5.4,
		cwe:         "CWE-345",
		desc:        "postMessage handler without origin validation",
		remediation: "Always validate event.origin in postMessage handlers",
		references:  []string{"https://cwe.mitre.org/data/definitions/345.html"},
	},
	"Local Storage Sensitive Data": {
		regex:       regexp.MustCompile(`(?i)localStorage\.(?:setItem|\.\w+)\s*\(\s*["'](?:password|token|secret|key|auth)["']\s*,`),
		severity:    "MEDIUM",
		cvss:        5.0,
		cwe:         "CWE-312",
		desc:        "Sensitive data stored in localStorage (not encrypted)",
		remediation: "Use secure HTTP-only cookies or encrypted storage for sensitive data",
		references:  []string{"https://cwe.mitre.org/data/definitions/312.html"},
	},
}

// Interesting Patterns (lower severity but useful for recon)
var interestingPatterns = map[string]vulnInfo{
	"TODO Comment": {
		regex:       regexp.MustCompile(`(?i)(?:TODO|FIXME|XXX|HACK|BUG)[\s:].{10,}`),
		severity:    "INFO",
		cvss:        0.0,
		cwe:         "",
		desc:        "Development comment found - may indicate incomplete functionality",
		remediation: "Review and address before production deployment",
		references:  []string{},
	},
	"Internal Endpoint": {
		regex:       regexp.MustCompile(`(?i)(?:/api/v\d+|/internal/|/admin/|/debug/|/test/|/dev/)`),
		severity:    "INFO",
		cvss:        0.0,
		cwe:         "",
		desc:        "Potential API or internal endpoint reference",
		remediation: "Ensure endpoints are properly secured and not exposed unnecessarily",
		references:  []string{},
	},
	"API Endpoint": {
		regex:       regexp.MustCompile(`(?i)(?:fetch|axios|XMLHttpRequest)\s*\(\s*["']/(?:api|graphql|rest|v\d+)`),
		severity:    "INFO",
		cvss:        0.0,
		cwe:         "",
		desc:        "API endpoint call detected",
		remediation: "Ensure API endpoints implement proper authentication and authorization",
		references:  []string{},
	},
	"Environment Variable Reference": {
		regex:       regexp.MustCompile(`(?i)(?:process\.env|processenv|getenv|os\.environ)`),
		severity:    "INFO",
		cvss:        0.0,
		cwe:         "",
		desc:        "Environment variable access detected",
		remediation: "Ensure environment variables are properly validated",
		references:  []string{},
	},
}
