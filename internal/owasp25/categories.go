// Package owasp25 provides structured scanning for the OWASP Top 25 vulnerabilities.
// https://owasp.org/www-project-top-ten/
package owasp25

import (
	"regexp"
)

// Category represents an OWASP Top 10/25 category
 type Category int

const (
	// OWASP Top 10 2021 Categories
	BrokenAccessControl Category = iota
	CryptographicFailures
	Injection
	InsecureDesign
	SecurityMisconfiguration
	VulnerableComponents
	AuthFailures
	IntegrityFailures
	LoggingFailures
	SSRF
	
	// Additional Top 25 Categories
	BufferOverflow
	XXE
	RaceConditions
	APIVulnerabilities
	MobileVulnerabilities
	CloudSecurity
	IoTSecurity
)

func (c Category) String() string {
	switch c {
	case BrokenAccessControl:
		return "A01:2021-Broken Access Control"
	case CryptographicFailures:
		return "A02:2021-Cryptographic Failures"
	case Injection:
		return "A03:2021-Injection"
	case InsecureDesign:
		return "A04:2021-Insecure Design"
	case SecurityMisconfiguration:
		return "A05:2021-Security Misconfiguration"
	case VulnerableComponents:
		return "A06:2021-Vulnerable and Outdated Components"
	case AuthFailures:
		return "A07:2021-Identification and Authentication Failures"
	case IntegrityFailures:
		return "A08:2021-Software and Data Integrity Failures"
	case LoggingFailures:
		return "A09:2021-Security Logging and Monitoring Failures"
	case SSRF:
		return "A10:2021-Server-Side Request Forgery"
	case BufferOverflow:
		return "CWE-120: Buffer Overflow"
	case XXE:
		return "CWE-611: XML External Entity"
	case RaceConditions:
		return "CWE-362: Race Condition"
	case APIVulnerabilities:
		return "API Security Top 10"
	case MobileVulnerabilities:
		return "Mobile Top 10"
	case CloudSecurity:
		return "Cloud Security"
	case IoTSecurity:
		return "IoT Security"
	default:
		return "Unknown"
	}
}

func (c Category) ShortName() string {
	switch c {
	case BrokenAccessControl:
		return "BrokenAccessControl"
	case CryptographicFailures:
		return "CryptographicFailures"
	case Injection:
		return "Injection"
	case InsecureDesign:
		return "InsecureDesign"
	case SecurityMisconfiguration:
		return "SecurityMisconfiguration"
	case VulnerableComponents:
		return "VulnerableComponents"
	case AuthFailures:
		return "AuthFailures"
	case IntegrityFailures:
		return "IntegrityFailures"
	case LoggingFailures:
		return "LoggingFailures"
	case SSRF:
		return "SSRF"
	case BufferOverflow:
		return "BufferOverflow"
	case XXE:
		return "XXE"
	case RaceConditions:
		return "RaceConditions"
	case APIVulnerabilities:
		return "APIVulnerabilities"
	case MobileVulnerabilities:
		return "MobileVulnerabilities"
	case CloudSecurity:
		return "CloudSecurity"
	case IoTSecurity:
		return "IoTSecurity"
	default:
		return "Unknown"
	}
}

// CategoryInfo provides detailed information about each category
 type CategoryInfo struct {
	Category        Category
	OWASPRank       int
	CWEs            []string
	CommonAttacks   []string
	DetectionPatterns []Pattern
	Remediation     string
	CVSSRange       struct {
		Min float64
		Max float64
	}
}

// Pattern combines a regex with metadata
 type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Severity    string
	CVSS        float64
	CWE         string
	Description string
	Remediation string
	References  []string
}

// CategoryDatabase holds all OWASP category definitions
 var CategoryDatabase = map[Category]CategoryInfo{
	BrokenAccessControl: {
		Category:  BrokenAccessControl,
		OWASPRank: 1,
		CWEs:      []string{"CWE-22", "CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-639", "CWE-798"},
		CommonAttacks: []string{
			"IDOR (Insecure Direct Object Reference)",
			"Path Traversal",
			"Privilege Escalation",
			"Force Browsing",
			"JWT Token Manipulation",
			"CORS Misconfiguration",
		},
		DetectionPatterns: []Pattern{
			{
				Name:        "IDOR Pattern",
				Regex:       regexp.MustCompile(`(?i)(\.get\(|\.find\(|\.query\()\s*[^)]*(req\.|request\.|params|query|id\s*=)`),
				Severity:    "HIGH",
				CVSS:        8.1,
				CWE:         "CWE-639",
				Description: "Potential IDOR - user input directly used in data access",
				Remediation: "Implement proper authorization checks before data access",
				References:  []string{"https://cwe.mitre.org/data/definitions/639.html"},
			},
			{
				Name:        "Path Traversal",
				Regex:       regexp.MustCompile(`(?i)(?:\.\./|\.\.\\\\|%(?:2e|2E){2}|%(?:5c|5C)).*(?:req\.|request\.|params|query)`),
				Severity:    "HIGH",
				CVSS:        7.5,
				CWE:         "CWE-22",
				Description: "Potential path traversal vulnerability",
				Remediation: "Validate and sanitize file paths, use allowlists",
				References:  []string{"https://cwe.mitre.org/data/definitions/22.html"},
			},
			{
				Name:        "CORS Wildcard",
				Regex:       regexp.MustCompile(`(?i)Access-Control-Allow-Origin["\s:=]*["']?\*["']?`),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-942",
				Description: "Overly permissive CORS allowing any origin",
				Remediation: "Specify explicit allowed origins instead of wildcard",
				References:  []string{"https://cwe.mitre.org/data/definitions/942.html"},
			},
		},
		Remediation: "Implement proper access control, deny by default, enforce ownership",
		CVSSRange: struct {
			Min float64
			Max float64
		}{5.0, 10.0},
	},
	
	CryptographicFailures: {
		Category:  CryptographicFailures,
		OWASPRank: 2,
		CWEs:      []string{"CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-326", "CWE-327", "CWE-328", "CWE-547", "CWE-916"},
		CommonAttacks: []string{
			"Weak Hash Cracking",
			"Downgrade Attacks",
			"Weak Key Recovery",
			"Padding Oracle",
		},
		DetectionPatterns: []Pattern{
			{
				Name:        "Weak Hash MD5",
				Regex:       regexp.MustCompile(`(?i)md5\s*\(`),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-327",
				Description: "MD5 is cryptographically broken",
				Remediation: "Use SHA-256 or stronger for cryptographic operations",
				References:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
			},
			{
				Name:        "Weak Hash SHA1",
				Regex:       regexp.MustCompile(`(?i)sha1\s*\(`),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-327",
				Description: "SHA1 is cryptographically broken",
				Remediation: "Use SHA-256 or stronger for cryptographic operations",
				References:  []string{"https://cwe.mitre.org/data/definitions/327.html"},
			},
			{
				Name:        "Insecure Random",
				Regex:       regexp.MustCompile(`(?i)Math\.random\s*\(`),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-338",
				Description: "Math.random() not cryptographically secure",
				Remediation: "Use crypto.getRandomValues() for security operations",
				References:  []string{"https://cwe.mitre.org/data/definitions/338.html"},
			},
			{
				Name:        "Hardcoded Password",
				Regex:       regexp.MustCompile(`(?i)(?:password|pwd|passwd)\s*[=:]\s*["']?([^"'\s;]{8,})["']?`),
				Severity:    "HIGH",
				CVSS:        7.5,
				CWE:         "CWE-798",
				Description: "Hardcoded password detected",
				Remediation: "Use environment variables or secret management",
				References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			},
		},
		Remediation: "Encrypt data at rest and in transit, use strong algorithms, proper key management",
		CVSSRange: struct {
			Min float64
			Max float64
		}{5.0, 9.8},
	},
	
	Injection: {
		Category:  Injection,
		OWASPRank: 3,
		CWEs:      []string{"CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-117", "CWE-564", "CWE-917"},
		CommonAttacks: []string{
			"SQL Injection",
			"NoSQL Injection",
			"Command Injection",
			"LDAP Injection",
			"XPath Injection",
			"Template Injection",
			"Log Injection",
		},
		DetectionPatterns: []Pattern{
			{
				Name:        "SQL Injection",
				Regex:       regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC|SCRIPT).*\$(?:_|\{)?(?:GET|POST|REQUEST|QUERY|PARAMS|BODY)`),
				Severity:    "CRITICAL",
				CVSS:        9.8,
				CWE:         "CWE-89",
				Description: "Potential SQL injection vulnerability",
				Remediation: "Use parameterized queries or prepared statements",
				References:  []string{"https://cwe.mitre.org/data/definitions/89.html"},
			},
			{
				Name:        "Command Injection",
				Regex:       regexp.MustCompile(`(?i)(?:exec|system|shell_exec|popen|proc_open|spawn)\s*\([^)]*\$(?:_|\{)?(?:GET|POST|REQUEST|QUERY|PARAMS|BODY)`),
				Severity:    "CRITICAL",
				CVSS:        9.8,
				CWE:         "CWE-78",
				Description: "Potential command injection vulnerability",
				Remediation: "Avoid command execution with user input",
				References:  []string{"https://cwe.mitre.org/data/definitions/78.html"},
			},
			{
				Name:        "XSS Script Tag",
				Regex:       regexp.MustCompile(`(?i)<script[^>]*>[^<]*(?:alert|prompt|confirm|console\.log)\s*\(`),
				Severity:    "HIGH",
				CVSS:        6.1,
				CWE:         "CWE-79",
				Description: "Potential reflected XSS via script tag",
				Remediation: "Sanitize user input, use Content Security Policy",
				References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
			},
			{
				Name:        "XSS Event Handler",
				Regex:       regexp.MustCompile(`(?i)<[^>]+\s+on\w+\s*=\s*["']?[^"'>\s]+["']?`),
				Severity:    "HIGH",
				CVSS:        6.1,
				CWE:         "CWE-79",
				Description: "Potential XSS via event handler",
				Remediation: "Sanitize HTML, remove dangerous event handlers",
				References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
			},
			{
				Name:        "DOM XSS innerHTML",
				Regex:       regexp.MustCompile(`(?i)\.innerHTML\s*=`),
				Severity:    "MEDIUM",
				CVSS:        5.4,
				CWE:         "CWE-79",
				Description: "Potential DOM-based XSS via innerHTML",
				Remediation: "Use textContent instead of innerHTML",
				References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
			},
			{
				Name:        "Eval Usage",
				Regex:       regexp.MustCompile(`(?i)\beval\s*\(`),
				Severity:    "HIGH",
				CVSS:        8.0,
				CWE:         "CWE-95",
				Description: "Dangerous eval() usage detected",
				Remediation: "Avoid eval(), use JSON.parse() for JSON",
				References:  []string{"https://cwe.mitre.org/data/definitions/95.html"},
			},
		},
		Remediation: "Use parameterized queries, input validation, output encoding, safe APIs",
		CVSSRange: struct {
			Min float64
			Max float64
		}{5.4, 10.0},
	},
	
	SecurityMisconfiguration: {
		Category:  SecurityMisconfiguration,
		OWASPRank: 5,
		CWEs:      []string{"CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-209", "CWE-215", "CWE-548", "CWE-611", "CWE-614", "CWE-756", "CWE-776"},
		CommonAttacks: []string{
			"Default Credentials",
			"Unnecessary Features Enabled",
			"Directory Listing",
			"Information Disclosure",
			"Stack Traces in Production",
		},
		DetectionPatterns: []Pattern{
			{
				Name:        "Debug Mode",
				Regex:       regexp.MustCompile(`(?i)(?:debug\s*=\s*true|DEBUG\s*=\s*True|enableDebug\(\))`),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-489",
				Description: "Debug mode enabled in production",
				Remediation: "Disable debug mode in production",
				References:  []string{"https://cwe.mitre.org/data/definitions/489.html"},
			},
			{
				Name:        "Stack Trace Disclosure",
				Regex:       regexp.MustCompile(`(?i)(?:stack.?trace|exception|error.?details).*\$\{`),
				Severity:    "MEDIUM",
				CVSS:        5.3,
				CWE:         "CWE-209",
				Description: "Potential stack trace disclosure",
				Remediation: "Implement proper error handling, hide detailed errors in production",
				References:  []string{"https://cwe.mitre.org/data/definitions/209.html"},
			},
			{
				Name:        "Insecure Cookie",
				Regex:       regexp.MustCompile(`(?i)document\.cookie\s*=\s*[^;]*;?[^;]*$`),
				Severity:    "MEDIUM",
				CVSS:        5.0,
				CWE:         "CWE-614",
				Description: "Cookie set without Secure or HttpOnly flags",
				Remediation: "Always set Secure, HttpOnly, and SameSite flags",
				References:  []string{"https://cwe.mitre.org/data/definitions/614.html"},
			},
		},
		Remediation: "Harden configurations, minimal platform, automated hardening",
		CVSSRange: struct {
			Min float64
			Max float64
		}{4.0, 8.0},
	},
	
	AuthFailures: {
		Category:  AuthFailures,
		OWASPRank: 7,
		CWEs:      []string{"CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-522", "CWE-613"},
		CommonAttacks: []string{
			"Credential Stuffing",
			"Brute Force",
			"Session Hijacking",
			"Weak Password Policy",
			"Missing MFA",
		},
		DetectionPatterns: []Pattern{
			{
				Name:        "Session in URL",
				Regex:       regexp.MustCompile(`(?i)(?:sid|sessionid|session[_-]?token|auth[_-]?token)=[a-zA-Z0-9\-_]{16,}`),
				Severity:    "HIGH",
				CVSS:        7.5,
				CWE:         "CWE-598",
				Description: "Session token exposed in URL",
				Remediation: "Use secure HTTP-only cookies for sessions",
				References:  []string{"https://cwe.mitre.org/data/definitions/598.html"},
			},
			{
				Name:        "Weak JWT Secret",
				Regex:       regexp.MustCompile(`(?i)(?:jwt|secret|signature)\s*[=:]\s*["']?([a-zA-Z0-9]{0,20})["']?`),
				Severity:    "CRITICAL",
				CVSS:        9.8,
				CWE:         "CWE-798",
				Description: "Potentially weak JWT secret",
				Remediation: "Use strong, random JWT secrets (256+ bits)",
				References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			},
		},
		Remediation: "Implement MFA, strong password policy, session management, brute force protection",
		CVSSRange: struct {
			Min float64
			Max float64
		}{5.0, 9.8},
	},
	
	SSRF: {
		Category:  SSRF,
		OWASPRank: 10,
		CWEs:      []string{"CWE-918"},
		CommonAttacks: []string{
			"Internal Port Scanning",
			"Cloud Metadata Access",
			"Internal API Access",
			"File:// Protocol Abuse",
		},
		DetectionPatterns: []Pattern{
			{
				Name:        "SSRF Pattern",
				Regex:       regexp.MustCompile(`(?i)(?:curl|wget|fetch|axios|request)\s*\([^)]*(?:req\.|request\.|params|query)`),
				Severity:    "HIGH",
				CVSS:        8.0,
				CWE:         "CWE-918",
				Description: "Potential SSRF - user input in outbound request",
				Remediation: "Validate URLs against allowlist, disable redirects",
				References:  []string{"https://cwe.mitre.org/data/definitions/918.html"},
			},
			{
				Name:        "Internal IP Access",
				Regex:       regexp.MustCompile(`(?i)(?:http|https|ftp|file)://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|::1|0:0:0:0:0:0:0:1)`),
				Severity:    "MEDIUM",
				CVSS:        6.5,
				CWE:         "CWE-918",
				Description: "Potential SSRF to internal addresses",
				Remediation: "Block requests to internal IP ranges",
				References:  []string{"https://cwe.mitre.org/data/definitions/918.html"},
			},
		},
		Remediation: "Validate URLs, enforce schema allowlist, disable unnecessary protocols",
		CVSSRange: struct {
			Min float64
			Max float64
		}{5.0, 9.8},
	},
}

// GetCategoryInfo returns category information by category
 func GetCategoryInfo(cat Category) (CategoryInfo, bool) {
	info, ok := CategoryDatabase[cat]
	return info, ok
}

// GetAllCategories returns all defined categories
 func GetAllCategories() []Category {
	return []Category{
		BrokenAccessControl,
		CryptographicFailures,
		Injection,
		InsecureDesign,
		SecurityMisconfiguration,
		VulnerableComponents,
		AuthFailures,
		IntegrityFailures,
		LoggingFailures,
		SSRF,
	}
}

// CategoryFromCWE returns the OWASP category that contains a given CWE
 func CategoryFromCWE(cwe string) (Category, bool) {
	for cat, info := range CategoryDatabase {
		for _, c := range info.CWEs {
			if c == cwe {
				return cat, true
			}
		}
	}
	return -1, false
}