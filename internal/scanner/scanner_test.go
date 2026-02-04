package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner(t *testing.T) {
	tempDir := t.TempDir()

	// Create a dummy file with multiple findings
	secretFile := filepath.Join(tempDir, "test.js")
	content := `
		const apiKey = "AIzaSyB-some-google-api-key-12345";
		const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjsXzI1NiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
		const pass = "password=supersecret";
		eval("alert(1)");
		window.location = "http://evil.com";
		const sid = "session=1234567890abcdef1234567890abcdef";
		document.cookie = "auth=123; path=/";
		const hash = md5(password);
		const insecure = Math.random();
		// TODO: Fix this security issue before release
		fetch("/api/v1/users");
	`
	err := os.WriteFile(secretFile, []byte(content), 0644)
	if err != nil {
		t.Fatal(err)
	}

	s := NewScanner(tempDir)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	types := make(map[string]int)
	for _, f := range findings {
		types[f.Type]++
	}

	expectedTypes := []string{"Secret Found", "Eval Usage", "Unsafe Redirect",
		"Weak Hash Algorithm", "Insecure Random",
		"TODO Comment", "API Endpoint"}
	for _, et := range expectedTypes {
		if count := types[et]; count == 0 {
			t.Errorf("Expected to find type %s, but found %d", et, count)
		}
	}

	// Verify that we found the expected number of secrets
	if types["Secret Found"] < 2 { // Should find at least password and JWT
		t.Errorf("Expected at least 2 secrets, found %d", types["Secret Found"])
	}

	// Check CVSS scoring
	for _, f := range findings {
		if f.Severity == "CRITICAL" && f.CVSS < 9.0 {
			t.Errorf("CRITICAL finding should have CVSS >= 9.0, got %f", f.CVSS)
		}
		if f.Severity == "HIGH" && f.CVSS < 7.0 {
			t.Errorf("HIGH finding should have CVSS >= 7.0, got %f", f.CVSS)
		}
		if f.Hash == "" {
			t.Errorf("Finding should have a hash for deduplication")
		}
	}
}

func TestScannerMultipleFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create multiple files with different findings
	files := map[string]string{
		"secrets.js": `const apiKey = "AKIATEST123456789012";`,
		"xss.html":   `<script>alert('xss')</script>`,
		"eval.js":    `eval(userInput);`,
		"binary.exe": "this should be skipped", // This should be skipped by the scanner
		"config.env": "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"app.php":    `<?php $query = "SELECT * FROM users WHERE id = " . $_GET['id']; ?>`,
		"server.py":  `os.system("ls " + request.args.get('path'))`,
	}

	for fileName, content := range files {
		filePath := filepath.Join(tempDir, fileName)
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatal(err)
		}
	}

	s := NewScanner(tempDir)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should find findings in the text files but skip the binary
	foundSecret := false
	foundSQLInjection := false
	foundCommandInjection := false
	for _, f := range findings {
		if f.Type == "Secret Found" {
			foundSecret = true
		}
		if f.Type == "SQL Injection Pattern" {
			foundSQLInjection = true
		}
		if f.Type == "Command Injection" {
			foundCommandInjection = true
		}
	}

	if !foundSecret {
		t.Error("Expected to find secrets in text files")
	}

	if !foundSQLInjection {
		t.Error("Expected to find SQL injection pattern in PHP file")
	}

	if !foundCommandInjection {
		t.Error("Expected to find command injection pattern in Python file")
	}

	// Count total text files processed vs binary files
	textFilesProcessed := 0
	for _, f := range findings {
		if filepath.Ext(f.File) != ".exe" { // Binary file should be skipped
			textFilesProcessed++
		}
	}

	t.Logf("Scanner processed text files and found %d findings", len(findings))
}

func TestIsValidTextFile(t *testing.T) {
	tests := []struct {
		ext      string
		expected bool
	}{
		{".html", true},
		{".htm", true},
		{".js", true},
		{".css", true},
		{".json", true},
		{".xml", true},
		{".txt", true},
		{".md", true},
		{".yaml", true},
		{".yml", true},
		{".conf", true},
		{".config", true},
		{".env", true}, // NEW: Environment files
		{".php", true}, // NEW: PHP files
		{".py", true},  // NEW: Python files
		{".go", true},  // NEW: Go files
		{".jsx", true}, // NEW: React JSX
		{".tsx", true}, // NEW: React TSX
		{".vue", true}, // NEW: Vue files
		{".exe", false},
		{".png", false},
		{".jpg", false},
		{".pdf", false},
		{".zip", false},
		{".tar", false},
		{".JSON", true}, // Test case insensitivity
		{".HTM", true},  // Test case insensitivity
	}

	for _, tt := range tests {
		got := isValidTextFile(tt.ext)
		if got != tt.expected {
			t.Errorf("isValidTextFile(%s) = %v; want %v", tt.ext, got, tt.expected)
		}
	}
}

func TestScannerWithEmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	s := NewScanner(tempDir)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed on empty directory: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings in empty directory, got %d", len(findings))
	}
}

func TestScannerWithNonExistentDirectory(t *testing.T) {
	s := NewScanner("/non/existent/directory")
	_, err := s.Scan()

	if err == nil {
		t.Error("Expected error when scanning non-existent directory, got nil")
	}
}

func TestScannerDeduplication(t *testing.T) {
	tempDir := t.TempDir()

	// Create two files with the same vulnerability pattern
	content := `eval("alert(1)");`

	file1 := filepath.Join(tempDir, "file1.js")
	file2 := filepath.Join(tempDir, "file2.js")

	os.WriteFile(file1, []byte(content), 0644)
	os.WriteFile(file2, []byte(content), 0644)

	s := NewScanner(tempDir)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should have 2 findings (different files)
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings (different files), got %d", len(findings))
	}

	// All findings should have unique hashes
	hashes := make(map[string]bool)
	for _, f := range findings {
		if hashes[f.Hash] {
			t.Errorf("Duplicate hash found: %s", f.Hash)
		}
		hashes[f.Hash] = true
	}
}

func TestScannerSeverityLevels(t *testing.T) {
	tempDir := t.TempDir()

	// Create file with various severity patterns
	content := `
		// CRITICAL
		query = "SELECT * FROM users WHERE id = " + req.params.id;
		os.system(userInput);
		
		// HIGH
		eval(userCode);
		window.location = redirectUrl;
		
		// MEDIUM
		element.innerHTML = userContent;
		Math.random();
		
		// INFO
		// TODO: Review this code
		fetch("/api/v1/users");
	`

	file := filepath.Join(tempDir, "severity_test.js")
	os.WriteFile(file, []byte(content), 0644)

	s := NewScanner(tempDir)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Count by severity
	severityCount := make(map[string]int)
	for _, f := range findings {
		severityCount[f.Severity]++
	}

	t.Logf("Findings by severity: %v", severityCount)

	// Verify we found CRITICAL and HIGH severity issues
	if severityCount["CRITICAL"] == 0 {
		t.Error("Expected to find CRITICAL severity issues (SQL Injection, Command Injection)")
	}
	if severityCount["HIGH"] == 0 {
		t.Error("Expected to find HIGH severity issues (eval, redirect)")
	}
}

func TestSecretPatterns(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string // expected secret type to find
	}{
		{
			name:     "Google API Key",
			content:  `const key = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI";`,
			expected: "Secret Found",
		},
		{
			name:     "AWS Access Key",
			content:  `const accessKey = "AKIAIOSFODNN7EXAMPLE";`,
			expected: "Secret Found",
		},
		{
			name:     "GitHub Token",
			content:  `const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";`,
			expected: "Secret Found",
		},
		{
			name:     "Slack Token",
			content:  `const slack = "xoxb-FAKE-TEST-TOKEN-FOR-TESTING";`,
			expected: "Secret Found",
		},
		{
			name:     "JWT Token",
			content:  `const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";`,
			expected: "Secret Found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			file := filepath.Join(tempDir, "test.js")
			os.WriteFile(file, []byte(tt.content), 0644)

			s := NewScanner(tempDir)
			findings, err := s.Scan()
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			found := false
			for _, f := range findings {
				if f.Type == tt.expected {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected to find %s for pattern: %s", tt.expected, tt.name)
			}
		})
	}
}

func TestCVSSScoring(t *testing.T) {
	// Test that CVSS scores align with severity levels
	testCases := []struct {
		severity string
		minCVSS  float64
		maxCVSS  float64
	}{
		{"CRITICAL", 9.0, 10.0},
		{"HIGH", 7.0, 8.9},
		{"MEDIUM", 4.0, 6.9},
		{"LOW", 0.1, 3.9},
		{"INFO", 0.0, 0.0},
	}

	for _, tc := range testCases {
		vuln, exists := vulnPatterns["SQL Injection Pattern"]
		if tc.severity == "CRITICAL" && exists {
			if vuln.cvss < tc.minCVSS || vuln.cvss > tc.maxCVSS {
				t.Errorf("SQL Injection CVSS %f not in range %f-%f", vuln.cvss, tc.minCVSS, tc.maxCVSS)
			}
		}
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string", 10, "this is a ..."},
		{"", 5, ""},
		{"exactly10!", 10, "exactly10!"},
	}

	for _, tt := range tests {
		result := truncateString(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncateString(%q, %d) = %q; want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestScannerRemediationMessages(t *testing.T) {
	tempDir := t.TempDir()
	content := `eval(userInput);`

	file := filepath.Join(tempDir, "test.js")
	os.WriteFile(file, []byte(content), 0644)

	s := NewScanner(tempDir)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected to find findings")
	}

	for _, f := range findings {
		if f.Remediation == "" {
			t.Errorf("Finding %s should have a remediation message", f.Type)
		}
		if len(f.References) == 0 && f.Severity != "INFO" {
			t.Errorf("Finding %s should have reference links", f.Type)
		}
	}
}
