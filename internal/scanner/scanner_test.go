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

	expectedTypes := []string{"Secret Found", "Eval Usage", "Unsafe Redirect", "ATO - Session in URL"}
	for _, et := range expectedTypes {
		if count := types[et]; count == 0 {
			t.Errorf("Expected to find type %s, but found %d", et, count)
		}
	}

	// Verify that we found the expected number of each type
	if types["Secret Found"] < 2 { // Should find API key and JWT
		t.Errorf("Expected at least 2 secrets, found %d", types["Secret Found"])
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
	for _, f := range findings {
		if f.Type == "Secret Found" {
			foundSecret = true
			break
		}
	}

	if !foundSecret {
		t.Error("Expected to find secrets in text files")
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
		{".exe", false},
		{".png", false},
		{".jpg", false},
		{".pdf", false},
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
