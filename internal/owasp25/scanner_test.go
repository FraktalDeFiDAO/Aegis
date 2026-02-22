package owasp25

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCategoryStrings(t *testing.T) {
	t.Parallel()

	if Injection.String() == "Unknown" {
		t.Fatal("expected concrete category string")
	}
	if Injection.ShortName() == "Unknown" {
		t.Fatal("expected concrete short name")
	}
	if Category(999).String() != "Unknown" {
		t.Fatal("expected unknown category string")
	}
}

func TestScanner_ScanAndStats(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "app.js")
	content := `
const q = "SELECT * FROM users WHERE id = " + $_GET["id"];
eval(userInput);
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	s := NewScanner(dir, WithWorkers(2), WithCategories(Injection))
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].Hash == "" {
		t.Fatal("expected finding hash")
	}

	byCategory := s.GetCategoryStats(findings)
	if byCategory[Injection] == 0 {
		t.Fatal("expected injection findings in stats")
	}

	bySeverity := s.GetSeverityStats(findings)
	if len(bySeverity) == 0 {
		t.Fatal("expected severity stats")
	}

	report := s.Report(findings)
	if !strings.Contains(report, "OWASP Top 25 Security Scan Report") {
		t.Fatalf("unexpected report output: %q", report)
	}
}

func TestScanner_ScanStringAndCategory(t *testing.T) {
	t.Parallel()

	s := NewScanner("", WithCategories(CryptographicFailures))
	findings := s.ScanString(`const x = md5(password);`, "inline.js")
	if len(findings) == 0 {
		t.Fatal("expected findings from ScanString")
	}

	catFindings := s.ScanCategory(`Math.random();`, "inline.js", CryptographicFailures)
	if len(catFindings) == 0 {
		t.Fatal("expected category findings")
	}

	none := s.ScanCategory(`safe code`, "inline.js", Category(999))
	if len(none) != 0 {
		t.Fatalf("expected no findings for invalid category, got %d", len(none))
	}
}

func TestScanner_Helpers(t *testing.T) {
	t.Parallel()

	if got := truncateString("abcdef", 3); got != "abc..." {
		t.Fatalf("unexpected truncateString: %q", got)
	}
	if got := getContext([]string{"a", "b", "c", "d"}, 1); !strings.Contains(got, "b") {
		t.Fatalf("unexpected context: %q", got)
	}
	if !isValidTextFile(".js") {
		t.Fatal("expected .js to be valid")
	}
	if isValidTextFile(".png") {
		t.Fatal("expected .png to be invalid")
	}

	f := Finding{Category: Injection, File: "a.js", Line: 1, Type: "SQL Injection"}
	if h := hashFinding(f); h == "" {
		t.Fatal("expected hashFinding output")
	}

	deduped := deduplicateFindings([]Finding{f, f})
	if len(deduped) != 1 {
		t.Fatalf("expected deduplicated finding count 1, got %d", len(deduped))
	}
}

func TestScanner_AddCustomPattern(t *testing.T) {
	s := NewScanner("")
	orig := CategoryDatabase[Injection]
	defer func() {
		CategoryDatabase[Injection] = orig
	}()

	p := Pattern{
		Name:        "Custom Pattern",
		Regex:       orig.DetectionPatterns[0].Regex,
		Severity:    "LOW",
		CVSS:        1.0,
		CWE:         "CWE-20",
		Description: "custom",
	}
	if err := s.AddCustomPattern(Injection, p); err != nil {
		t.Fatalf("AddCustomPattern returned error: %v", err)
	}
	if err := s.AddCustomPattern(Category(999), p); err == nil {
		t.Fatal("expected invalid category error")
	}
}
