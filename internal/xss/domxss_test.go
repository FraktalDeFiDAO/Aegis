package xss

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewDOMXSSAnalyzerWithConfig_InvalidPath(t *testing.T) {
	t.Parallel()

	if _, err := NewDOMXSSAnalyzerWithConfig("/does/not/exist.yaml"); err == nil {
		t.Fatal("expected error for invalid config path")
	}
}

func TestDOMXSSAnalyzer_AnalyzeContentAndFile(t *testing.T) {
	t.Parallel()

	a, err := NewDOMXSSAnalyzer()
	if err != nil {
		t.Fatalf("NewDOMXSSAnalyzer returned error: %v", err)
	}

	content := `
const source = location.hash;
document.body.innerHTML = source;
document.body.innerHTML = "safe";
`
	findings := a.AnalyzeContent(content, "inline.js")
	if len(findings) == 0 {
		t.Fatal("expected DOM XSS findings")
	}

	foundSource := false
	foundSink := false
	for _, f := range findings {
		if f.PatternType == "source" {
			foundSource = true
		}
		if f.PatternType == "sink" {
			foundSink = true
		}
	}
	if !foundSource || !foundSink {
		t.Fatalf("expected both source and sink findings, got %+v", findings)
	}
}

func TestDOMXSSAnalyzer_AnalyzeDirectoryAndPayloads(t *testing.T) {
	t.Parallel()

	a, err := NewDOMXSSAnalyzer()
	if err != nil {
		t.Fatalf("NewDOMXSSAnalyzer returned error: %v", err)
	}

	dir := t.TempDir()
	jsFile := filepath.Join(dir, "app.js")
	txtFile := filepath.Join(dir, "notes.txt")
	js := []byte("const x = location.search;\ndocument.write(x);")
	if err := os.WriteFile(jsFile, js, 0o644); err != nil {
		t.Fatalf("write js file: %v", err)
	}
	if err := os.WriteFile(txtFile, []byte("ignored"), 0o644); err != nil {
		t.Fatalf("write txt file: %v", err)
	}

	report, err := a.AnalyzeDirectory(dir)
	if err != nil {
		t.Fatalf("AnalyzeDirectory returned error: %v", err)
	}
	if report.FilesScanned != 1 {
		t.Fatalf("expected 1 scanned file, got %d", report.FilesScanned)
	}
	if report.TotalFlows == 0 {
		t.Fatal("expected at least one source/sink flow")
	}

	if len(a.GetPayloads("basic")) == 0 {
		t.Fatal("expected basic payloads")
	}
	if len(a.GetPayloads("all")) == 0 {
		t.Fatal("expected all payloads")
	}
}

func TestDOMXSSHelpers(t *testing.T) {
	t.Parallel()

	if !isStaticLiteralAssignment(`el.innerHTML = "safe";`, len("el.innerHTML")) {
		t.Fatal("expected static literal assignment detection")
	}
	if isStaticLiteralAssignment(`el.innerHTML = userInput;`, len("el.innerHTML")) {
		t.Fatal("did not expect static literal assignment")
	}
	if got := truncateContext("  abcdef  ", 3); got != "abc..." {
		t.Fatalf("unexpected truncateContext: %q", got)
	}
	if h := hashDOMFinding("f.js", 1, "p"); len(h) != 16 {
		t.Fatalf("unexpected hash length: %q", h)
	}
	if abs(-3) != 3 || abs(2) != 2 {
		t.Fatal("abs helper mismatch")
	}
}
