package xss

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewScannerAndHelpers(t *testing.T) {
	t.Parallel()

	s, err := NewScanner(WithTimeout(2 * time.Second))
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}
	if s.timeout != 2*time.Second {
		t.Fatalf("unexpected timeout: %v", s.timeout)
	}

	u := injectParameter("https://example.com?a=1", "a", "<x>")
	if u == "" {
		t.Fatal("injectParameter returned empty URL")
	}

	if got := truncate("abcdef", 3); got != "abc..." {
		t.Fatalf("unexpected truncate: %q", got)
	}

	h1 := hashFinding("https://example.com", "q")
	h2 := hashFinding("https://example.com", "q")
	if h1 != h2 || len(h1) != 16 {
		t.Fatalf("unexpected hash output: %q %q", h1, h2)
	}
}

func TestScanTarget_ReflectedXSS(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		_, _ = w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer ts.Close()

	s, err := NewScanner()
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}

	findings := s.ScanTarget(ts.URL + "?q=test")
	if len(findings) == 0 {
		t.Fatal("expected reflected XSS findings")
	}
	if findings[0].Type == "" || findings[0].Hash == "" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestScanTarget_InvalidURL(t *testing.T) {
	t.Parallel()

	s, _ := NewScanner()
	findings := s.ScanTarget("://bad-url")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for invalid URL, got %d", len(findings))
	}
}

func TestGenerateReportAndClose(t *testing.T) {
	t.Parallel()

	s, _ := NewScanner()
	data, err := s.GenerateReport([]XSSFinding{
		{Type: "Reflected XSS", URL: "https://example.com"},
	})
	if err != nil {
		t.Fatalf("GenerateReport returned error: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("report is not valid JSON")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}
