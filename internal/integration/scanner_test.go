package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/apiextract"
	"github.com/coppertone/bug-hunter/app/aegis/internal/assets"
	"github.com/coppertone/bug-hunter/app/aegis/internal/content"
	"github.com/coppertone/bug-hunter/app/aegis/internal/exploitable"
	"github.com/coppertone/bug-hunter/app/aegis/internal/owasp25"
	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
	"github.com/coppertone/bug-hunter/app/aegis/internal/xss"
)

func TestNewUnifiedScanner_DisabledModules(t *testing.T) {
	t.Parallel()

	s, err := NewUnifiedScanner(func(u *UnifiedScanner) {
		u.enableExploitable = false
		u.enableContent = false
		u.enableOWASP = false
	})
	if err != nil {
		t.Fatalf("NewUnifiedScanner returned error: %v", err)
	}
	if s.platformDetector == nil {
		t.Fatal("expected platform detector")
	}

	findings, err := s.ScanTarget(Target{})
	if err != nil {
		t.Fatalf("ScanTarget returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestUnifiedScanner_scanExploitable_EmptyHost(t *testing.T) {
	t.Parallel()

	s := &UnifiedScanner{
		exploitableScanner: exploitable.NewScanner(exploitable.WithTimeout(100 * time.Millisecond)),
	}
	findings := s.scanExploitable(Target{Host: "", Ports: []int{1}})
	if len(findings) != 0 {
		t.Fatalf("expected no findings for empty host, got %d", len(findings))
	}
}

func TestCompleteScanner_CalculateSummaryAndClose(t *testing.T) {
	t.Parallel()

	s := &CompleteScanner{}
	result := &CompleteScanResult{
		XSS: []xss.XSSFinding{
			{Severity: "HIGH"},
			{Severity: "LOW"},
		},
		Exploitable: []UnifiedFinding{
			{Severity: "CRITICAL"},
			{Severity: "MEDIUM"},
		},
		OWASP: []owasp25.Finding{
			{Severity: "HIGH"},
			{Severity: "LOW"},
		},
	}

	summary := s.calculateSummary(result)
	if summary.TotalXSS != 2 || summary.TotalExploitable != 2 || summary.TotalOWASP != 2 {
		t.Fatalf("unexpected totals: %+v", summary)
	}
	if summary.CriticalCount != 1 || summary.HighCount != 2 || summary.MediumCount != 1 || summary.LowCount != 2 {
		t.Fatalf("unexpected severity counters: %+v", summary)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestCompleteScanner_scanExploitable_NoResults(t *testing.T) {
	t.Parallel()

	s := &CompleteScanner{
		exploitableScan: exploitable.NewScanner(exploitable.WithTimeout(200 * time.Millisecond)),
	}

	findings := s.scanExploitable(Target{
		Host:  "127.0.0.1",
		Ports: []int{1},
	})
	if len(findings) != 0 {
		t.Fatalf("expected no exploitable findings on closed local port, got %d", len(findings))
	}
}

func TestUnifiedScanner_scanContentAndOWASP(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>eval(userInput)</script></body></html>`))
	}))
	defer ts.Close()

	acq, err := content.NewAcquirer(content.WithStrategy(content.StaticOnly))
	if err != nil {
		t.Fatalf("NewAcquirer returned error: %v", err)
	}

	s := &UnifiedScanner{
		contentAcquirer:  acq,
		platformDetector: platform.NewDetector(time.Second),
		owaspScanner:     owasp25.NewScanner("", owasp25.WithCategories(owasp25.Injection)),
		enableOWASP:      true,
	}

	findings := s.scanContentAndOWASP(Target{URL: ts.URL})
	if len(findings) == 0 {
		t.Fatal("expected findings from content/owasp scan")
	}
}

func TestCompleteScanner_Scan_StaticComponents(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
<html>
<script src="/app.js"></script>
<script>eval(userInput); fetch('/api/users')</script>
</html>`))
	}))
	defer ts.Close()

	xssScanner, err := xss.NewScanner()
	if err != nil {
		t.Fatalf("NewScanner returned error: %v", err)
	}
	assetDiscoverer, err := assets.NewDiscoverer()
	if err != nil {
		t.Fatalf("NewDiscoverer returned error: %v", err)
	}
	acq, err := content.NewAcquirer(content.WithStrategy(content.StaticOnly))
	if err != nil {
		t.Fatalf("NewAcquirer returned error: %v", err)
	}

	s := &CompleteScanner{
		xssScanner:       xssScanner,
		assetDiscoverer:  assetDiscoverer,
		apiExtractor:     apiextract.NewExtractor(),
		contentAcquirer:  acq,
		platformDetector: platform.NewDetector(time.Second),
		owaspScanner:     owasp25.NewScanner("", owasp25.WithCategories(owasp25.Injection)),
	}

	result, err := s.Scan(Target{URL: ts.URL})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil scan result")
	}
	if result.Summary.TotalAPIs == 0 {
		t.Fatalf("expected API count in summary, got %+v", result.Summary)
	}
}
