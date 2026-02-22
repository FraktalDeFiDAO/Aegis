package xss

import (
	"strings"
	"testing"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/waf"
)

func TestNewEnhancedScanner_Options(t *testing.T) {
	t.Parallel()

	s, err := NewEnhancedScanner(
		WithEnhancedTimeout(2*time.Second),
		WithRateLimit(10*time.Millisecond),
		WithUserAgent("test-agent"),
		WithWAFBypass(true),
		WithWAFType(waf.WAFCloudflare),
		WithEncodingLevel(waf.EncodingLevelAggessive),
		WithElements(waf.ElementScript),
		WithVerbose(true),
	)
	if err != nil {
		t.Fatalf("NewEnhancedScanner returned error: %v", err)
	}

	if s.timeout != 2*time.Second || s.rateLimit != 10*time.Millisecond {
		t.Fatalf("unexpected timing config: timeout=%v ratelimit=%v", s.timeout, s.rateLimit)
	}
	if s.userAgent != "test-agent" || !s.wafBypass || s.wafType != waf.WAFCloudflare {
		t.Fatalf("unexpected scanner options: %+v", s)
	}
}

func TestEnhancedScanner_ReflectionAndContext(t *testing.T) {
	t.Parallel()

	s, _ := NewEnhancedScanner()

	payload := `<script>alert(1)</script>`
	body := "<html><script>" + payload + "</script></html>"
	if !s.isPayloadReflected(body, payload) {
		t.Fatal("expected payload reflection")
	}
	if ctx := s.detectContext(body, payload); ctx != "javascript" {
		t.Fatalf("unexpected context: %q", ctx)
	}

	attrPayload := `onerror=alert(1)`
	attrBody := `<img src="x" ` + attrPayload + `>`
	if ctx := s.detectContext(attrBody, attrPayload); ctx != "attribute" && ctx != "html" {
		t.Fatalf("unexpected attribute context: %q", ctx)
	}
}

func TestEnhancedScanner_ClassificationAndHelpers(t *testing.T) {
	t.Parallel()

	s, _ := NewEnhancedScanner()

	typ, sev, _ := s.classifyXSS("javascript", "eval(alert(1))")
	if sev != "CRITICAL" || !strings.Contains(typ, "Code Execution") {
		t.Fatalf("unexpected classification: %s %s", typ, sev)
	}

	typ, sev, _ = s.classifyXSS("url", "javascript:alert(1)")
	if sev != "HIGH" || !strings.Contains(typ, "JavaScript Protocol") {
		t.Fatalf("unexpected classification: %s %s", typ, sev)
	}

	if enc := s.detectEncoding("&#x3c;script&#x3e;"); enc != "html-hex" {
		t.Fatalf("unexpected encoding: %q", enc)
	}
	if enc := s.detectEncoding("%253Cscript%253E"); enc != "double-url" {
		t.Fatalf("unexpected encoding: %q", enc)
	}
	if enc := s.detectEncoding("AbCd"); enc != "case-variation" {
		t.Fatalf("unexpected encoding: %q", enc)
	}

	ev := s.extractEvidence(strings.Repeat("A", 20)+"PAYLOAD"+strings.Repeat("B", 20), "PAYLOAD")
	if !strings.Contains(ev, "PAYLOAD") {
		t.Fatalf("unexpected evidence: %q", ev)
	}
	if rem := s.getRemediation("javascript"); !strings.Contains(rem, "JavaScript") {
		t.Fatalf("unexpected remediation: %q", rem)
	}
	if len(s.GetWAFStrategies(waf.WAFCloudflare)) == 0 {
		t.Fatal("expected WAF strategies")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}
