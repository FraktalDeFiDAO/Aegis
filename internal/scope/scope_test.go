package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFile_CustomYAML_AndScopeChecks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	content := []byte(`
program_name: Example Program
platform: custom
in_scope:
  - "*.example.com"
  - "10.0.0.1"
  - "10.0.0.0/24"
  - "https://api.example.com/v1"
out_of_scope:
  - "admin.example.com"
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write scope file: %v", err)
	}

	s, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if s.ProgramName != "Example Program" {
		t.Fatalf("unexpected program name: %q", s.ProgramName)
	}
	if !s.IsInScope("https://foo.example.com/page") {
		t.Fatal("expected wildcard domain to be in scope")
	}
	if s.IsInScope("admin.example.com") {
		t.Fatal("expected out-of-scope domain to be excluded")
	}
	if !s.IsInScope("10.0.0.10") {
		t.Fatal("expected CIDR host to be in scope")
	}

	targets := s.Targets()
	if len(targets) == 0 {
		t.Fatal("expected non-empty targets")
	}
}

func TestParseFile_HackerOneJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "h1.json")
	content := []byte(`{
  "name": "H1 Program",
  "targets": {
    "in_scope": ["app.example.com"],
    "out_of_scope": ["legacy.example.com"]
  }
}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write scope file: %v", err)
	}

	s, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}

	if s.Platform != "hackerone" {
		t.Fatalf("unexpected platform: %q", s.Platform)
	}
	if len(s.InScope) != 1 || len(s.OutOfScope) != 1 {
		t.Fatalf("unexpected parsed items: in=%d out=%d", len(s.InScope), len(s.OutOfScope))
	}
}

func TestParseFile_BugcrowdYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bugcrowd.yaml")
	content := []byte(`
name: BC Program
target_groups:
  - in_scope: true
    targets:
      - domain: api.example.com
  - in_scope: false
    targets:
      - domain: old.example.com
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write scope file: %v", err)
	}

	s, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile returned error: %v", err)
	}
	if s.Platform != "bugcrowd" {
		t.Fatalf("unexpected platform: %q", s.Platform)
	}
	if len(s.InScope) != 1 || len(s.OutOfScope) != 1 {
		t.Fatalf("unexpected parsed items: in=%d out=%d", len(s.InScope), len(s.OutOfScope))
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	if got := normalizeDomain("https://example.com/path"); got != "example.com" {
		t.Fatalf("unexpected normalizeDomain: %q", got)
	}
	if got := detectType("*.example.com"); got != "wildcard" {
		t.Fatalf("unexpected detectType for wildcard: %q", got)
	}
	if got := detectType("10.0.0.0/24"); got != "cidr" {
		t.Fatalf("unexpected detectType for cidr: %q", got)
	}
	if got := detectType("127.0.0.1"); got != "ip" {
		t.Fatalf("unexpected detectType for ip: %q", got)
	}
	if !matches("sub.example.com", "*.example.com", "wildcard") {
		t.Fatal("expected wildcard match")
	}
	if matches("example.net", "*.example.com", "wildcard") {
		t.Fatal("unexpected wildcard match")
	}
	if !matches("10.0.0.5", "10.0.0.0/24", "cidr") {
		t.Fatal("expected cidr match")
	}
	if matches("bad", "10.0.0.0/24", "cidr") {
		t.Fatal("unexpected cidr match")
	}
	if got := uniqueStrings([]string{"a", "a", "b"}); len(got) != 2 {
		t.Fatalf("expected deduplicated values, got %v", got)
	}
	if _, err := parseHost("://bad url"); err == nil {
		t.Fatal("expected parseHost error")
	}
}
