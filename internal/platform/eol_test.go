package platform

import "testing"

func TestEOLChecker_CheckEOL(t *testing.T) {
	t.Parallel()

	c := NewEOLChecker()

	eol := c.CheckEOL("React", "17.0.2")
	if eol == nil {
		t.Fatal("expected EOL info for React 17")
	}
	if !eol.IsEOL {
		t.Fatal("expected React 17 to be EOL")
	}
	if eol.Severity == "" {
		t.Fatal("expected severity for EOL version")
	}

	supported := c.CheckEOL("React", "18.2.0")
	if supported == nil {
		t.Fatal("expected info for React 18")
	}
	if supported.IsEOL {
		t.Fatal("expected React 18 to be supported")
	}

	if unknown := c.CheckEOL("UnknownFramework", "1.0.0"); unknown != nil {
		t.Fatal("expected nil for unknown framework")
	}
}

func TestEOLChecker_CheckDetection(t *testing.T) {
	t.Parallel()

	c := NewEOLChecker()
	d := &Detection{
		Frameworks: []FrameworkInfo{
			{Name: "React", Version: "17.0.2"},
			{Name: "Vue.js", Version: "3.4.0"},
			{Name: "Angular"},
		},
	}

	results := c.CheckDetection(d)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 EOL checks, got %d", len(results))
	}

	frameworks := c.GetAllEOLFrameworks()
	if len(frameworks) == 0 {
		t.Fatal("expected non-empty EOL framework list")
	}
}

func TestEOLHelpers(t *testing.T) {
	t.Parallel()

	if got := extractMajorVersion("18.2.0"); got != "18.2" {
		t.Fatalf("unexpected major version: %q", got)
	}
	if got := extractMajorVersion("7"); got != "7" {
		t.Fatalf("unexpected single-part version: %q", got)
	}

	parsed := parseVersion("7.14.1")
	if len(parsed) != 3 || parsed[0] != 7 || parsed[1] != 14 || parsed[2] != 1 {
		t.Fatalf("unexpected parsed version: %+v", parsed)
	}

	if !versionGreaterOrEqual([]int{2, 0, 0}, []int{1, 9, 9}) {
		t.Fatal("expected versionGreaterOrEqual true")
	}
	if versionGreaterOrEqual([]int{1, 2, 0}, []int{1, 3, 0}) {
		t.Fatal("expected versionGreaterOrEqual false")
	}
}
