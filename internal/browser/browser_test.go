package browser

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewLauncher(t *testing.T) {
	t.Parallel()

	l := NewLauncher(true)
	if l == nil {
		t.Fatal("expected launcher instance")
	}
}

func TestLoadScript_YAMLAndJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	yamlPath := filepath.Join(dir, "script.yaml")
	yamlContent := []byte(`
name: test-yaml
actions:
  - type: navigate
    url: https://example.com
`)
	if err := os.WriteFile(yamlPath, yamlContent, 0o644); err != nil {
		t.Fatalf("write YAML script: %v", err)
	}
	s, err := LoadScript(yamlPath)
	if err != nil {
		t.Fatalf("LoadScript YAML returned error: %v", err)
	}
	if s.Name != "test-yaml" || len(s.Actions) != 1 {
		t.Fatalf("unexpected YAML script parse: %+v", s)
	}

	jsonPath := filepath.Join(dir, "script.json")
	jsonContent := []byte(`{"name":"test-json","actions":[{"type":"log","value":"ok"}]}`)
	if err := os.WriteFile(jsonPath, jsonContent, 0o644); err != nil {
		t.Fatalf("write JSON script: %v", err)
	}
	s, err = LoadScript(jsonPath)
	if err != nil {
		t.Fatalf("LoadScript JSON returned error: %v", err)
	}
	if s.Name != "test-json" || len(s.Actions) != 1 {
		t.Fatalf("unexpected JSON script parse: %+v", s)
	}

	badPath := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(badPath, []byte(":"), 0o644); err != nil {
		t.Fatalf("write invalid script: %v", err)
	}
	if _, err := LoadScript(badPath); err == nil {
		t.Fatal("expected parse error for invalid script")
	}
}

func TestAutomatorOptionsAndHelpers(t *testing.T) {
	t.Parallel()

	a := NewAutomator(
		WithHeadless(false),
		WithAutomatorTimeout(3*time.Second),
		WithSlowMotion(10*time.Millisecond),
		WithAutomatorVerbose(true),
		WithScreenshotsDir("/tmp/screens"),
	)
	if a.headless {
		t.Fatal("expected headless=false from option")
	}
	if a.timeout != 3*time.Second || a.slowMotion != 10*time.Millisecond {
		t.Fatalf("unexpected timings: timeout=%v slow=%v", a.timeout, a.slowMotion)
	}
	if !a.verbose || a.screenshotsDir != "/tmp/screens" {
		t.Fatalf("unexpected options applied: verbose=%v dir=%s", a.verbose, a.screenshotsDir)
	}

	a.variables["token"] = "abc123"
	got := a.resolveVariable("Bearer {{token}}")
	if got != "Bearer abc123" {
		t.Fatalf("unexpected resolved variable: %q", got)
	}

	a.applySettings(ScriptSettings{
		Timeout:        "5s",
		SlowMotion:     "25ms",
		ScreenshotsDir: "/tmp/new",
		Headless:       false,
	})
	if a.timeout != 5*time.Second || a.slowMotion != 25*time.Millisecond || a.screenshotsDir != "/tmp/new" {
		t.Fatalf("unexpected applySettings result: timeout=%v slow=%v dir=%s", a.timeout, a.slowMotion, a.screenshotsDir)
	}
}

func TestSaveScriptResult(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	result := &ScriptResult{
		ScriptName: "demo",
		Status:     "success",
		Variables:  map[string]string{"k": "v"},
	}

	jsonPath := filepath.Join(dir, "result.json")
	if err := SaveScriptResult(result, jsonPath); err != nil {
		t.Fatalf("SaveScriptResult json returned error: %v", err)
	}
	if b, err := os.ReadFile(jsonPath); err != nil || len(b) == 0 {
		t.Fatalf("expected non-empty JSON output, err=%v", err)
	}

	yamlPath := filepath.Join(dir, "result.yaml")
	if err := SaveScriptResult(result, yamlPath); err != nil {
		t.Fatalf("SaveScriptResult yaml returned error: %v", err)
	}
	if b, err := os.ReadFile(yamlPath); err != nil || len(b) == 0 {
		t.Fatalf("expected non-empty YAML output, err=%v", err)
	}
}

func TestWaitAndExecuteActionNonBrowserBranches(t *testing.T) {
	t.Parallel()

	a := NewAutomator()
	ctx := context.Background()

	if err := a.wait(ctx, Action{Duration: "5ms"}); err != nil {
		t.Fatalf("wait returned error: %v", err)
	}
	if err := a.wait(ctx, Action{Duration: "bad"}); err == nil {
		t.Fatal("expected parse error for invalid wait duration")
	}

	a.variables["name"] = "world"
	res := a.executeAction(ctx, Action{Type: ActionLog, Value: "hello {{name}}"}, 0)
	if res.Status != "success" {
		t.Fatalf("expected success for ActionLog, got %+v", res)
	}

	res = a.executeAction(ctx, Action{Type: ActionPause, Duration: "1ms"}, 1)
	if res.Status != "success" {
		t.Fatalf("expected success for ActionPause, got %+v", res)
	}

	res = a.executeAction(ctx, Action{Type: ActionType("unknown")}, 2)
	if res.Status != "failure" {
		t.Fatalf("expected failure for unknown action, got %+v", res)
	}
}
