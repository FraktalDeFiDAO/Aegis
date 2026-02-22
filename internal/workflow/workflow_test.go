package workflow

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadWorkflow_YAML(t *testing.T) {
	// Create temp workflow file
	content := `
name: "Test Workflow"
description: "A test workflow"
version: "1.0.0"
variables:
  target: "https://example.com"
steps:
  - id: waf_detect
    name: "Detect WAF"
    type: waf_detect
    config:
      target: "{{target}}"
`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatalf("LoadWorkflow failed: %v", err)
	}

	if wf.Name != "Test Workflow" {
		t.Errorf("Expected name 'Test Workflow', got '%s'", wf.Name)
	}

	if len(wf.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(wf.Steps))
	}

	if wf.Steps[0].ID != "waf_detect" {
		t.Errorf("Expected step ID 'waf_detect', got '%s'", wf.Steps[0].ID)
	}
}

func TestLoadWorkflow_JSON(t *testing.T) {
	content := `{
  "name": "JSON Workflow",
  "steps": [
    {
      "id": "scan",
      "name": "Run Scan",
      "type": "scan",
      "config": {
        "target": "https://example.com"
      }
    }
  ]
}`
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatalf("LoadWorkflow failed: %v", err)
	}

	if wf.Name != "JSON Workflow" {
		t.Errorf("Expected name 'JSON Workflow', got '%s'", wf.Name)
	}
}

func TestWorkflow_Validate(t *testing.T) {
	tests := []struct {
		name    string
		wf      Workflow
		wantErr bool
	}{
		{
			name: "valid workflow",
			wf: Workflow{
				Name: "Test",
				Steps: []Step{
					{ID: "step1", Type: StepTypeScan},
				},
			},
			wantErr: false,
		},
		{
			name:    "missing name",
			wf:      Workflow{Steps: []Step{{ID: "step1", Type: StepTypeScan}}},
			wantErr: true,
		},
		{
			name:    "no steps",
			wf:      Workflow{Name: "Test", Steps: []Step{}},
			wantErr: true,
		},
		{
			name: "duplicate step ID",
			wf: Workflow{
				Name: "Test",
				Steps: []Step{
					{ID: "step1", Type: StepTypeScan},
					{ID: "step1", Type: StepTypeXSS},
				},
			},
			wantErr: true,
		},
		{
			name: "missing step type",
			wf: Workflow{
				Name:  "Test",
				Steps: []Step{{ID: "step1"}},
			},
			wantErr: true,
		},
		{
			name: "unknown dependency",
			wf: Workflow{
				Name: "Test",
				Steps: []Step{
					{ID: "step1", Type: StepTypeScan, DependsOn: []string{"unknown"}},
				},
			},
			wantErr: true,
		},
		{
			name: "forward dependency reference",
			wf: Workflow{
				Name: "Test",
				Steps: []Step{
					{ID: "step1", Type: StepTypeScan, DependsOn: []string{"step2"}},
					{ID: "step2", Type: StepTypeXSS},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.wf.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunner_ResolveVariable(t *testing.T) {
	wf := &Workflow{
		Name: "Test",
		Variables: map[string]string{
			"target":     "https://example.com",
			"output_dir": "/tmp/output",
		},
		Steps: []Step{{ID: "step1", Type: StepTypeScan}},
	}

	runner := NewRunner(wf)

	tests := []struct {
		input    string
		expected string
	}{
		{"{{target}}", "https://example.com"},
		{"{{output_dir}}/report.json", "/tmp/output/report.json"},
		{"no variables", "no variables"},
		{"{{unknown}}", "{{unknown}}"},
	}

	for _, tt := range tests {
		result := runner.resolveVariable(tt.input)
		if result != tt.expected {
			t.Errorf("resolveVariable(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestRunner_Run_BasicWorkflow(t *testing.T) {
	wf := &Workflow{
		Name: "Basic Test",
		Variables: map[string]string{
			"target": "https://httpbin.org",
		},
		Steps: []Step{
			{
				ID:   "wait",
				Name: "Wait Step",
				Type: StepTypeWait,
				Config: StepConfig{
					Duration: "10ms",
				},
			},
		},
	}

	runner := NewRunner(wf, WithVerbose(false))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("Expected status 'success', got '%s'", result.Status)
	}

	if len(result.Steps) != 1 {
		t.Errorf("Expected 1 step result, got %d", len(result.Steps))
	}

	if result.Steps[0].Status != "success" {
		t.Errorf("Expected step status 'success', got '%s'", result.Steps[0].Status)
	}
}

func TestRunner_Run_WithDependencies(t *testing.T) {
	wf := &Workflow{
		Name: "Dependency Test",
		Steps: []Step{
			{
				ID:   "step1",
				Name: "First Step",
				Type: StepTypeWait,
				Config: StepConfig{
					Duration: "1ms",
				},
			},
			{
				ID:        "step2",
				Name:      "Second Step",
				Type:      StepTypeWait,
				DependsOn: []string{"step1"},
				Config: StepConfig{
					Duration: "1ms",
				},
			},
		},
	}

	runner := NewRunner(wf)
	ctx := context.Background()

	result, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("Expected status 'success', got '%s'", result.Status)
	}

	if len(result.Steps) != 2 {
		t.Errorf("Expected 2 step results, got %d", len(result.Steps))
	}
}

func TestParseWAFType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"cloudflare", "cloudflare"},
		{"CLOUDFLARE", "cloudflare"},
		{"akamai", "akamai"},
		{"unknown", "unknown"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		result := parseWAFType(tt.input)
		if string(result) != tt.expected {
			t.Errorf("parseWAFType(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseElementTypes(t *testing.T) {
	tests := []struct {
		input    []string
		minCount int
	}{
		{[]string{"script", "img"}, 2},
		{[]string{"svg", "div", "span"}, 3},
		{[]string{}, 4}, // defaults
		{[]string{"unknown"}, 4}, // falls back to defaults
	}

	for _, tt := range tests {
		result := parseElementTypes(tt.input)
		if len(result) < tt.minCount {
			t.Errorf("parseElementTypes(%v) returned %d elements, want at least %d", tt.input, len(result), tt.minCount)
		}
	}
}

func TestWorkflowResult_Helpers(t *testing.T) {
	result := &WorkflowResult{
		Steps: []StepResult{
			{StepID: "step1", Status: "success", Output: map[string]interface{}{"findings": []interface{}{"f1", "f2"}}},
			{StepID: "step2", Status: "failure", Error: "something failed"},
			{StepID: "step3", Status: "skipped"},
		},
	}

	// Test GetFindings
	findings := result.GetFindings()
	if len(findings) != 2 {
		t.Errorf("GetFindings() returned %d findings, want 2", len(findings))
	}

	// Test HasFailures
	if !result.HasFailures() {
		t.Error("HasFailures() should return true")
	}

	// Test GetFailedSteps
	failed := result.GetFailedSteps()
	if len(failed) != 1 {
		t.Errorf("GetFailedSteps() returned %d steps, want 1", len(failed))
	}
}
