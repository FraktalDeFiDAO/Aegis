package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Success(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte(`
target: https://example.com
instances:
  - name: victim
    type: browser
    headless: true
tasks:
  - name: test task
    description: sample
    actions:
      - instance: victim
        type: navigate
        params:
          url: https://example.com/login
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Target != "https://example.com" {
		t.Fatalf("unexpected target: %q", cfg.Target)
	}
	if len(cfg.Instances) != 1 || cfg.Instances[0].Name != "victim" {
		t.Fatalf("unexpected instances: %+v", cfg.Instances)
	}
	if len(cfg.Tasks) != 1 || len(cfg.Tasks[0].Actions) != 1 {
		t.Fatalf("unexpected tasks/actions: %+v", cfg.Tasks)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	t.Parallel()

	if _, err := Load("/does/not/exist/config.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("target: ["), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected YAML parse error")
	}
}
