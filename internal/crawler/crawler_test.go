package crawler

import (
	"testing"
)

func TestNewCrawler(t *testing.T) {
	cfg := Config{
		Target:      "http://example.com",
		MaxDepth:    2,
		WorkerCount: 5,
	}
	c := NewCrawler(cfg, "")

	if c.config.Target != "http://example.com" {
		t.Errorf("Expected target http://example.com, got %s", c.config.Target)
	}

	if c.config.WorkerCount != 5 {
		t.Errorf("Expected 5 workers, got %d", c.config.WorkerCount)
	}
}

func TestGenerateFilename(t *testing.T) {
	tests := []struct {
		url      string
		ext      string
		expected string
	}{
		{"http://example.com/", ".html", "index.html"},
		{"http://example.com/test", ".html", "test.html"},
		{"http://example.com/a/b", ".html", "a_b.html"},
		{"http://example.com/?q=1", ".html", "index_q%3D1.html"},
	}

	for _, tt := range tests {
		got := generateFilename(tt.url, tt.ext)
		if got != tt.expected {
			t.Errorf("generateFilename(%s, %s) = %s; want %s", tt.url, tt.ext, got, tt.expected)
		}
	}
}

func TestIsSameDomain(t *testing.T) {
	cfg := Config{Target: "http://example.com"}
	c := NewCrawler(cfg, "")

	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com/path", true},
		{"https://example.com/other", true}, // Host matches
		{"http://sub.example.com", false},   // Different host
		{"http://google.com", false},
	}

	for _, tt := range tests {
		got := c.isSameDomain(tt.url)
		if got != tt.expected {
			t.Errorf("isSameDomain(%s) = %v; want %v", tt.url, got, tt.expected)
		}
	}
}
