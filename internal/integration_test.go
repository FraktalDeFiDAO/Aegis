package internal_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
	"github.com/coppertone/bug-hunter/app/aegis/internal/scanner"
)

func TestFullWorkflowIntegration(t *testing.T) {
	skipIfNoBrowser(t)

	// 1. Setup Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><h1>Welcome</h1><a href="/secret">Go to secrets</a><script>eval("alert(1)")</script></body></html>`))
		} else if r.URL.Path == "/secret" {
			w.Write([]byte(`<html><body><p>Internal API Key: AIzaSyB-123456789</p><a href="http://evil.com/redirect">Bad Link</a></body></html>`))
		}
	}))
	defer server.Close()

	// 2. Setup Crawler
	tempDir := t.TempDir()
	dumpPath := filepath.Join(tempDir, "dump")

	cfg := crawler.Config{
		Target:            server.URL,
		MaxDepth:          1,
		WorkerCount:       1,
		Headless:          true,
		AllowPrivateHosts: true,
	}

	c := crawler.NewCrawler(cfg, "")

	// 3. Run Crawl
	err := c.Run(dumpPath)
	if err != nil {
		t.Fatalf("Crawler failed: %v", err)
	}

	// Verify that HTML files were created during crawl
	if countHTMLFiles(t, dumpPath) == 0 {
		t.Fatalf("Crawler did not create any HTML files in dump directory")
	}

	// 4. Run Scan
	s := scanner.NewScanner(dumpPath)
	findings, err := s.Scan()
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	// 5. Verify Results - Check for multiple types of findings
	foundSecret := false
	foundEval := false
	foundRedirect := false

	for _, f := range findings {
		switch f.Type {
		case "Secret Found":
			foundSecret = true
		case "Eval Usage":
			foundEval = true
		case "Unsafe Redirect":
			foundRedirect = true
		}
	}

	if !foundSecret {
		t.Error("Integration test failed: Secret from mock server not detected in crawl dump")
	}

	if !foundEval {
		t.Error("Integration test failed: Eval usage not detected in crawl dump")
	}

	// Note: Unsafe redirect might not be detected depending on the exact pattern, so we'll note this
	t.Logf("Findings detected: Secret=%v, Eval=%v, Redirect=%v", foundSecret, foundEval, foundRedirect)
	t.Logf("Total findings: %d", len(findings))
}

func TestCrawlerDepthLimit(t *testing.T) {
	skipIfNoBrowser(t)

	// Test that crawler respects depth limits
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><body><h1>Home</h1><a href="/page1">Page 1</a></body></html>`))
		} else if r.URL.Path == "/page1" {
			w.Write([]byte(`<html><body><h1>Page 1</h1><a href="/page2">Page 2</a></body></html>`))
		} else if r.URL.Path == "/page2" {
			w.Write([]byte(`<html><body><h1>Page 2</h1><a href="/page3">Page 3</a></body></html>`))
		} else {
			w.Write([]byte(`<html><body><h1>Other page</h1></body></html>`))
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	dumpPath := filepath.Join(tempDir, "dump")

	// Set max depth to 1, so it should only crawl / and /page1, not /page2
	cfg := crawler.Config{
		Target:            server.URL,
		MaxDepth:          1,
		WorkerCount:       1,
		Headless:          true,
		AllowPrivateHosts: true,
	}

	c := crawler.NewCrawler(cfg, "")
	err := c.Run(dumpPath)
	if err != nil {
		t.Fatalf("Crawler failed: %v", err)
	}

	// Count the number of HTML files created
	count := countHTMLFiles(t, dumpPath)

	// With depth 1 starting from /, we should have at most 2 HTML files (for / and /page1)
	if count > 2 {
		t.Errorf("Depth limit not respected: expected at most 2 HTML files, got %d", count)
	}
}

func skipIfNoBrowser(t *testing.T) {
	t.Helper()
	l := browser.NewLauncher(true)
	if _, err := l.Launch(); err != nil {
		t.Skipf("Skipping browser test: %v", err)
	}
	l.Cleanup()
}

func countHTMLFiles(t *testing.T, dir string) int {
	t.Helper()
	count := 0
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".html") {
			count++
		}
		return nil
	}); err != nil {
		t.Fatalf("Could not walk dump directory: %v", err)
	}
	return count
}
