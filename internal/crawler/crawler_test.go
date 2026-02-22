package crawler

import (
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coppertone/bug-hunter/app/aegis/internal/browser"
	"github.com/coppertone/bug-hunter/app/aegis/internal/session"
	"github.com/go-rod/rod"
	_ "github.com/mattn/go-sqlite3"
)

func TestNewCrawler(t *testing.T) {
	cfg := Config{
		Target:            "http://example.com",
		MaxDepth:          2,
		WorkerCount:       5,
		AllowPrivateHosts: true,
	}
	c := NewCrawler(cfg, "")

	if c.config.Target != "http://example.com" {
		t.Errorf("Expected target http://example.com, got %s", c.config.Target)
	}

	if c.config.WorkerCount != 5 {
		t.Errorf("Expected 5 workers, got %d", c.config.WorkerCount)
	}
}

func TestNewCrawlerDefaultsWorkerCount(t *testing.T) {
	cfg := Config{
		Target:            "http://example.com",
		MaxDepth:          1,
		WorkerCount:       0,
		AllowPrivateHosts: true,
	}
	c := NewCrawler(cfg, "")

	if c.config.WorkerCount != 1 {
		t.Errorf("Expected default worker count 1, got %d", c.config.WorkerCount)
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
	cfg.AllowPrivateHosts = true
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

func TestCrawlerFeatures(t *testing.T) {
	skipIfNoBrowser(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!doctype html>
<html>
<head>
<style>body { height: 2000px; }</style>
<script>
window.addEventListener('load', () => {
  const val = localStorage.getItem('session-key') || '';
  const sessionEl = document.getElementById('session');
  if (sessionEl) { sessionEl.textContent = val; }
});
window.addEventListener('scroll', () => {
  const marker = document.getElementById('scroll-marker');
  if (marker) { marker.textContent = 'scrolled'; }
});
</script>
</head>
<body>
<div id="ua">%s</div>
<div id="session"></div>
<div id="scroll-marker">not-scrolled</div>
</body>
</html>`, r.UserAgent())
	}))
	defer server.Close()

	tempDir := t.TempDir()
	dumpPath := filepath.Join(tempDir, "dump")
	screenshotPath := filepath.Join(tempDir, "screenshots")
	sessionPath := filepath.Join(tempDir, "session.json")
	sessionKey := []byte("01234567890123456789012345678901")

	createSessionFile(t, server.URL, sessionPath, sessionKey)

	cfg := Config{
		Target:            server.URL,
		MaxDepth:          0,
		WorkerCount:       1,
		Headless:          true,
		Scroll:            true,
		UserAgent:         "AegisTestUA/1.0",
		EnableScreenshot:  true,
		ScreenshotPath:    screenshotPath,
		SessionKey:        sessionKey,
		AllowPrivateHosts: true,
	}

	c := NewCrawler(cfg, sessionPath)
	if err := c.Run(dumpPath); err != nil {
		t.Fatalf("Crawler run failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dumpPath, "crawl.db")); err != nil {
		t.Fatalf("Expected crawl database to be created: %v", err)
	}
	assertRenderCheckRecorded(t, dumpPath)

	htmlPath := findSingleHTML(t, dumpPath)
	content, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("Failed to read crawl output: %v", err)
	}

	body := string(content)
	if !strings.Contains(body, "session-value") {
		t.Error("Expected session value to be injected into page content")
	}
	if !strings.Contains(body, "AegisTestUA/1.0") {
		t.Error("Expected custom User-Agent to appear in server-rendered HTML")
	}
	if !strings.Contains(body, "scrolled") {
		t.Error("Expected scroll handler to update page content")
	}

	if _, err := os.Stat(filepath.Join(screenshotPath, "index.png")); err != nil {
		t.Fatalf("Expected screenshot to be saved: %v", err)
	}
}

func assertRenderCheckRecorded(t *testing.T, dumpPath string) {
	t.Helper()
	dbPath := filepath.Join(dumpPath, "crawl.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open crawl db: %v", err)
	}
	defer db.Close()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM render_checks").Scan(&count); err != nil {
		t.Fatalf("query render_checks: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected render_checks to have entries")
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

func createSessionFile(t *testing.T, pageURL, sessionPath string, key []byte) {
	t.Helper()
	l := browser.NewLauncher(true)
	u, err := l.Launch()
	if err != nil {
		t.Skipf("Skipping browser test: %v", err)
	}
	defer l.Cleanup()

	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	page := browser.MustPage(pageURL)
	page.MustWaitLoad()
	page.MustEval(`() => localStorage.setItem("session-key", "session-value")`)

	mgr := session.NewSessionManager(sessionPath, key)
	if err := mgr.Save(page); err != nil {
		t.Fatalf("Failed to create session file: %v", err)
	}
	page.MustClose()
}

func findSingleHTML(t *testing.T, dumpPath string) string {
	t.Helper()
	var htmlPath string
	err := filepath.WalkDir(dumpPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".html") {
			htmlPath = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk dump directory: %v", err)
	}
	if htmlPath == "" {
		t.Fatalf("No HTML files found in %s", dumpPath)
	}
	return htmlPath
}
