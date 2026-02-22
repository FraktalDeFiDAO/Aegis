package scrape

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportedParsersAndURLHelpers(t *testing.T) {
	t.Parallel()

	if got := ParseSrcSet("a.png 1x, b.png 2x"); len(got) != 2 || got[0] != "a.png" {
		t.Fatalf("unexpected srcset parse: %+v", got)
	}
	if got := ParseCSSImports(`@import "/a.css"; .x{background:url('/b.png')}`); len(got) < 2 {
		t.Fatalf("unexpected css imports: %+v", got)
	}
	if got := ParseJSImport(`import x from "/a.js"; const y=require("/b.js");`); len(got) < 2 {
		t.Fatalf("unexpected js imports: %+v", got)
	}

	norm, err := NormalizeURL("HTTPS://Example.com/a#frag")
	if err != nil {
		t.Fatalf("NormalizeURL returned error: %v", err)
	}
	if strings.Contains(norm, "#") || !strings.HasPrefix(norm, "https://example.com") {
		t.Fatalf("unexpected normalized URL: %q", norm)
	}

	resolved, err := ResolveURL("https://example.com/a/b", "../c")
	if err != nil {
		t.Fatalf("ResolveURL returned error: %v", err)
	}
	if resolved != "https://example.com/c" {
		t.Fatalf("unexpected resolved URL: %q", resolved)
	}
	if !IsHTTPURL("https://example.com") || IsHTTPURL("javascript:alert(1)") {
		t.Fatal("unexpected IsHTTPURL behavior")
	}
}

func TestCollectResourcesAndUniqueStrings(t *testing.T) {
	t.Parallel()

	html := `<a href="/a"></a><img src="/b.png"><style>body{background:url('/c.png')}</style>`
	links, sources, imports := CollectResourcesFromHTML("https://example.com", html)
	if len(links) == 0 || len(sources) == 0 || len(imports) == 0 {
		t.Fatalf("unexpected collected resources: links=%v sources=%v imports=%v", links, sources, imports)
	}

	uniq := uniqueStrings([]string{"a", "a", "b"})
	if len(uniq) != 2 {
		t.Fatalf("expected unique list, got %v", uniq)
	}
}

func TestFetchHTMLAndHeaders(t *testing.T) {
	t.Parallel()

	if _, err := fetchHTML(nil, "https://example.com", "", nil, 0, 0); err == nil {
		t.Fatal("expected error for nil http client")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/large" {
			_, _ = w.Write([]byte(strings.Repeat("A", 2048)))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	body, err := fetchHTML(client, ts.URL, "ua", map[string]string{"X-Test": "1"}, 0, 1024)
	if err != nil {
		t.Fatalf("fetchHTML returned error: %v", err)
	}
	if !strings.Contains(body, "ok") {
		t.Fatalf("unexpected fetch body: %q", body)
	}
	if _, err := fetchHTML(client, ts.URL+"/status", "ua", nil, 0, 1024); err == nil {
		t.Fatal("expected non-2xx error")
	}
	if _, err := fetchHTML(client, ts.URL+"/large", "ua", nil, 0, 128); err == nil {
		t.Fatal("expected max-bytes error")
	}
}

func TestHeaderAndPathHelpers(t *testing.T) {
	t.Parallel()

	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	applyHeaders(req, map[string]string{"X-A": "1", " ": "ignored"})
	if req.Header.Get("X-A") != "1" {
		t.Fatalf("expected header applied, got %v", req.Header)
	}

	if got := headerValue(map[string]string{"x-test": "ok"}, "X-Test"); got != "ok" {
		t.Fatalf("unexpected headerValue: %q", got)
	}
	if pairs := headerPairs(map[string]string{"X-A": "1"}); len(pairs) != 2 {
		t.Fatalf("unexpected headerPairs: %v", pairs)
	}

	base := t.TempDir()
	resourcePath, err := BuildResourcePath(base, "https://example.com/path/file.js?x=1")
	if err != nil {
		t.Fatalf("BuildResourcePath returned error: %v", err)
	}
	if !strings.Contains(resourcePath, "example.com") {
		t.Fatalf("unexpected resource path: %q", resourcePath)
	}

	filePath := filepath.Join(base, "already_file")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write setup file: %v", err)
	}
	dirPath, err := ensureDir(filePath)
	if err != nil {
		t.Fatalf("ensureDir returned error: %v", err)
	}
	if !strings.Contains(dirPath, "__dir") {
		t.Fatalf("expected __dir suffix fallback, got %q", dirPath)
	}
}

func TestFetchToFileAndWriters(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("payload"))
	}))
	defer ts.Close()

	base := t.TempDir()
	dest := filepath.Join(base, "out.bin")
	client := &http.Client{Timeout: 2 * time.Second}

	if err := fetchToFile(client, ts.URL, dest, "ua", nil, 0, 1024); err != nil {
		t.Fatalf("fetchToFile returned error: %v", err)
	}
	if b, err := os.ReadFile(dest); err != nil || string(b) != "payload" {
		t.Fatalf("unexpected fetched file content: err=%v data=%q", err, string(b))
	}
	if err := fetchToFile(client, ts.URL+"/bad", dest, "ua", nil, 0, 1024); err == nil {
		t.Fatal("expected fetchToFile status error")
	}
	if err := fetchToFile(client, ts.URL, dest, "ua", nil, 0, 2); err == nil {
		t.Fatal("expected fetchToFile max-bytes error")
	}

	if _, err := writeHTML(base, "https://example.com/a", "<html/>"); err != nil {
		t.Fatalf("writeHTML returned error: %v", err)
	}
	if _, err := writeScreenshot(base, "https://example.com/a", []byte("img")); err != nil {
		t.Fatalf("writeScreenshot returned error: %v", err)
	}
}

func TestValidateTargetAndSanitizeSegment(t *testing.T) {
	t.Parallel()

	if err := validateTarget("https://example.com", false); err != nil {
		t.Fatalf("validateTarget returned unexpected error: %v", err)
	}
	if err := validateTarget("http://127.0.0.1", false); err == nil {
		t.Fatal("expected private-target validation error")
	}
	if err := validateTarget("http://127.0.0.1", true); err != nil {
		t.Fatalf("expected allowPrivate=true to pass, got %v", err)
	}

	if got := sanitizeSegment("../a/b\\c"); strings.Contains(got, "..") || strings.Contains(got, "/") || strings.Contains(got, "\\") {
		t.Fatalf("unexpected sanitized segment: %q", got)
	}
}
