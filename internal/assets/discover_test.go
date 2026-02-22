package assets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewDiscoverer_WithTimeout(t *testing.T) {
	t.Parallel()

	d, err := NewDiscoverer(WithTimeout(2 * time.Second))
	if err != nil {
		t.Fatalf("NewDiscoverer returned error: %v", err)
	}
	if d.timeout != 2*time.Second {
		t.Fatalf("unexpected timeout: %v", d.timeout)
	}
}

func TestDiscover_Success(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
<html>
  <script src="/static/app.js"></script>
  <script src="/static/app.js"></script>
  <link rel="stylesheet" href="/assets/site.css">
  <img src="https://cdn.example.com/logo.png">
</html>`))
	}))
	defer ts.Close()

	d, err := NewDiscoverer()
	if err != nil {
		t.Fatalf("NewDiscoverer returned error: %v", err)
	}

	result, err := d.Discover(ts.URL)
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}

	if result.TotalCount != 3 {
		t.Fatalf("expected 3 assets, got %d", result.TotalCount)
	}
	if result.ByType[AssetJavaScript] != 1 {
		t.Fatalf("unexpected js count: %d", result.ByType[AssetJavaScript])
	}
	if result.ByType[AssetCSS] != 1 {
		t.Fatalf("unexpected css count: %d", result.ByType[AssetCSS])
	}
	if result.ByType[AssetImage] != 1 {
		t.Fatalf("unexpected image count: %d", result.ByType[AssetImage])
	}
	if len(result.ExternalHosts) != 1 || result.ExternalHosts[0] != "cdn.example.com" {
		t.Fatalf("unexpected external hosts: %+v", result.ExternalHosts)
	}
}

func TestDiscover_HTTPError(t *testing.T) {
	t.Parallel()

	d, err := NewDiscoverer()
	if err != nil {
		t.Fatalf("NewDiscoverer returned error: %v", err)
	}
	if _, err := d.Discover("http://127.0.0.1:1"); err == nil {
		t.Fatal("expected request error")
	}
}

func TestHelpersAndReport(t *testing.T) {
	t.Parallel()

	if got := resolveURL("https://example.com/a", "/b.js"); got != "https://example.com/b.js" {
		t.Fatalf("unexpected resolveURL: %q", got)
	}
	if got := resolveURL("https://example.com/a", "data:text/plain,abc"); got != "" {
		t.Fatalf("expected empty for data URL, got %q", got)
	}
	if !isSameHost("https://example.com", "https://example.com/x.js") {
		t.Fatal("expected same host")
	}
	if isSameHost("https://example.com", "https://cdn.example.com/x.js") {
		t.Fatal("expected different host")
	}
	if !contains([]string{"a", "b"}, "b") {
		t.Fatal("contains should return true")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Fatal("contains should return false")
	}

	d, _ := NewDiscoverer()
	data, err := d.GenerateReport(&DiscoveryResult{
		BaseURL:    "https://example.com",
		TotalCount: 1,
		Assets:     []Asset{{URL: "https://example.com/a.js", Type: AssetJavaScript}},
		ByType:     map[AssetType]int{AssetJavaScript: 1},
	})
	if err != nil {
		t.Fatalf("GenerateReport returned error: %v", err)
	}

	var parsed DiscoveryResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}
