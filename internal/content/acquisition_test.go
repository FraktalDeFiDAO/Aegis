package content

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/platform"
)

func TestNewAcquirer_StaticOnly(t *testing.T) {
	t.Parallel()

	a, err := NewAcquirer(WithStrategy(StaticOnly), WithTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("NewAcquirer returned error: %v", err)
	}
	if a.strategy != StaticOnly {
		t.Fatalf("unexpected strategy: %v", a.strategy)
	}
}

func TestAcquire_Static(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Test", "ok")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer ts.Close()

	a, err := NewAcquirer(WithStrategy(StaticOnly))
	if err != nil {
		t.Fatalf("NewAcquirer returned error: %v", err)
	}

	c, err := a.Acquire(ts.URL)
	if err != nil {
		t.Fatalf("Acquire returned error: %v", err)
	}
	if c.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", c.StatusCode)
	}
	if c.JavaScriptExecuted {
		t.Fatal("expected static acquisition")
	}
	if c.Headers["X-Test"] != "ok" {
		t.Fatalf("missing expected header in output: %+v", c.Headers)
	}
}

func TestAcquire_RenderAlwaysWithoutBrowser(t *testing.T) {
	t.Parallel()

	a := &Acquirer{
		strategy:   RenderAlways,
		useBrowser: false,
	}
	if _, err := a.Acquire("https://example.com"); err == nil {
		t.Fatal("expected browser-not-available error")
	}
}

func TestAcquireStatic_InvalidURL(t *testing.T) {
	t.Parallel()

	a := &Acquirer{
		httpClient: &http.Client{Timeout: time.Second},
	}
	if _, err := a.acquireStatic("://bad-url"); err == nil {
		t.Fatal("expected URL parse error")
	}
}

func TestShouldRender_ErrorAndClose(t *testing.T) {
	t.Parallel()

	a := &Acquirer{
		detector: platform.NewDetector(500 * time.Millisecond),
	}
	if _, err := a.ShouldRender("http://127.0.0.1:1"); err == nil {
		t.Fatal("expected detector error")
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}
