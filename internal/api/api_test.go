package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coppertone/bug-hunter/app/aegis/internal/crawler"
)

func TestHealthEndpoint(t *testing.T) {
	s := NewServer()
	req, _ := http.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(s.handleHealth)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := `{"status":"ok"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestCrawlEndpointMethod(t *testing.T) {
	s := NewServer()
	req, _ := http.NewRequest("GET", "/crawl", nil)
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(s.handleCrawl)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code for GET: got %v want %v", status, http.StatusMethodNotAllowed)
	}
}

func TestCrawlEndpointValidRequest(t *testing.T) {
	s := NewServer()
	done := make(chan struct{})
	s.crawlRunner = func(crawler.Config, string) error {
		close(done)
		return nil
	}

	// Create a valid config payload
	config := crawler.Config{
		Target:      "http://example.com",
		MaxDepth:    1,
		WorkerCount: 1,
		Headless:    true,
	}

	payload, _ := json.Marshal(config)
	req, _ := http.NewRequest("POST", "/crawl", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(s.handleCrawl)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusAccepted)
	}

	expected := `{"message":"Crawl started"}`
	if !strings.Contains(rr.Body.String(), "Crawl started") {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("crawl runner did not finish")
	}
}

func TestCrawlEndpointInvalidRequest(t *testing.T) {
	s := NewServer()

	// Send invalid JSON
	req, _ := http.NewRequest("POST", "/crawl", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(s.handleCrawl)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
}

func TestStartRequiresAuthConfiguration(t *testing.T) {
	t.Setenv("AEGIS_API_TOKEN", "")
	t.Setenv("API_TOKEN", "")
	t.Setenv("AEGIS_API_ALLOW_UNAUTH", "")

	s := NewServer()
	if err := s.Start("127.0.0.1:0"); err == nil {
		t.Fatal("expected Start to reject missing auth configuration")
	}
}

func TestAuthMiddlewareRequiresTokenByDefault(t *testing.T) {
	s := &Server{token: "secret"}
	req, _ := http.NewRequest(http.MethodPost, "/crawl", nil)
	rr := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestAuthMiddlewareAllowsExplicitUnauthenticatedMode(t *testing.T) {
	s := &Server{allowUnauthenticated: true}
	req, _ := http.NewRequest(http.MethodPost, "/crawl", nil)
	rr := httptest.NewRecorder()

	handler := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected request to pass through, got %d", rr.Code)
	}
}

// newTestServer builds a Server with the same default eviction parameters
// as NewServer() so tests don't accidentally trigger eviction by leaving
// the new v3 fields at their Go zero values.
func newTestServer(ratePerMin, rateMaxBurst int) *Server {
	return &Server{
		rateBuckets:  make(map[string]*clientBucket),
		ratePerMin:   ratePerMin,
		rateWindow:   time.Minute,
		rateMaxBurst: rateMaxBurst,
		bucketTTL:    time.Hour,
		maxBuckets:   10000,
		sweepEvery:   time.Hour,
		lastSweepAt:  time.Now(),
	}
}

func TestRateLimitMiddlewareRejectsExcessRequests(t *testing.T) {
	s := newTestServer(60, 1)

	handler := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// First request passes (consumes burst)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, httptest.NewRequest("GET", "/crawl", nil))
	if rr1.Code != http.StatusNoContent {
		t.Fatalf("expected first request to pass, got %d", rr1.Code)
	}

	// Second request should be rate limited
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, httptest.NewRequest("GET", "/crawl", nil))
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be limited, got %d", rr2.Code)
	}
}

func TestRateLimitDisabledWhenPerMinZero(t *testing.T) {
	s := newTestServer(0, 1)

	handler := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 100; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest("GET", "/crawl", nil))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("request %d unexpectedly limited (ratePerMin=0): got %d", i, rr.Code)
		}
	}
}

func TestRateLimitPerClientKey(t *testing.T) {
	s := newTestServer(60, 1)

	handler := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// client a: consume its burst
	reqA := httptest.NewRequest("GET", "/crawl", nil)
	reqA.RemoteAddr = "10.0.0.1:1234"
	rrA := httptest.NewRecorder()
	handler.ServeHTTP(rrA, reqA)
	if rrA.Code != http.StatusNoContent {
		t.Fatalf("client a first request: got %d", rrA.Code)
	}

	// client b: should still pass (separate bucket)
	reqB := httptest.NewRequest("GET", "/crawl", nil)
	reqB.RemoteAddr = "10.0.0.2:5678"
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != http.StatusNoContent {
		t.Fatalf("client b first request should pass, got %d", rrB.Code)
	}
}

func TestRateLimitBucketEvictionAtMaxBuckets(t *testing.T) {
	s := &Server{
		rateBuckets:  make(map[string]*clientBucket),
		ratePerMin:   60,
		rateWindow:   time.Minute,
		rateMaxBurst: 100,
		maxBuckets:   3,
		bucketTTL:    time.Hour,
		sweepEvery:   time.Hour,
		lastSweepAt:  time.Now(),
	}

	// Create 5 buckets; map should cap at 3.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/crawl", nil)
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:1234", i+1)
		_ = s.allowRequest(req.RemoteAddr)
	}

	if got := len(s.rateBuckets); got != 3 {
		t.Fatalf("expected 3 buckets after eviction, got %d", got)
	}
}

func TestRateLimitBucketSweepRemovesStale(t *testing.T) {
	now := time.Now()
	s := &Server{
		rateBuckets: map[string]*clientBucket{
			"stale-a": {tokens: 0, lastRefill: now.Add(-2 * time.Hour)},
			"stale-b": {tokens: 0, lastRefill: now.Add(-90 * time.Minute)},
			"fresh":   {tokens: 0, lastRefill: now.Add(-1 * time.Minute)},
		},
		ratePerMin:   60,
		rateMaxBurst: 10,
		bucketTTL:    time.Hour,
	}

	s.sweepStaleBuckets(now)

	if _, ok := s.rateBuckets["stale-a"]; ok {
		t.Error("stale-a should have been evicted")
	}
	if _, ok := s.rateBuckets["stale-b"]; ok {
		t.Error("stale-b should have been evicted")
	}
	if _, ok := s.rateBuckets["fresh"]; !ok {
		t.Error("fresh should still be present")
	}
}

func TestRateLimitSweepRunsPeriodically(t *testing.T) {
	s := &Server{
		rateBuckets:  make(map[string]*clientBucket),
		ratePerMin:   60,
		rateMaxBurst: 1,
		bucketTTL:    time.Hour,
		sweepEvery:   50 * time.Millisecond,
		lastSweepAt:  time.Now().Add(-time.Hour), // force sweep on next call
	}

	// Pre-populate a stale bucket
	s.rateBuckets["stale"] = &clientBucket{
		tokens:     0,
		lastRefill: time.Now().Add(-2 * time.Hour),
	}

	req := httptest.NewRequest("GET", "/crawl", nil)
	req.RemoteAddr = "10.0.0.99:1"
	_ = s.allowRequest(req.RemoteAddr)

	if _, ok := s.rateBuckets["stale"]; ok {
		t.Error("stale bucket should have been swept during allowRequest")
	}
}

func TestPrepareCrawlDumpDirPrunesOldest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AEGIS_API_DUMP_ROOT", dir)
	t.Setenv("AEGIS_API_DUMP_MAX_DIRS", "3")

	// Pre-create 5 old directories
	oldNames := []string{"20260101_000000.000000000", "20260102_000000.000000000", "20260103_000000.000000000", "20260104_000000.000000000", "20260105_000000.000000000"}
	for _, n := range oldNames {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got, err := prepareCrawlDumpDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(got), "20") {
		t.Errorf("expected timestamped dump dir, got %s", got)
	}

	// Should have at most 3 entries (max=3)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Errorf("expected 3 dirs after prune, got %d", len(entries))
	}

	// Oldest two should be gone
	for _, n := range oldNames[:2] {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Errorf("expected %s pruned, still exists", n)
		}
	}
}

func TestPrepareCrawlDumpDirRespectsRootOverride(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "custom-root")
	t.Setenv("AEGIS_API_DUMP_ROOT", subdir)
	t.Setenv("AEGIS_API_DUMP_MAX_DIRS", "4")

	got, err := prepareCrawlDumpDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, subdir) {
		t.Errorf("expected dump dir under %s, got %s", subdir, got)
	}
}
