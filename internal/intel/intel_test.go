package intel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIntelManagerInitialization(t *testing.T) {
	manager := NewIntelManager()

	if manager == nil {
		t.Error("Expected IntelManager to be initialized, got nil")
	}

	if len(manager.feeds) == 0 {
		t.Error("Expected IntelManager to have default feeds, got none")
	}
}

func TestIsMalicious(t *testing.T) {
	manager := NewIntelManager()

	// With no cached data, should return false
	result := manager.IsMalicious("http://example.com")

	if result {
		t.Error("Expected IsMalicious to return false with empty cache")
	}
}

func TestFetchUpdatesAndIsMalicious(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"urls":["http://malicious.test/path"]}`))
	}))
	defer server.Close()

	manager := NewIntelManager()
	manager.feeds = []ThreatFeed{{Name: "test-feed", URL: server.URL}}

	if err := manager.FetchUpdates(); err != nil {
		t.Fatalf("FetchUpdates failed: %v", err)
	}

	if !manager.IsMalicious("http://malicious.test/path") {
		t.Error("Expected IsMalicious to return true for cached URL")
	}

	if manager.IsMalicious("http://benign.test/path") {
		t.Error("Expected IsMalicious to return false for unknown URL")
	}
}

func TestFetchUpdatesInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{invalid json"))
	}))
	defer server.Close()

	manager := NewIntelManager()
	manager.feeds = []ThreatFeed{{Name: "bad-feed", URL: server.URL}}

	if err := manager.FetchUpdates(); err == nil {
		t.Error("Expected error when decoding invalid JSON, got nil")
	}
}
