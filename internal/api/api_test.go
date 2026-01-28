package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
