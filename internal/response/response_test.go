package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseHandlerInitialization(t *testing.T) {
	handler := NewResponseHandler("https://example.com/webhook")

	if handler == nil {
		t.Error("Expected ResponseHandler to be initialized, got nil")
	}

	if handler.webhookURL != "https://example.com/webhook" {
		t.Errorf("Expected webhook URL to be set, got %s", handler.webhookURL)
	}
}

func TestActionStructure(t *testing.T) {
	action := Action{
		Type:   "ALERT",
		Target: "user@example.com",
		Payload: map[string]interface{}{
			"severity": "high",
			"details":  "test alert",
		},
	}

	if action.Type != "ALERT" {
		t.Errorf("Expected action type to be ALERT, got %s", action.Type)
	}

	if action.Target != "user@example.com" {
		t.Errorf("Expected action target to be user@example.com, got %s", action.Target)
	}
}

func TestTriggerWithWebhook(t *testing.T) {
	var received Action
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Expected application/json content type, got %s", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	handler := NewResponseHandler(server.URL)
	action := Action{
		Type:   "ALERT",
		Target: "service-1",
		Payload: map[string]interface{}{
			"severity": "high",
			"details":  "test alert",
		},
	}

	if err := handler.Trigger(action); err != nil {
		t.Fatalf("Trigger failed: %v", err)
	}

	if received.Type != action.Type {
		t.Errorf("Expected action type %s, got %s", action.Type, received.Type)
	}
	if received.Target != action.Target {
		t.Errorf("Expected action target %s, got %s", action.Target, received.Target)
	}
	if received.Payload["severity"] != action.Payload["severity"] {
		t.Errorf("Expected payload severity %v, got %v", action.Payload["severity"], received.Payload["severity"])
	}
}

func TestTriggerWithoutWebhook(t *testing.T) {
	handler := NewResponseHandler("")
	action := Action{Type: "ALERT", Target: "service-2"}

	if err := handler.Trigger(action); err != nil {
		t.Fatalf("Expected nil error with empty webhook URL, got %v", err)
	}
}
