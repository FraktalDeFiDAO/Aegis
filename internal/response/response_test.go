package response

import (
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