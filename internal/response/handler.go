// Package response handles automated incident response actions triggered
// by vulnerability discoveries.
package response

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/coppertone/bug-hunter/app/aegis/internal/logger"
)

// Action defines the structure of an automated response, including
// the target system and any required metadata.
type Action struct {
	Type    string                 // Action type (e.g., "ALERT", "REVOKE")
	Target  string                 // The system or user identifier targeted
	Payload map[string]interface{} // Metadata associated with the action
}

// ResponseHandler manages the execution of incident response workflows,
// such as sending notifications to webhooks.
type ResponseHandler struct {
	webhookURL string
	log        *logger.Logger
}

// NewResponseHandler initializes a handler with a target webhook URL.
func NewResponseHandler(webhookURL string) *ResponseHandler {
	return &ResponseHandler{
		webhookURL: webhookURL,
		log:        logger.New(),
	}
}

// Trigger executes the specified Action. If a webhook URL is configured,
// it sends a POST request with the action payload.
func (h *ResponseHandler) Trigger(action Action) error {
	h.log.Info("Triggering IR action", "type", action.Type, "target", action.Target)

	if h.webhookURL == "" {
		return nil
	}

	data, _ := json.Marshal(action)
	resp, err := http.Post(h.webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to trigger webhook: %w", err)
	}
	defer resp.Body.Close()

	return nil
}
