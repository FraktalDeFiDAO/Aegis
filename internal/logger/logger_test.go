package logger

import (
	"testing"
)

func TestLoggerInitialization(t *testing.T) {
	logger := New()

	if logger == nil {
		t.Error("Expected Logger to be initialized, got nil")
	}
}

func TestLoggerMethods(t *testing.T) {
	logger := New()
	
	// Test that methods exist and don't panic
	logger.Info("test message", "key", "value")
	logger.Error("test error", "error", "some error")
	logger.Warn("test warning", "warning", "some warning")
	
	// If we reach here, the methods didn't panic
}