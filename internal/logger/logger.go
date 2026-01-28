package logger

import (
	"log/slog"
	"os"
)

// Logger type alias for slog.Logger
type Logger = slog.Logger

// New creates a new JSON logger
func New() *Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}