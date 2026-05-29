package logging

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
)

func TestNewWithWriterProducesJSONLogger(t *testing.T) {
	var buf bytes.Buffer

	logger := NewWithWriter(config.GlobalConfig{
		AppEnv:      "test",
		ServiceName: "logger-test",
		Log: config.LogConfig{
			Level:  "info",
			Format: "json",
		},
	}, &buf)

	logger.Info("hello")

	if buf.Len() == 0 {
		t.Fatal("expected log output")
	}
}

func TestContextRoundTrip(t *testing.T) {
	fallback := slog.Default()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	ctx := WithContext(context.Background(), logger)
	got := FromContext(ctx, fallback)
	if got != logger {
		t.Fatal("expected logger from context")
	}
}

func TestTraceLoggerAddsTraceID(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	ctx := WithTraceLogger(context.Background(), logger)

	if TraceIDFromContext(ctx) == "" {
		t.Fatal("expected trace ID in context")
	}
	if FromContext(ctx, nil) == nil {
		t.Fatal("expected logger in context")
	}
}
