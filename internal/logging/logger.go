package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jm/security-automation-go/internal/config"
)

func New(cfg config.GlobalConfig) *slog.Logger {
	return NewWithWriter(cfg, os.Stdout)
}

func NewWithWriter(cfg config.GlobalConfig, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)}

	var handler slog.Handler
	if strings.EqualFold(cfg.Log.Format, "text") {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	return slog.New(handler).With(
		slog.String("service", cfg.ServiceName),
		slog.String("env", cfg.AppEnv),
	)
}

func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, logger)
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if traceID == "" {
		traceID = NewTraceID()
	}
	return context.WithValue(ctx, traceIDContextKey{}, traceID)
}

func WithTraceLogger(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil {
		return ctx
	}
	traceID := TraceIDFromContext(ctx)
	if traceID == "" {
		ctx = WithTraceID(ctx, "")
		traceID = TraceIDFromContext(ctx)
	}
	return WithContext(ctx, logger.With(slog.String("trace_id", traceID)))
}

func FromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if ctx == nil {
		return fallback
	}
	logger, ok := ctx.Value(loggerContextKey{}).(*slog.Logger)
	if !ok || logger == nil {
		return fallback
	}
	return logger
}

func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	traceID, ok := ctx.Value(traceIDContextKey{}).(string)
	if !ok {
		return ""
	}
	return traceID
}

func NewTraceID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "trace-id-unavailable"
	}
	return hex.EncodeToString(buf[:])
}

type loggerContextKey struct{}
type traceIDContextKey struct{}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
