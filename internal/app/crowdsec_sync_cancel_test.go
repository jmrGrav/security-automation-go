package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
)

// TestSyncCloudflareStopsBetweenMutationsWhenContextIsCanceled proves the live
// CrowdSec->Cloudflare sync loop honors context cancellation between mutations
// (e.g. daemon shutdown / lost lease) instead of continuing to issue throttled
// Cloudflare writes. It mirrors the cleanup path guarantee.
func TestSyncCloudflareStopsBetweenMutationsWhenContextIsCanceled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"

	ctx, cancel := context.WithCancel(context.Background())
	cf := &cleanupFakeCloudflare{rules: map[string]string{
		"5.6.7.8":    "delete-rule-1",
		"9.10.11.12": "delete-rule-2",
	}}
	// Both rules are stale (no active bans) so both are scheduled for deletion.
	// Cancel after the first delete to prove the loop stops before the next one.
	cf.onDelete = cancel

	app := &CrowdSecSyncApp{
		logger: logger,
		cfg:    cfg,
		cf:     cf,
		cs:     &cleanupFakeCrowdSec{activeBans: nil},
	}

	if err := app.syncCloudflare(ctx, logger); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if len(cf.deleteCalls) != 1 {
		t.Fatalf("expected sync to stop before second delete after cancellation, got %+v", cf.deleteCalls)
	}
}
