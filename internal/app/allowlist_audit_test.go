package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
)

type allowlistFakeCrowdSec struct {
	entries []csmodels.AllowlistEntry
	err     error
	calls   int
}

func (f *allowlistFakeCrowdSec) ListAllowlist(_ context.Context, _ string) ([]csmodels.AllowlistEntry, error) {
	f.calls++
	return append([]csmodels.AllowlistEntry(nil), f.entries...), f.err
}

func (f *allowlistFakeCrowdSec) AddAllowlistEntry(context.Context, string, csmodels.AllowlistEntry) error {
	return nil
}

func TestAllowlistSyncListsEntriesWithoutMutation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.CrowdSec.AllowlistName = "my_allowlist"
	cs := &allowlistFakeCrowdSec{entries: []csmodels.AllowlistEntry{{Value: "1.2.3.4"}}}
	app := &AllowlistSyncApp{logger: logger, cfg: cfg, cs: cs}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("allowlist sync: %v", err)
	}
	if cs.calls != 1 {
		t.Fatalf("expected exactly one allowlist fetch, got %d", cs.calls)
	}
}

func TestAllowlistSyncFailsClosedOnAllowlistError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cs := &allowlistFakeCrowdSec{err: errors.New("cscli failed")}
	app := &AllowlistSyncApp{logger: logger, cfg: cfg, cs: cs}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("expected allowlist sync to fail closed on allowlist error")
	}
}
