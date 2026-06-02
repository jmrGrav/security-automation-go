package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	runtimebreaker "github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func initRuntimeScope(cfg *config.Config, logger *slog.Logger) (scope.RuntimeScope, string) {
	currentScope := scope.RuntimeScope{
		Tenant:      cfg.Global.ServiceName,
		AccountID:   "shared",
		ZoneID:      cfg.Cloudflare.ZoneID,
		Environment: "production",
	}
	scopeDir := filepath.Join(cfg.StateDir, currentScope.ID())
	_ = os.MkdirAll(scopeDir, 0o755)

	logger.Info("runtime scope initialized",
		"scope_id", currentScope.ID(),
		"scope_name", currentScope.String(),
		"scope_dir", scopeDir,
	)

	return currentScope, scopeDir
}

func initScopedState(scopeDir string) (*state.StateStore, journal.JournalStore, *runtimebreaker.CircuitBreaker) {
	stateStore := state.NewStateStore(scopeDir)
	jsonlJournal := journal.NewJSONLJournal(filepath.Join(scopeDir, "audit.jsonl"))
	cb := runtimebreaker.New(5, 5*time.Minute, 1*time.Minute)
	return stateStore, jsonlJournal, cb
}

func initHTTPClient(cfg *config.Config) httpclient.Client {
	return httpclient.New(cfg.Global.HTTP)
}

func initSQLite(scopeDir string, scopeID string) (*sqlite.DB, *sqlite.EventRepository, *sqlite.ReportingStores, *sqlite.OwnershipRepository, *sqlite.LeaseRepository, *sqlite.CursorStore, error) {
	sqliteDB, err := sqlite.New(scopeDir)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("failed to initialize SQLite database in scope %q: %w", scopeID, err)
	}
	reportingStores := sqlite.NewReportingStores(sqliteDB)
	return sqliteDB, sqlite.NewEventRepository(sqliteDB), reportingStores, sqlite.NewOwnershipRepository(sqliteDB), sqlite.NewLeaseRepository(sqliteDB), reportingStores.Cursors, nil
}
