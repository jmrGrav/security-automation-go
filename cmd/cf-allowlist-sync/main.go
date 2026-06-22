package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jm/security-automation-go/internal/app"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

// cf-allowlist-sync is the narrow, root-run, oneshot helper for the
// CrowdSec spoke of the trusted-networks registry. It is the ONLY process
// permitted to invoke `cscli allowlists inspect/add/remove`: the long-lived
// cf-sync daemon runs as the unprivileged security-automation user and
// cannot read /etc/crowdsec/local_api_credentials.yaml (root:root 0600).
//
// It opens the SAME scoped SQLite database the daemon uses (derived from
// the same STATE_DIR + Cloudflare zone the daemon was configured with),
// reads the trusted-networks registry from it, reconciles the CrowdSec
// allowlist, and writes the result back to the crowdsec_allowlist_status
// table for the daemon/UI to read.
func main() {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Mirrors cmd/cf-sync's initRuntimeScope: the scope must be derived
	// identically so this helper opens the exact same runtime.db the daemon
	// reads from and writes to.
	currentScope := scope.RuntimeScope{
		Tenant:      cfg.Global.ServiceName,
		AccountID:   "shared",
		ZoneID:      cfg.Cloudflare.ZoneID,
		Environment: "production",
	}
	scopeDir := filepath.Join(cfg.StateDir, currentScope.ID())
	if err := os.MkdirAll(scopeDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create scope dir %q: %v\n", scopeDir, err)
		os.Exit(1)
	}

	db, err := sqlite.New(scopeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open SQLite in scope %q: %v\n", scopeDir, err)
		os.Exit(1)
	}
	defer db.Close()

	tnStore := sqlite.NewTrustedNetworksStore(db)
	statusStore := sqlite.NewCrowdSecAllowlistStatusStore(db)

	syncApp := app.NewAllowlistSyncApp(logger, cfg, tnStore, statusStore)

	if err := syncApp.Run(context.Background()); err != nil {
		logger.Error("crowdsec allowlist sync failed", "error", err)
		os.Exit(1)
	}
}
