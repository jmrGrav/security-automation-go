package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jm/security-automation-go/internal/app"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func main() {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Resolve secrets from the encrypted CredentialStore — never from env or YAML.
	db, err := sqlite.New(cfg.StateDir)
	if err != nil {
		logger.Error("failed to open state db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	credStore := sqlite.NewCredentialStore(db)
	ctx := context.Background()
	if v, ok, _ := credStore.Lookup(ctx, "crowdsec.lapi_key"); ok {
		cfg.CrowdSec.PollerLAPIKey = v
	}

	syncApp := app.NewCrowdSecSyncApp(logger, cfg)

	if err := syncApp.Run(ctx); err != nil {
		logger.Error("crowdsec sync failed", "error", err)
		os.Exit(1)
	}
}
