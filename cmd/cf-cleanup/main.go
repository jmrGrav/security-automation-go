package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/jm/security-automation-go/internal/app"
	"github.com/jm/security-automation-go/internal/config"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "plan cleanup without deleting Cloudflare rules")
	flag.Parse()

	cfg, err := config.Load("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cleanupApp := app.NewCleanupApp(logger, cfg)
	if *dryRun {
		cleanupApp.WithDryRun()
	}

	if err := cleanupApp.Run(context.Background()); err != nil {
		logger.Error("cleanup failed", "error", err)
		os.Exit(1)
	}
}
