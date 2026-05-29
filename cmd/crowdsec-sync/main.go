package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jm/security-automation-go/internal/app"
	"github.com/jm/security-automation-go/internal/config"
)

func main() {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Printf("failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	syncApp := app.NewCrowdSecSyncApp(logger, cfg)

	if err := syncApp.Run(context.Background()); err != nil {
		logger.Error("crowdsec sync failed", "error", err)
		os.Exit(1)
	}
}
