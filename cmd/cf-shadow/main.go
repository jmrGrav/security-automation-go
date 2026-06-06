// cf-shadow runs the CrowdSec → Cloudflare enforcement logic in shadow mode:
// Go computes sync plans each cycle but never mutates Cloudflare.
// Python remains the authoritative enforcement daemon.
//
// Usage:
//
//	cf-shadow [--config /path/to/config.yaml] [--report-dir /var/lib/security-automation-go]
//
// Environment:
//
//	All variables supported by crowdsec-sync plus:
//	  SHADOW_REPORT_DIR   directory for SHADOW_MODE_REPORT.md and analysis files
//	  SHADOW_CONFIG       path to YAML config file
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/jm/security-automation-go/internal/app"
	"github.com/jm/security-automation-go/internal/config"
)

func main() {
	configPath := flag.String("config", envOr("SHADOW_CONFIG", ""), "Path to YAML config file")
	reportDir := flag.String("report-dir", envOr("SHADOW_REPORT_DIR", ""), "Directory for shadow mode reports")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cf-shadow: failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Report directory defaults to StateDir from config.
	rDir := *reportDir
	if rDir == "" {
		rDir = cfg.StateDir
	}
	reportPath := filepath.Join(rDir, "SHADOW_MODE_REPORT.md")

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	logger.Info("starting cf-shadow",
		"state_dir", cfg.StateDir,
		"report_dir", rDir,
		"interval", cfg.Interval,
		"zone_id", cfg.Cloudflare.ZoneID,
	)
	logger.Info("SHADOW MODE: Go will compute plans but NOT mutate Cloudflare",
		"python_authority", "Python daemon remains the enforcement authority",
		"report", reportPath,
	)

	syncApp := app.NewCrowdSecSyncApp(logger, cfg).WithShadowMode(reportPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("signal received, shutting down", "signal", sig)
		cancel()
	}()

	if err := syncApp.Run(ctx); err != nil {
		logger.Error("cf-shadow exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("cf-shadow stopped cleanly")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
