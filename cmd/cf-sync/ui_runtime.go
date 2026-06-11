package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aigateway "github.com/jm/security-automation-go/internal/ai/gateway"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aianthropic "github.com/jm/security-automation-go/internal/ai/providers/anthropic"
	aigemini "github.com/jm/security-automation-go/internal/ai/providers/gemini"
	aiopenai "github.com/jm/security-automation-go/internal/ai/providers/openai"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/runtime/lock"
	"github.com/jm/security-automation-go/internal/startupcheck"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/ui"
)

func runUI(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	return runUIWithLocker(ctx, logger, cfg, true)
}

func runUIWithLocker(ctx context.Context, logger *slog.Logger, cfg *config.Config, acquireLock bool) error {
	if !cfg.UI.Enabled {
		return errors.New("ui mode requires UI_ENABLED=1 or ui.enabled=true")
	}

	// Extract port from address
	host, portStr, err := net.SplitHostPort(cfg.UI.Addr)
	if err != nil {
		return fmt.Errorf("parse ui.addr: %w", err)
	}
	port := parseInt(portStr)
	if port == 0 {
		return fmt.Errorf("invalid port in ui.addr: %s", portStr)
	}

	// Check port availability
	if err := startupcheck.CheckPortAvailable(host, port); err != nil {
		if pidErr, ok := err.(startupcheck.PortInUseError); ok {
			return fmt.Errorf("UI port %d already in use.\n\nPID: %d\nProcess: %s",
				port, pidErr.PID, pidErr.ProcName)
		}
		return err
	}

	if acquireLock {
		// Acquire instance lock
		lockFile := filepath.Join(cfg.StateDir, "security-automation-go.pid")
		locker, err := lock.NewFileLock(lockFile)
		if err != nil {
			return fmt.Errorf("create lock: %w", err)
		}

		if err := locker.Acquire(); err != nil {
			if lockErr, ok := err.(lock.PIDLockedError); ok {
				return fmt.Errorf("another instance (PID %d) is running", lockErr.PID)
			}
			return err
		}
		defer locker.Release()
		logger.Info("instance lock acquired", "lock_file", lockFile)
	}

	// Open SQLite for setup wizard state persistence.
	setupDB, err := sqlite.New(cfg.StateDir)
	if err != nil {
		return fmt.Errorf("open setup db: %w", err)
	}
	defer setupDB.Close()
	setupStore := sqlite.NewSetupStore(setupDB)
	credentialStore := sqlite.NewCredentialStore(setupDB)

	if v, ok, _ := credentialStore.Lookup(ctx, "cloudflare.api_token"); ok {
		cfg.Cloudflare.APIToken = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "abuseipdb.api_key"); ok {
		cfg.AbuseIPDB.APIKey = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "betterstack.source_token"); ok {
		cfg.BetterStack.SourceToken = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "crowdsec.lapi_key"); ok {
		cfg.CrowdSec.APIKey = v
	}

	// Apply wizard settings as runtime overrides (wizard stores these in SQLite).
	if v, ok, _ := setupStore.GetSetting(ctx, "ui_addr"); ok && v != "" {
		cfg.UI.Addr = v
	}
	if v, ok, _ := setupStore.GetSetting(ctx, "mutations_enabled"); ok && v == "true" {
		cfg.UI.MutationsEnabled = true
	}

	if rflags, err := setupStore.GetRuntimeFlags(ctx); err == nil {
		if rflags.CSPollerEnabled {
			cfg.CrowdSec.PollerEnabled = true
		}
		if rflags.CloudflareMutationsEnabled {
			cfg.Cloudflare.MutationsEnabled = true
			cfg.UI.MutationsEnabled = true
		}
		if rflags.AbuseIPDBEnabled {
			cfg.AbuseIPDB.Enabled = true
		}
	} else {
		logger.Warn("could not read runtime flags from SQLite", "error", err)
	}

	// Phase 5 — Setup Mode UX: log the wizard URL if setup is not yet complete.
	// The operator sees this in journald immediately after systemctl start cf-sync.
	if complete, _ := setupStore.IsComplete(ctx); !complete {
		logger.Info("first boot setup required — open in browser to create admin password",
			"url", "http://"+cfg.UI.Addr+"/setup/step/1",
			"action", "complete_wizard_before_enabling_production")
	}

	auditSink, err := ui.NewFileAuditSink(filepath.Join(cfg.StateDir, "ui-audit.log"))
	if err != nil {
		return err
	}
	aiCfg := ai.FromEnv()
	if v, ok, _ := credentialStore.Lookup(ctx, "ai.openai.api_key"); ok {
		aiCfg.OpenAI.APIKey = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "ai.anthropic.api_key"); ok {
		aiCfg.Anthropic.APIKey = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "ai.gemini.api_key"); ok {
		aiCfg.Gemini.APIKey = v
	}
	server, err := ui.NewServer(cfg, ui.Options{
		SetupStore:      setupStore,
		CredentialStore: credentialStore,
		SecretProvider:  ui.NewFileSecretProvider(cfg.UI.SecretFile),
		AuditSink:       auditSink,
		Logger:          logger,
		AIExplainBuilder: func(effective ai.Config) aigateway.Gateway {
			return aigateway.NewService(effective, buildAIProviders(effective, logger), nil, auditSink)
		},
		AIConfig: aiCfg,
		ProviderFactories: map[string]ui.ProviderFactory{
			"openai":    func(pc ai.ProviderConfig) providers.Provider { return aiopenai.New(pc) },
			"anthropic": func(pc ai.ProviderConfig) providers.Provider { return aianthropic.New(pc) },
			"gemini":    func(pc ai.ProviderConfig) providers.Provider { return aigemini.New(pc) },
		},
	})
	if err != nil {
		return err
	}

	if host, _, err := net.SplitHostPort(cfg.UI.Addr); err == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
			logger.Warn("ui server binding to non-loopback address — restrict access at the network level",
				"addr", cfg.UI.Addr)
		}
	}

	httpSrv := &http.Server{
		Addr:              cfg.UI.Addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting ui server", "addr", cfg.UI.Addr)
		errCh <- httpSrv.ListenAndServe()
	}()

	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-sigCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("ui server failed: %w", err)
	}
}

func buildAIProviders(cfg ai.Config, logger *slog.Logger) []providers.Provider {
	if !cfg.Enabled {
		return nil
	}
	out := make([]providers.Provider, 0, 3)
	add := func(name string, enabled bool, model, apiKey string, newProvider func(ai.ProviderConfig) providers.Provider) {
		if !enabled {
			return
		}
		provider := newProvider(ai.ProviderConfig{
			Enabled: enabled,
			Model:   model,
			APIKey:  apiKey,
		})
		if enabler, ok := provider.(interface{ Enabled() bool }); ok && !enabler.Enabled() {
			if logger != nil {
				logger.Warn("AI provider unavailable", "provider", name, "reason", "disabled or credential missing")
			}
			return
		}
		out = append(out, provider)
	}

	add("openai", cfg.OpenAI.Enabled, cfg.OpenAI.Model, cfg.OpenAI.APIKey, func(pc ai.ProviderConfig) providers.Provider {
		return aiopenai.New(pc)
	})
	add("anthropic", cfg.Anthropic.Enabled, cfg.Anthropic.Model, cfg.Anthropic.APIKey, func(pc ai.ProviderConfig) providers.Provider {
		return aianthropic.New(pc)
	})
	add("gemini", cfg.Gemini.Enabled, cfg.Gemini.Model, cfg.Gemini.APIKey, func(pc ai.ProviderConfig) providers.Provider {
		return aigemini.New(pc)
	})

	return out
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
