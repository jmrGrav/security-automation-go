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
	"syscall"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aigateway "github.com/jm/security-automation-go/internal/ai/gateway"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aianthropic "github.com/jm/security-automation-go/internal/ai/providers/anthropic"
	aigemini "github.com/jm/security-automation-go/internal/ai/providers/gemini"
	aiopenai "github.com/jm/security-automation-go/internal/ai/providers/openai"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/ui"
)

func runUI(ctx context.Context, logger *slog.Logger, cfg *config.Config) error {
	if !cfg.UI.Enabled {
		return errors.New("ui mode requires UI_ENABLED=1 or ui.enabled=true")
	}
	auditSink, err := ui.NewFileAuditSink(filepath.Join(cfg.StateDir, "ui-audit.log"))
	if err != nil {
		return err
	}
	aiCfg := ai.FromEnv()
	server, err := ui.NewServer(cfg, ui.Options{
		SecretProvider: ui.NewFileSecretProvider(cfg.UI.SecretFile),
		AuditSink:      auditSink,
		Logger:         logger,
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
	add := func(name string, enabled bool, model, keyFile string, newProvider func(ai.ProviderConfig) providers.Provider) {
		if !enabled {
			return
		}
		provider := newProvider(ai.ProviderConfig{
			Enabled:    enabled,
			Model:      model,
			APIKeyFile: keyFile,
		})
		if enabler, ok := provider.(interface{ Enabled() bool }); ok && !enabler.Enabled() {
			if logger != nil {
				logger.Warn("AI provider unavailable", "provider", name, "reason", "disabled or secret file missing")
			}
			return
		}
		out = append(out, provider)
	}

	add("openai", cfg.OpenAI.Enabled, cfg.OpenAI.Model, cfg.OpenAI.APIKeyFile, func(pc ai.ProviderConfig) providers.Provider {
		return aiopenai.New(pc)
	})
	add("anthropic", cfg.Anthropic.Enabled, cfg.Anthropic.Model, cfg.Anthropic.APIKeyFile, func(pc ai.ProviderConfig) providers.Provider {
		return aianthropic.New(pc)
	})
	add("gemini", cfg.Gemini.Enabled, cfg.Gemini.Model, cfg.Gemini.APIKeyFile, func(pc ai.ProviderConfig) providers.Provider {
		return aigemini.New(pc)
	})

	return out
}
