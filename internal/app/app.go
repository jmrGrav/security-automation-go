package app

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cidrban"
	"github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/logging"
	"github.com/jm/security-automation-go/internal/modsecurity"
	"github.com/jm/security-automation-go/internal/recidive"
	"github.com/jm/security-automation-go/internal/scheduler"
	"github.com/jm/security-automation-go/internal/state"
)

type Runner interface {
	Run(ctx context.Context) error
}

type CrowdSecSyncApp struct {
	logger  *slog.Logger
	cfg     *config.Config
	store   state.Store
	cf      cloudflare.AccessRuleClient
	cs      crowdsec.ActiveBanSource
	abuse   *abuseipdb.Client
	better  betterstack.IngestClient
	modsec  modsecurity.Service
	recidiv recidive.Service
	cidr    cidrban.Service
}

type AllowlistSyncApp struct {
	logger *slog.Logger
	cfg    *config.Config
	cf     cloudflare.ListClient
	cs     crowdsec.AllowlistManager
}

type CleanupApp struct {
	logger *slog.Logger
	cfg    *config.Config
	cf     cloudflare.AccessRuleClient
}

func NewCrowdSecSyncApp(logger *slog.Logger, cfg *config.Config) *CrowdSecSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	var abuse *abuseipdb.Client
	if cfg.AbuseIPDB.APIKey != "" && !abuseIPDBReportingDisabled(cfg) {
		abuse = abuseipdb.NewClient(cfg.AbuseIPDB.APIKey, httpClient)
	}

	return &CrowdSecSyncApp{
		logger:  logger,
		cfg:     cfg,
		store:   state.NewJSONStore(cfg.StateDir),
		cf:      cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken),
		cs:      crowdsec.NewClient(),
		abuse:   abuse,
		better:  betterstack.NewClient(httpClient, cfg.BetterStack.SourceToken, cfg.BetterStack.IngestingHost),
		modsec:  modsecurity.NewPlaceholderService(),
		recidiv: recidive.NewPlaceholderService(),
		cidr:    cidrban.NewPlaceholderService(),
	}
}

func NewAllowlistSyncApp(logger *slog.Logger, cfg *config.Config) *AllowlistSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)

	return &AllowlistSyncApp{
		logger: logger,
		cfg:    cfg,
		cf:     cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken),
		cs:     crowdsec.NewClient(),
	}
}

func NewCleanupApp(logger *slog.Logger, cfg *config.Config) *CleanupApp {
	httpClient := httpclient.New(cfg.Global.HTTP)

	return &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken),
	}
}

func (a *CrowdSecSyncApp) Run(ctx context.Context) error {
	const op = "app.CrowdSecSyncApp.Run"

	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)

	logger.InfoContext(ctx, "starting crowdsec sync daemon", "interval", a.cfg.Interval)

	wafRuntime := newWAFReportingRuntime(ctx, logger, a.cfg, a.abuse, a.better)
	defer wafRuntime.close()

	runner := &scheduler.IntervalRunner{
		Name:     "crowdsec-sync",
		Interval: a.cfg.Interval,
		Timeout:  a.cfg.Interval,
	}
	task := schedulerTask(func(runCtx context.Context) error {
		runCtx = logging.WithTraceLogger(runCtx, a.logger)
		logger := logging.FromContext(runCtx, a.logger)
		logger.InfoContext(runCtx, "crowdsec sync tick")

		wafRuntime.processCrowdSec(runCtx, logger)
		wafRuntime.processOpenResty(runCtx, logger)
		wafRuntime.processOutbox(runCtx, logger)

		_ = a.store
		_ = a.cf
		_ = a.cs
		_ = a.abuse
		_ = a.better
		_ = a.modsec
		_ = a.recidiv
		_ = a.cidr
		return nil
	})

	if err := runner.Run(ctx, task); err != nil && !errors.Is(err, context.Canceled) {
		return apperr.Wrap(op, err)
	}
	return nil
}

func (a *AllowlistSyncApp) Run(ctx context.Context) error {
	const op = "app.AllowlistSyncApp.Run"

	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)
	logger.InfoContext(ctx, "starting allowlist sync daemon")

	_ = a.cf
	_ = a.cs
	return nil
}

func (a *CleanupApp) Run(ctx context.Context) error {
	const op = "app.CleanupApp.Run"

	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	ctx = logging.WithTraceLogger(ctx, a.logger)
	logger := logging.FromContext(ctx, a.logger)
	logger.InfoContext(ctx, "starting cleanup daemon")

	_ = a.cf
	return nil
}

type schedulerTask func(ctx context.Context) error

func (t schedulerTask) Run(ctx context.Context) error {
	return t(ctx)
}

func abuseIPDBReportingDisabled(cfg *config.Config) bool {
	return cfg != nil && cfg.AbuseIPDB.ReportingEnabled != nil && !*cfg.AbuseIPDB.ReportingEnabled
}
