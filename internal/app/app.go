package app

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cidrban"
	"github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec"
	cspoller "github.com/jm/security-automation-go/internal/crowdsec/poller"
	"github.com/jm/security-automation-go/internal/httpclient"
	luastate "github.com/jm/security-automation-go/internal/openresty/state"
	"github.com/jm/security-automation-go/internal/recidive"
	"github.com/jm/security-automation-go/internal/security/protected"
	"github.com/jm/security-automation-go/internal/shadow"
	"github.com/jm/security-automation-go/internal/state"
)

// NOTE_TAG is the Cloudflare rule notes tag for CrowdSec-managed bans.
// Mirrors Python's NOTE_TAG = "crowdsec-local-ban".
const NOTE_TAG = "crowdsec-local-ban"

// NOTE_TAG_CIDR is the notes tag for automatic /24 CIDR bans.
const NOTE_TAG_CIDR = "crowdsec-cidr-ban"

type Runner interface {
	Run(ctx context.Context) error
}

type CrowdSecSyncApp struct {
	logger      *slog.Logger
	cfg         *config.Config
	store       state.Store
	cf          cloudflare.EnforcementClient
	cs          crowdsec.ActiveBanSource
	csDecisions crowdsec.DecisionManager
	csAllowlist crowdsec.AllowlistManager // for per-cycle allowlist fetch
	abuse       *abuseipdb.Client
	better      betterstack.IngestClient
	recidiv     recidive.Service
	cidr        cidrban.Service

	// Anti-self-ban shield (P0 safety).
	shield *protected.Shield

	// Shadow mode: compute plans but do not mutate Cloudflare.
	shadowMode   bool
	shadowStore  *shadow.Store
	shadowReport string // path to SHADOW_MODE_REPORT.md

	// luaWriter publishes bans.json for the OpenResty Lua bouncer (optional).
	luaWriter *luastate.Writer

	// poller is the Go replacement for crowdsec-poller.py. Nil when disabled.
	poller *cspoller.Poller
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
	cf     cloudflare.EnforcementClient
	cs     crowdsec.ActiveBanSource
	dryRun bool
}

func NewCrowdSecSyncApp(logger *slog.Logger, cfg *config.Config) *CrowdSecSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	cfClient := cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken)
	csClient := crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout)

	var abuse *abuseipdb.Client
	if cfg.AbuseIPDB.APIKey != "" && !abuseIPDBReportingDisabled(cfg) {
		abuse = abuseipdb.NewClient(cfg.AbuseIPDB.APIKey, httpClient)
	}

	shield := protected.New()

	return &CrowdSecSyncApp{
		logger:      logger,
		cfg:         cfg,
		store:       state.NewJSONStore(cfg.StateDir),
		cf:          cfClient,
		cs:          csClient,
		csDecisions: csClient,
		csAllowlist: csClient,
		abuse:       abuse,
		better:      betterstack.NewClient(httpClient, cfg.BetterStack.SourceToken, cfg.BetterStack.IngestingHost),
		recidiv: recidive.NewService(recidive.Config{
			StateDir: cfg.StateDir,
			BanSource: &recidiveBanSourceAdapter{
				src:           csClient,
				shield:        shield,
				csAllowlist:   csClient,
				allowlistName: cfg.CrowdSec.AllowlistName,
			},
			Escalator: csClient,
		}),
		cidr: cidrban.NewService(cidrban.Config{
			StateDir: cfg.StateDir,
			BanSource: &cidrBanSourceAdapter{
				src:           csClient,
				shield:        shield,
				csAllowlist:   csClient,
				allowlistName: cfg.CrowdSec.AllowlistName,
			},
			CFBanner:      cfClient,
			CFRuleGetter:  cfClient,
			CFDeleter:     cfClient,
			CSRangeBanner: csClient,
			ZoneID:        cfg.Cloudflare.ZoneID,
		}),
		shield:       shield,
		shadowStore:  shadow.NewStore(cfg.StateDir),
		shadowReport: filepath.Join(cfg.StateDir, "SHADOW_MODE_REPORT.md"),
		luaWriter:    newLuaWriter(cfg),
		poller: cspoller.New(cspoller.Config{
			Enabled:  cfg.CrowdSec.PollerEnabled,
			LAPIURL:  cfg.CrowdSec.PollerLAPIURL,
			LAPIKey:  cfg.CrowdSec.PollerLAPIKey,
			Interval: cfg.CrowdSec.PollerInterval,
			LogPath:  cfg.CrowdSec.DecisionsLog,
			CscliBin: cfg.CrowdSec.BinPath,
			Timeout:  cfg.CrowdSec.Timeout,
		}, logger),
	}
}

func NewAllowlistSyncApp(logger *slog.Logger, cfg *config.Config) *AllowlistSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	return &AllowlistSyncApp{
		logger: logger,
		cfg:    cfg,
		cf:     cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken),
		cs:     crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout),
	}
}

func NewCleanupApp(logger *slog.Logger, cfg *config.Config) *CleanupApp {
	httpClient := httpclient.New(cfg.Global.HTTP)
	cfClient := cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken)
	csClient := crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout)
	return &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cfClient,
		cs:     csClient,
	}
}

// WithDryRun enables cleanup planning without mutating Cloudflare.
func (a *CleanupApp) WithDryRun() *CleanupApp {
	if a != nil {
		a.dryRun = true
	}
	return a
}

// WithShadowMode enables shadow mode: Go computes plans but does not mutate CF.
// The report path is where SHADOW_MODE_REPORT.md is written after each cycle.
func (a *CrowdSecSyncApp) WithShadowMode(reportPath string) *CrowdSecSyncApp {
	a.shadowMode = true
	if reportPath != "" {
		a.shadowReport = reportPath
	}
	return a
}
