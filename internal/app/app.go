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
	"github.com/jm/security-automation-go/internal/trustednetworks"
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

// AllowlistSyncApp is the root-run, oneshot helper that owns the entire
// CrowdSec-spoke reconcile for the trusted-networks registry. It is the
// ONLY process that ever invokes `cscli allowlists inspect/add` — the
// long-lived cf-sync daemon runs as the unprivileged security-automation
// user and cannot read /etc/crowdsec/local_api_credentials.yaml, so it must
// never attempt these calls itself. AllowlistSyncApp persists its result
// (success/failure, counts, drift) to SQLite via statusStore; the daemon
// and UI read that record instead of shelling out.
type AllowlistSyncApp struct {
	logger *slog.Logger
	cfg    *config.Config
	cf     cloudflare.ListClient

	// reg drives the actual reconcile. Its CrowdSec spoke is always set
	// (this app's whole purpose); its Cloudflare spoke is always nil — the
	// Cloudflare spoke of the trusted-networks registry continues to run
	// inside the long-lived daemon, unaffected by this helper.
	reg *trustednetworks.Registry

	// statusStore persists the CrowdSec spoke's reconcile result so the
	// daemon/UI can read live status without calling cscli themselves.
	statusStore trustednetworks.CrowdSecStatusStore
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

// NewAllowlistSyncApp builds the root-run CrowdSec-allowlist helper.
// tnStore is the trusted-networks registry's source of truth (the same
// SQLite-backed store the daemon reads); statusStore is where this helper
// persists its reconcile result for the daemon/UI to read. Both must be
// non-nil in production — callers (cmd/cf-allowlist-sync) construct them
// against the same STATE_DIR/scope the daemon uses.
func NewAllowlistSyncApp(logger *slog.Logger, cfg *config.Config, tnStore trustednetworks.Store, statusStore trustednetworks.CrowdSecStatusStore) *AllowlistSyncApp {
	httpClient := httpclient.New(cfg.Global.HTTP)

	reg := &trustednetworks.Registry{
		Store:                 tnStore,
		Mode:                  cfg.TrustedNetworks.EffectiveMode(),
		Logger:                logger,
		CrowdSec:              crowdsec.NewClientFromConfig(cfg.CrowdSec.BinPath, cfg.CrowdSec.DecisionsLog, cfg.CrowdSec.Timeout),
		CrowdSecAllowlistName: allowlistNameFromConfig(cfg),
	}

	return &AllowlistSyncApp{
		logger:      logger,
		cfg:         cfg,
		cf:          cloudflare.NewClient(httpClient, cfg.Cloudflare.APIToken),
		reg:         reg,
		statusStore: statusStore,
	}
}

// allowlistNameFromConfig resolves the cscli allowlist name the helper
// reconciles against: TrustedNetworks.CrowdSec.AllowlistName when set,
// falling back to the legacy top-level CrowdSec.AllowlistName so existing
// deployments that only set the latter keep working unchanged.
func allowlistNameFromConfig(cfg *config.Config) string {
	if cfg.TrustedNetworks.CrowdSec.AllowlistName != "" {
		return cfg.TrustedNetworks.CrowdSec.AllowlistName
	}
	return cfg.CrowdSec.AllowlistName
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
