package ui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aigateway "github.com/jm/security-automation-go/internal/ai/gateway"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/security"
	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

const (
	sessionCookieName = "ui_session"
	csrfHeaderName    = "X-CSRF-Token"
	sessionTTL        = 8 * time.Hour
)

// SetupStorer is the subset of sqlite.SetupStore used by the UI server.
// Using an interface keeps the UI package free of a hard dependency on sqlite.
type SetupStorer interface {
	GetCurrentStep(ctx context.Context) (int, error)
	SetCurrentStep(ctx context.Context, step int) error
	IsComplete(ctx context.Context) (bool, error)
	MarkComplete(ctx context.Context) error
	GetSetting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAuthEpoch(ctx context.Context) (int64, error)
	IncrementAuthEpoch(ctx context.Context) (int64, error)
	GetPasswordChangeRequired(ctx context.Context) (bool, error)
	SetPasswordChangeRequired(ctx context.Context, required bool) error
}

type CredentialStorer interface {
	Lookup(ctx context.Context, key string) (string, bool, error)
	Set(ctx context.Context, key, value string, enabled bool) error
	Delete(ctx context.Context, key string) error
	ImportLegacyDir(ctx context.Context, legacyDir string) (int, error)
}

var legacySecretsDirPath = "/etc/security-automation-go/secrets"

// BanDebanner is the UI-facing abstraction for operator-initiated Cloudflare
// deban actions on the /ban-lifecycle page. Implementations must only ever
// remove the Cloudflare rule and update banlifecycle.Store — debanning from
// Cloudflare must never delete AbuseIPDB report history or reset the
// AbuseIPDB reporting window.
type BanDebanner interface {
	DebanIP(ctx context.Context, ip, reason string) error
	ClearManagedBans(ctx context.Context, reason string) (BanClearResult, error)
}

// BanClearResult summarizes the outcome of a bulk "clear all managed bans"
// action, for audit logging and operator feedback.
type BanClearResult struct {
	Attempted int
	Deleted   int
	Skipped   int
	Failed    int
	Errors    []string
}

// NoteStorer persists operator annotations locally. Never influences provider decisions.
type NoteStorer interface {
	Upsert(ctx context.Context, entityType, entityValue, content string) error
	Get(ctx context.Context, entityType, entityValue string) (sqlite.Note, bool, error)
	Delete(ctx context.Context, entityType, entityValue string) error
	List(ctx context.Context) ([]sqlite.Note, error)
}

type Options struct {
	SecretProvider       SecretProvider
	CredentialStore      CredentialStorer
	AuditSink            AuditSink
	Logger               *slog.Logger
	Enrichment           *enrichment.Service
	EvidenceStore        reporting.EvidenceStore
	BanLifecycleStore    banlifecycle.Store
	BanDebanner          BanDebanner
	TrustedNetworksCache *trustednetworks.ReportCache
	// CrowdSecStatusStore is the read-only source for the CrowdSec spoke's
	// status (configured/auth_ok/last_sync_at/last_error/counts), persisted
	// by the separate root-owned cf-allowlist-sync helper. The UI never
	// calls cscli itself — it only reads this record.
	CrowdSecStatusStore   trustednetworks.CrowdSecStatusStore
	CrowdSecAllowlistName string
	// EventStore is the scoped runtime event journal, used by /timeline to
	// surface real lifecycle lineage (sequence numbers, correlation ids)
	// instead of leaving runtime events unread.
	EventStore          events.EventStore
	AIExplain           aigateway.Gateway
	AIExplainBuilder    func(ai.Config) aigateway.Gateway
	AIConfig            ai.Config
	ProviderFactories   map[string]ProviderFactory
	SetupStore          SetupStorer
	NoteStore           NoteStorer
	ValidateCloudflare  func(context.Context, string, string) error
	ValidateAbuseIPDB   func(context.Context, string) error
	ValidateBetterStack func(context.Context, string) error
}

type Server struct {
	cfg                   *config.Config
	secretProvider        SecretProvider
	credentialStore       CredentialStorer
	audit                 AuditSink
	logger                *slog.Logger
	mux                   *http.ServeMux
	sessions              map[string]time.Time
	mu                    sync.Mutex
	authEpoch             atomic.Int64
	sessionMax            int
	lastSessionSweep      time.Time
	sessionSweepEvery     time.Duration
	limiter               *rateLimiter
	aiLimiter             *rateLimiter
	aiMu                  sync.RWMutex
	uiSecret              string
	enrichment            *enrichment.Service
	aiBaseConfig          ai.Config
	aiExplain             aigateway.Gateway
	aiConfig              ai.Config
	aiExplainBuilder      func(ai.Config) aigateway.Gateway
	providerFactories     map[string]ProviderFactory
	setupStore            SetupStorer
	noteStore             NoteStorer
	evidence              reporting.EvidenceStore
	banLifecycleStore     banlifecycle.Store
	banDebanner           BanDebanner
	trustedNetworksCache  *trustednetworks.ReportCache
	crowdSecStatusStore   trustednetworks.CrowdSecStatusStore
	crowdSecAllowlistName string
	eventStore            events.EventStore
	validateCloudflare    func(context.Context, string, string) error
	validateAbuseIPDB     func(context.Context, string) error
	validateBetterStack   func(context.Context, string) error
	timelineMu            sync.Mutex
	timelineCache         []audit.TimelineEvent
	timelineCacheAt       time.Time
	timelineCacheLimit    int
	cfInventoryMu         sync.Mutex
	cfInventoryCache      cfRuleInventory
	cfInventoryCacheAt    time.Time
	// cfRuleLister overrides the live Cloudflare API call fetchCFRuleInventory
	// makes (see cfsync_page.go, issue #83). nil in production — the real
	// discovery.ListIPAccessRules implementation is used. Tests inject a fake
	// here, the same test-seam pattern as validateCloudflare, to avoid making
	// real outbound Cloudflare API calls.
	cfRuleLister func(ctx context.Context, token, zoneID string) ([]cfmodels.IPAccessRule, error)
}

func NewServer(cfg *config.Config, opts Options) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if opts.SecretProvider == nil {
		opts.SecretProvider = NewFileSecretProvider(cfg.UI.SecretFile)
	}
	if opts.AuditSink == nil {
		opts.AuditSink = noopAuditSink{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	uiSecret, err := opts.SecretProvider.Ensure("UI_SECRET")
	if err != nil {
		return nil, fmt.Errorf("load ui secret: %w", err)
	}

	state, loaded, err := loadAIStateFromStoreOrFile(context.Background(), opts.SetupStore, cfg.UI.ProviderStateFile)
	if err != nil {
		return nil, fmt.Errorf("load ai provider state: %w", err)
	}
	effectiveAIConfig := applyAIProviderState(opts.AIConfig, state, loaded)
	s := &Server{
		cfg:                   cfg,
		secretProvider:        opts.SecretProvider,
		credentialStore:       opts.CredentialStore,
		audit:                 opts.AuditSink,
		logger:                opts.Logger,
		mux:                   http.NewServeMux(),
		sessions:              make(map[string]time.Time),
		sessionMax:            4096,
		sessionSweepEvery:     time.Minute,
		limiter:               newRateLimiter(20, time.Minute),
		uiSecret:              uiSecret,
		enrichment:            opts.Enrichment,
		evidence:              opts.EvidenceStore,
		banLifecycleStore:     opts.BanLifecycleStore,
		banDebanner:           opts.BanDebanner,
		trustedNetworksCache:  opts.TrustedNetworksCache,
		crowdSecStatusStore:   opts.CrowdSecStatusStore,
		crowdSecAllowlistName: opts.CrowdSecAllowlistName,
		eventStore:            opts.EventStore,
		aiBaseConfig:          opts.AIConfig,
		aiConfig:              effectiveAIConfig,
		aiExplainBuilder:      opts.AIExplainBuilder,
		providerFactories:     opts.ProviderFactories,
		setupStore:            opts.SetupStore,
		noteStore:             opts.NoteStore,
		validateCloudflare:    opts.ValidateCloudflare,
		validateAbuseIPDB:     opts.ValidateAbuseIPDB,
		validateBetterStack:   opts.ValidateBetterStack,
	}
	if s.aiConfig.MaxContextBytes <= 0 {
		s.aiConfig.MaxContextBytes = 12_000
	}
	if s.aiConfig.MaxOutputTokens <= 0 {
		s.aiConfig.MaxOutputTokens = 800
	}
	if s.aiConfig.RateLimitPerMinute <= 0 {
		s.aiConfig.RateLimitPerMinute = 10
	}
	s.aiLimiter = newRateLimiter(s.aiConfig.RateLimitPerMinute, time.Minute)
	if s.aiExplainBuilder != nil {
		s.aiExplain = s.aiExplainBuilder(s.aiConfig)
	} else {
		s.aiExplain = opts.AIExplain
	}
	if opts.SetupStore != nil {
		if epoch, err := opts.SetupStore.GetAuthEpoch(context.Background()); err == nil {
			s.authEpoch.Store(epoch)
		}
	}
	s.routes()
	_ = s.rebuildAIExplainFromState()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.pruneSessions()
		s.mux.ServeHTTP(w, r)
	}))
}

// securityHeaders adds defensive HTTP headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// v2 routes load Google Fonts — extend CSP only for those paths.
		if strings.HasPrefix(r.URL.Path, "/v2/") {
			h.Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:")
		} else {
			h.Set("Content-Security-Policy",
				"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		}
		if r.URL.Path != "/login" {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	s.registerSetupRoutes() // must come first — setup routes bypass the guard
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.Handle("POST /ui/settings/password/change", s.forcePasswordChangeMiddleware(http.HandlerFunc(s.handleChangePassword)))
	s.mux.Handle("POST /logout", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleLogout)))))
	s.mux.Handle("GET /logout", s.setupGuardMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleLogoutGET))))
	s.mux.Handle("GET /", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleDashboard)))))
	s.mux.Handle("GET /search", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleDashboardSearch)))))
	s.mux.Handle("GET /providers", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProviders)))))
	s.mux.Handle("POST /admin/providers/{name}/key", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProviderReplaceKey)))))
	s.mux.Handle("POST /admin/providers/import-legacy", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleLegacyCredentialImport)))))
	s.mux.Handle("POST /admin/providers/{name}/test", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProviderTest)))))
	s.mux.Handle("POST /admin/providers/test-all", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProvidersTestAll)))))
	s.mux.Handle("POST /admin/providers/{name}/enable", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProviderEnable)))))
	s.mux.Handle("POST /admin/providers/{name}/disable", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProviderDisable)))))
	s.mux.Handle("POST /admin/providers/{name}/reset-diagnostics", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProviderResetDiagnostics)))))
	s.mux.Handle("GET /forensic", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleForensicPage)))))
	s.mux.Handle("POST /forensic", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleForensicLookup)))))
	s.mux.Handle("GET /evidence", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleEvidencePage)))))
	s.mux.Handle("GET /evidence/{id}", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleEvidenceDetailPage)))))
	s.mux.Handle("GET /pipeline", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handlePipelineHealthPage)))))
	s.mux.Handle("GET /nginx-access", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleNginxAccessPage)))))
	s.mux.Handle("GET /sync", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCFSyncPage)))))
	s.mux.Handle("GET /ban-lifecycle", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleBanLifecyclePage)))))
	s.mux.Handle("POST /actions/ban-lifecycle/deban", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleBanLifecycleDeban)))))
	s.mux.Handle("POST /actions/ban-lifecycle/clear", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleBanLifecycleClearAll)))))
	s.mux.Handle("GET /about", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleAboutPage)))))
	s.mux.Handle("GET /system", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleAboutPage)))))
	s.mux.Handle("GET /audit", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleAuditTrailPage)))))
	s.mux.Handle("GET /notes", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleNotesPage)))))
	s.mux.Handle("POST /notes", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleNoteUpsert)))))
	s.mux.Handle("POST /notes/delete", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleNoteDelete)))))
	s.mux.Handle("GET /timeline", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleTimelinePage)))))
	s.mux.Handle("GET /timeline/correlated", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCorrelatedTimelinePage)))))
	s.mux.Handle("GET /incident", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleIncidentPage)))))
	s.mux.Handle("GET /intelligence", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleIntelligencePage)))))
	s.mux.Handle("POST /intelligence", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleIntelligenceLookup)))))
	s.mux.Handle("GET /trusted-networks", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleTrustedNetworksPage)))))
	s.mux.Handle("GET /trusted-networks/export", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleTrustedNetworksExport)))))
	s.mux.Handle("GET /cloudflare/diff", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCloudflareDiffPage)))))
	s.mux.Handle("POST /actions/cloudflare/ban", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCloudflareBanPreview)))))
	s.mux.Handle("POST /ui/ai/explain", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleAIExplain)))))
	s.mux.Handle("GET /static/ai-explain.js", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleAIExplainScript)))))
	s.mux.Handle("GET /static/operator-live.js", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleOperatorLiveScript)))))
	s.mux.Handle("GET /static/providers-live.js", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleProvidersLiveScript)))))
	s.mux.Handle("GET /health", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleHealthPage)))))
	s.mux.Handle("GET /health/json", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleHealthJSON)))))
	s.mux.Handle("POST /health/diagnostic", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleRunDiagnostic)))))
	s.mux.Handle("GET /health/support-bundle", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleSupportBundle)))))
	s.mux.Handle("GET /settings/runtime", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleRuntimeSettings)))))
	s.mux.Handle("POST /settings/runtime", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleRuntimeSettingsPost)))))
	s.mux.Handle("GET /status/runtime", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleRuntimeStatus)))))
	s.registerCrowdSecAdminRoutes()

	// v2 UI — coexists with v1; same session cookie, separate prefix.
	s.mux.HandleFunc("GET /v2/login", s.handleV2LoginPage)
	s.mux.HandleFunc("POST /v2/login", s.handleV2Login)
	s.mux.Handle("GET /v2/", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandlerV2(s.handleV2Dashboard)))))
	s.mux.Handle("GET /v2/investigate", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandlerV2(s.handleV2Investigate)))))
	s.mux.Handle("GET /v2/static/attack-map.js", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandlerV2(s.handleV2AttackMapScript)))))
	s.mux.Handle("GET /v2/static/palette.js", s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandlerV2(s.handleV2PaletteScript)))))
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.isAuthed(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	_ = LoginPage("").Render(r.Context(), w)
}

func (s *Server) handleLogoutGET(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.pruneSessionsLocked(time.Now().UTC())
		s.mu.Unlock()
	}
	s.clearSessionCookie(w)
	eventID := newUIEventID()
	s.audit.Record("logout", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "ui_session",
		"result":         "success",
		"method":         "get",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		eventID := newUIEventID()
		s.audit.Record("logout", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "csrf_rejected",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.pruneSessionsLocked(time.Now().UTC())
		s.mu.Unlock()
	}
	s.clearSessionCookie(w)
	eventID := newUIEventID()
	s.audit.Record("logout", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "ui_session",
		"result":         "success",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	_ = DashboardConsolePage(s.dashboardConsoleViewForWindow(ctx, r.URL.Query().Get("window"))).Render(ctx, w)
}

func (s *Server) handleDashboardSearch(w http.ResponseWriter, r *http.Request) {
	target := dashboardSearchTarget(r.URL.Query().Get("q"))
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	view, _ := s.unifiedProvidersView()
	_ = UnifiedProvidersPage(view, s.csrfTokenFromRequest(r)).Render(r.Context(), w)
}

func (s *Server) handleAboutPage(w http.ResponseWriter, r *http.Request) {
	_ = AboutPage(r.URL.Path, BuildInfoFromConfig(s.cfg, s.providerHealthViews(), s.audit)).Render(r.Context(), w)
}

func (s *Server) handleAuditTrailPage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	eventID := newUIEventID()
	defer s.audit.Record("audit_view", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "audit",
		"result":         "read-only",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	_ = AuditTrailPage(s.auditTrailView(r.URL.Query().Get("q"), r.URL.RequestURI()), s.csrfTokenFromRequest(r)).Render(ctx, w)
}

func (s *Server) handleTimelinePage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	eventID := newUIEventID()
	defer s.audit.Record("timeline_view", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "timeline",
		"result":         "read-only",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	view := s.timelineView(r)
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format"))) {
	case "json":
		renderTimelineJSON(w, view)
	case "csv":
		renderTimelineCSV(w, view)
	default:
		_ = TimelinePage(view, s.csrfTokenFromRequest(r)).Render(ctx, w)
	}
}

func (s *Server) handleCloudflareDiffPage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	eventID := newUIEventID()
	defer s.audit.Record("cloudflare_diff_view", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "cloudflare-diff",
		"result":         "read-only",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	_ = workflowProjectionPage(s.cloudflareDiffView()).Render(ctx, w)
}

func (s *Server) handleCloudflareBanPreview(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.UI.MutationsEnabled {
		http.Error(w, "ui mutations disabled", http.StatusForbidden)
		return
	}
	if !s.cfg.Cloudflare.MutationsEnabled {
		http.Error(w, "cloudflare mutations disabled", http.StatusForbidden)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := r.PostForm.Get("ip")
	s.audit.Record("cloudflare_ban_preview", map[string]string{"ip": ip, "mode": "dry-run"})
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("dry-run"))
}

type aiExplainRequest struct {
	SubjectType        string `json:"subject_type"`
	SubjectID          string `json:"subject_id"`
	ProviderPreference string `json:"provider_preference"`
}

func (s *Server) handleAIExplain(w http.ResponseWriter, r *http.Request) {
	if !s.aiLimiter.Allow(clientKey(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req aiExplainRequest
	if err := dec.Decode(&req); err != nil {
		eventID := newUIEventID()
		s.audit.Record("ai_explain_failed", map[string]string{
			"target":         "ai_explain",
			"source":         "ui",
			"result":         "bad_json",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	subjectType := normalizeAISubjectType(req.SubjectType)
	if subjectType == "" {
		eventID := newUIEventID()
		s.audit.Record("ai_explain_failed", map[string]string{
			"source":         "ui",
			"target":         strings.TrimSpace(req.SubjectID),
			"subject_type":   req.SubjectType,
			"subject_id":     req.SubjectID,
			"result":         "invalid_subject_type",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "invalid subject_type", http.StatusBadRequest)
		return
	}
	providerPreference := normalizeAIProviderPreference(req.ProviderPreference)
	if providerPreference == "" {
		eventID := newUIEventID()
		s.audit.Record("ai_explain_failed", map[string]string{
			"source":         "ui",
			"target":         strings.TrimSpace(req.SubjectID),
			"subject_type":   subjectType,
			"subject_id":     req.SubjectID,
			"provider":       strings.TrimSpace(req.ProviderPreference),
			"result":         "invalid_provider_preference",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "invalid provider_preference", http.StatusBadRequest)
		return
	}
	eventID := newUIEventID()
	s.audit.Record("ai_explain_requested", map[string]string{
		"source":         "ui",
		"target":         strings.TrimSpace(req.SubjectID),
		"subject_type":   subjectType,
		"subject_id":     req.SubjectID,
		"provider":       providerPreference,
		"result":         "requested",
		"correlation_id": eventID,
		"event_id":       eventID,
	})

	response := ai.ExplainResponse{
		Provider:    "none",
		Model:       "",
		Cached:      false,
		QuotaState:  "UNKNOWN",
		Explanation: "AI explain unavailable: no provider is configured",
		ContextHash: "",
		AuditID:     eventID,
	}
	s.aiMu.RLock()
	explain := s.aiExplain
	aiCfg := s.aiConfig
	s.aiMu.RUnlock()
	if explain != nil {
		explainResp, err := explain.Explain(r.Context(), ai.ExplainRequest{
			SubjectType:        ai.SubjectType(subjectType),
			SubjectID:          req.SubjectID,
			ProviderPreference: providerPreference,
			MaxContextBytes:    aiCfg.MaxContextBytes,
			MaxOutputTokens:    aiCfg.MaxOutputTokens,
		})
		if err != nil {
			s.audit.Record("ai_explain_failed", map[string]string{
				"source":         "ui",
				"target":         strings.TrimSpace(req.SubjectID),
				"subject_type":   subjectType,
				"subject_id":     req.SubjectID,
				"provider":       providerPreference,
				"result":         "gateway_error",
				"correlation_id": eventID,
				"event_id":       eventID,
			})
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		response = explainResp
		response.AuditID = eventID
	}

	switch response.Provider {
	case "", "none":
		s.audit.Record("ai_provider_skipped", map[string]string{
			"source":         "ui",
			"target":         strings.TrimSpace(req.SubjectID),
			"subject_type":   subjectType,
			"subject_id":     req.SubjectID,
			"provider":       providerPreference,
			"result":         "unavailable",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		s.audit.Record("ai_explain_unavailable", map[string]string{
			"source":         "ui",
			"target":         strings.TrimSpace(req.SubjectID),
			"subject_type":   subjectType,
			"subject_id":     req.SubjectID,
			"provider":       providerPreference,
			"result":         "unavailable",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
	default:
		s.audit.Record("ai_provider_selected", map[string]string{
			"source":         "ui",
			"target":         strings.TrimSpace(req.SubjectID),
			"subject_type":   subjectType,
			"subject_id":     req.SubjectID,
			"provider":       response.Provider,
			"quota_state":    response.QuotaState,
			"context_hash":   response.ContextHash,
			"result":         "selected",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		if strings.Contains(strings.ToLower(response.Explanation), "unavailable") {
			s.audit.Record("ai_explain_unavailable", map[string]string{
				"source":         "ui",
				"target":         strings.TrimSpace(req.SubjectID),
				"subject_type":   subjectType,
				"subject_id":     req.SubjectID,
				"provider":       response.Provider,
				"result":         "unavailable",
				"correlation_id": eventID,
				"event_id":       eventID,
			})
		} else {
			s.audit.Record("ai_explain_completed", map[string]string{
				"source":         "ui",
				"target":         strings.TrimSpace(req.SubjectID),
				"subject_type":   subjectType,
				"subject_id":     req.SubjectID,
				"provider":       response.Provider,
				"quota_state":    response.QuotaState,
				"context_hash":   response.ContextHash,
				"result":         "completed",
				"correlation_id": eventID,
				"event_id":       eventID,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *Server) handleAIExplainScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, aiExplainScript())
}

func (s *Server) handleOperatorLiveScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, operatorLiveScript())
}

func (s *Server) handleProvidersLiveScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, providersLiveScript())
}

func (s *Server) handleForensicPage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	if ipStr := strings.TrimSpace(r.URL.Query().Get("ip")); ipStr != "" {
		// Deep-link: /forensic?ip=X performs the lookup inline.
		ip, err := netip.ParseAddr(ipStr)
		if err != nil || !ip.IsValid() {
			renderForensicPage(ctx, w, ForensicView{IP: ipStr, Error: "invalid IP address"}, s.csrfTokenFromRequest(r))
			return
		}
		view := ForensicView{IP: ipStr}
		if svc := s.securityIntelligenceService(); svc != nil {
			summary, err := svc.Enrich(ctx, ip, enrichment.LookupOptions{ManualForensics: true})
			if err == nil {
				view.Summary = summary
				view.Assess = svc.Assess(summary)
				view.HasEnrichment = true
			} else {
				view.EnrichmentError = fmt.Sprintf("enrichment failed: %v", err)
			}
		}
		if s.evidence != nil {
			local, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{IP: ipStr, Limit: 20})
			if err == nil {
				view.LocalEvidence = local
			}
		}
		if s.noteStore != nil {
			existing, _, _ := s.noteStore.Get(ctx, "ip", ipStr)
			view.NoteFormHTML = NoteFormHTML("ip", ipStr, existing.Content)
		}
		view.HasData = view.HasEnrichment || len(view.LocalEvidence) > 0
		renderForensicPage(ctx, w, view, s.csrfTokenFromRequest(r))
		return
	}
	renderForensicPage(ctx, w, ForensicView{}, s.csrfTokenFromRequest(r))
}

func (s *Server) handleForensicLookup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := stableUIReadContext(r.Context())
	defer cancel()
	if !s.validCSRF(r) {
		s.audit.Record("forensic_lookup", map[string]string{
			"result": "csrf_rejected",
		})
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderForensicPage(ctx, w, ForensicView{Error: "bad request"}, s.csrfTokenFromRequest(r))
		return
	}
	ipStr := strings.TrimSpace(r.PostForm.Get("ip"))
	view := ForensicView{IP: ipStr}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.IsValid() {
		view.Error = "invalid IP address"
		renderForensicPage(ctx, w, view, s.csrfTokenFromRequest(r))
		return
	}

	s.audit.Record("forensic_lookup", map[string]string{"ip": ipStr})

	if svc := s.securityIntelligenceService(); svc != nil {
		summary, err := svc.Enrich(ctx, ip, enrichment.LookupOptions{ManualForensics: true})
		if err == nil {
			view.Summary = summary
			view.Assess = svc.Assess(summary)
			view.HasEnrichment = true
		} else {
			view.EnrichmentError = fmt.Sprintf("enrichment failed: %v", err)
		}
	}

	if s.evidence != nil {
		local, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{
			IP:    ipStr,
			Limit: 20,
		})
		if err == nil {
			view.LocalEvidence = local
		}
	}

	if s.noteStore != nil {
		existing, _, _ := s.noteStore.Get(ctx, "ip", ipStr)
		view.NoteFormHTML = NoteFormHTML("ip", ipStr, existing.Content)
	}

	view.HasData = view.HasEnrichment || len(view.LocalEvidence) > 0
	renderForensicPage(ctx, w, view, s.csrfTokenFromRequest(r))
}

func (s *Server) requireAuthHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthed(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAuthHandlerV2(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isAuthed(r) {
			http.Redirect(w, r, "/v2/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) isAuthed(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	s.mu.Lock()
	s.pruneSessionsLocked(time.Now().UTC())
	expiry, ok := s.sessions[cookie.Value]
	if ok && time.Now().UTC().After(expiry) {
		delete(s.sessions, cookie.Value)
		ok = false
	}
	s.mu.Unlock()
	return ok
}

// setSessionCookie writes the session cookie to the response.
// Secure is unconditionally true: the UI binds to 127.0.0.1 only, and both
// http://localhost and http://127.0.0.1 qualify as "potentially trustworthy
// origins" under the W3C Secure Contexts spec (§3.2), so modern browsers
// (Chrome, Firefox 84+) store and send Secure cookies over the loopback
// interface without HTTPS. Keeping Secure:true as a compile-time constant also
// prevents CodeQL go/cookie-secure-not-set from re-triggering on future
// call sites.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
}

// clearSessionCookie instructs the browser to delete the session cookie.
// Secure must match the original Set-Cookie attributes so the browser honours
// the Max-Age:-1 expiry on the matching cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
}

func (s *Server) csrfTokenFor(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(s.uiSecret))
	_, _ = mac.Write([]byte(sessionToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	expected := s.csrfTokenFor(cookie.Value)
	if subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeaderName)), []byte(expected)) == 1 {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(r.FormValue("csrf_token")), []byte(expected)) == 1
}

func (s *Server) csrfTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return s.csrfTokenFor(cookie.Value)
}

func (s *Server) pruneSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSessionsLocked(time.Now().UTC())
}

func (s *Server) pruneSessionsLocked(now time.Time) {
	if s == nil {
		return
	}
	if !s.lastSessionSweep.IsZero() && now.Sub(s.lastSessionSweep) < s.sessionSweepEvery && len(s.sessions) <= s.sessionMax {
		metrics.UISessionEntries.Set(float64(len(s.sessions)))
		return
	}
	removed := 0
	for token, expiry := range s.sessions {
		if now.After(expiry) {
			delete(s.sessions, token)
			removed++
		}
	}
	if s.sessionMax > 0 && len(s.sessions) > s.sessionMax {
		type sessionItem struct {
			token  string
			expiry time.Time
		}
		items := make([]sessionItem, 0, len(s.sessions))
		for token, expiry := range s.sessions {
			items = append(items, sessionItem{token: token, expiry: expiry})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].expiry.Equal(items[j].expiry) {
				return items[i].token < items[j].token
			}
			return items[i].expiry.Before(items[j].expiry)
		})
		for len(s.sessions) > s.sessionMax && len(items) > 0 {
			victim := items[0]
			items = items[1:]
			delete(s.sessions, victim.token)
			removed++
		}
	}
	s.lastSessionSweep = now
	metrics.UISessionEntries.Set(float64(len(s.sessions)))
	if removed > 0 {
		metrics.UISessionsPrunedTotal.Add(float64(removed))
	}
}

func (s *Server) providerHealthViews() []ProviderHealth {
	ctx := context.Background()
	abState, abLoaded, _ := loadProviderRuntimeSnapshot(ctx, s.setupStore, "abuseipdb")
	shState, shLoaded, _ := loadProviderRuntimeSnapshot(ctx, s.setupStore, "spamhaus")
	vtState, vtLoaded, _ := loadProviderRuntimeSnapshot(ctx, s.setupStore, "virustotal")
	if !abLoaded {
		abState.Enabled = s.cfg.AbuseIPDB.Enabled
	}
	if !shLoaded {
		shState.Enabled = s.cfg.Spamhaus.Enabled
	}
	if !vtLoaded {
		vtState.Enabled = s.cfg.VirusTotal.Enabled
	}
	views := []ProviderHealth{
		{
			Name:           "AbuseIPDB",
			Enabled:        abState.Enabled,
			Configured:     credentialConfigured(ctx, s.credentialStore, "abuseipdb.api_key"),
			MaskedKey:      maskedCredentialStoreValue(ctx, s.credentialStore, "abuseipdb.api_key"),
			Status:         providerStatus(abState.Enabled, credentialConfigured(ctx, s.credentialStore, "abuseipdb.api_key")),
			Mode:           providerHealthModeText(abState.Healthy, abState.Enabled),
			LastValidation: providerHealthValidationText(abState.LastTestAt),
			LastSuccess:    providerLastSuccessText(abState.Enabled, abState.Healthy, abState.LastTestAt, abState.LastSuccessAt),
			LastError:      providerLastErrorText(abState.Enabled, abState.Healthy, abState.LastErrorCode),
			LastLatency:    formatLatencyMS(abState.LastLatencyMS),
			QuotaRemaining: "quota not exposed",
			Notes:          []string{"lookup/report split remains explicit"},
		},
		{
			Name:           "Spamhaus",
			Enabled:        shState.Enabled,
			Configured:     credentialConfigured(ctx, s.credentialStore, "spamhaus.api_key"),
			MaskedKey:      maskedCredentialStoreValue(ctx, s.credentialStore, "spamhaus.api_key"),
			Status:         providerStatus(shState.Enabled, credentialConfigured(ctx, s.credentialStore, "spamhaus.api_key")),
			Mode:           providerHealthModeText(shState.Healthy, shState.Enabled),
			LastValidation: providerHealthValidationText(shState.LastTestAt),
			LastSuccess:    providerLastSuccessText(shState.Enabled, shState.Healthy, shState.LastTestAt, shState.LastSuccessAt),
			LastError:      providerLastErrorText(shState.Enabled, shState.Healthy, shState.LastErrorCode),
			LastLatency:    formatLatencyMS(shState.LastLatencyMS),
			QuotaRemaining: "quota not exposed",
			Notes:          []string{"lookup/report split remains explicit"},
		},
		{
			Name:           "VirusTotal",
			Enabled:        vtState.Enabled,
			Configured:     credentialConfigured(ctx, s.credentialStore, "virustotal.api_key"),
			MaskedKey:      maskedCredentialStoreValue(ctx, s.credentialStore, "virustotal.api_key"),
			Status:         providerStatus(vtState.Enabled, credentialConfigured(ctx, s.credentialStore, "virustotal.api_key")),
			Mode:           providerHealthModeText(vtState.Healthy, vtState.Enabled),
			LastValidation: providerHealthValidationText(vtState.LastTestAt),
			LastSuccess:    providerLastSuccessText(vtState.Enabled, vtState.Healthy, vtState.LastTestAt, vtState.LastSuccessAt),
			LastError:      providerLastErrorText(vtState.Enabled, vtState.Healthy, vtState.LastErrorCode),
			LastLatency:    formatLatencyMS(vtState.LastLatencyMS),
			QuotaRemaining: "quota not exposed",
			Notes:          []string{"manual forensic only"},
		},
		{
			Name:           "DNS",
			Enabled:        s.cfg.Enrichment.DNSEnabled,
			Configured:     true,
			MaskedKey:      "local resolver",
			Status:         providerStatus(s.cfg.Enrichment.DNSEnabled, true),
			QuotaRemaining: "n/a",
			Notes:          []string{"net.Resolver", "timeout neutral"},
		},
		{
			Name:           "ASN",
			Enabled:        s.cfg.Enrichment.ASNEnabled,
			Configured:     true,
			MaskedKey:      "local classifier",
			Status:         providerStatus(s.cfg.Enrichment.ASNEnabled, true),
			QuotaRemaining: "n/a",
			Notes:          []string{"protected networks registry"},
		},
		{
			Name:           "Cloudflare",
			Enabled:        s.cfg.Cloudflare.MutationsEnabled,
			Configured:     s.cfSentinelToken() != "" && s.cfZoneIDFromSetup(context.Background()) != "",
			MaskedKey:      s.cfMaskedKey(),
			Status:         cloudflareHealthStatus(s.cfSentinelToken(), s.cfZoneIDFromSetup(context.Background()), s.cfg.Cloudflare.MutationsEnabled),
			QuotaRemaining: "quota not exposed",
			Notes:          []string{"live mutations remain feature-flagged"},
		},
		{
			Name:           "CrowdSec",
			Enabled:        true,
			Configured:     strings.TrimSpace(s.cfg.CrowdSec.APIKey) != "",
			MaskedKey:      maskedCrowdSecValue(s.cfg.CrowdSec.APIKey),
			Status:         crowdSecHealthStatus(s.cfg.CrowdSec.DecisionsLog),
			QuotaRemaining: "n/a",
			Notes:          []string{"single writer boundary only"},
		},
	}
	for i := range views {
		if views[i].Status == "" {
			views[i].Status = "unknown"
		}
	}
	return views
}

func (s *Server) dashboardConsoleView(ctx context.Context) DashboardConsoleView {
	return s.dashboardConsoleViewForWindow(ctx, "")
}

func (s *Server) dashboardConsoleViewForWindow(ctx context.Context, rawWindow string) DashboardConsoleView {
	checks := health.RunAll(s.buildHealthConfig())
	detectors := detect.RunAll(s.buildDetectConfig())
	statuses := []StatusItem{
		{Label: "Runtime", Level: "healthy", Detail: "UI mode active"},
		{Label: "CrowdSec", Level: statusLevelFromText(crowdSecHealthStatus(s.cfg.CrowdSec.DecisionsLog)), Detail: crowdSecHealthStatus(s.cfg.CrowdSec.DecisionsLog)},
		{Label: "Cloudflare", Level: statusLevelFromText(cloudflareHealthStatus(s.cfSentinelToken(), s.cfZoneIDFromSetup(ctx), s.cfg.Cloudflare.MutationsEnabled)), Detail: cloudflareHealthStatus(s.cfSentinelToken(), s.cfZoneIDFromSetup(ctx), s.cfg.Cloudflare.MutationsEnabled)},
		{Label: "OpenResty", Level: openRestyDashboardLevel(detectors), Detail: openRestyDashboardDetail(detectors, s.cfg.OpenResty.EventsFile)},
		{Label: "Nginx", Level: statusLevelFromText(nginxStatus(s.cfg.CrowdSec.NginxLogDir)), Detail: nginxStatus(s.cfg.CrowdSec.NginxLogDir)},
		{Label: "SQLite WAL", Level: statusLevelFromText(sqliteWALStatus(s.cfg.StateDir)), Detail: sqliteWALStatus(s.cfg.StateDir)},
		{Label: "UI", Level: boolStatus(s.cfg.UI.Enabled), Detail: uiStatus(s.cfg.UI.Enabled, s.cfg.UI.Addr)},
		{Label: "HA / fencing", Level: haFencingLevel(), Detail: haFencingDetail()},
		{Label: "Ownership", Level: "unknown", Detail: "lineage is recorded by the daemon process; not observable from the UI"},
		{Label: "UI mutations", Level: boolStatus(s.cfg.UI.MutationsEnabled), Detail: boolDetail(s.cfg.UI.MutationsEnabled, "enabled", "disabled")},
		{Label: "Cloudflare mutations", Level: cloudflareLevel(s.cfSentinelToken(), s.cfZoneIDFromSetup(ctx), s.cfg.Cloudflare.MutationsEnabled), Detail: cloudflareHealthStatus(s.cfSentinelToken(), s.cfZoneIDFromSetup(ctx), s.cfg.Cloudflare.MutationsEnabled)},
	}
	env := EnvironmentWidget{Total: len(detectors)}
	for _, c := range checks {
		switch c.Status {
		case health.Green:
			env.Green++
		case health.Yellow:
			env.Yellow++
		case health.Red:
			env.Red++
		}
	}
	for _, d := range detectors {
		if d.Healthy {
			env.Healthy++
		}
	}
	healthyCount, warningCount, errorCount, disabledCount := 0, 0, 0, 0
	for _, status := range statuses {
		switch strings.ToLower(strings.TrimSpace(status.Level)) {
		case "healthy", "live":
			healthyCount++
		case "warning", "degraded":
			warningCount++
		case "error":
			errorCount++
		case "disabled":
			disabledCount++
		}
	}

	updatedAt := time.Now().UTC()
	window := dashboardTimeWindow(rawWindow)
	windowFrom := dashboardWindowStart(window.Active, updatedAt)

	reportedTotal := 0
	reportedWindowTotal := 0
	if s.evidence != nil {
		if n, err := s.evidence.Count(ctx, reporting.EvidenceSearchOptions{AbuseIPDBReported: true}); err == nil {
			reportedTotal = n
		}
		if n, err := s.evidence.Count(ctx, reporting.EvidenceSearchOptions{AbuseIPDBReported: true, From: windowFrom}); err == nil {
			reportedWindowTotal = n
		}
	}

	providers := s.providerDashboardEntries()
	nonAIProviders := s.nonAIProviderEntries()
	activity := s.dashboardActivityFeedForWindow(ctx, windowFrom)
	threats := s.dashboardThreatView(ctx, windowFrom)
	freshness := []DashboardFreshnessView{
		dashboardFreshness("Dashboard", true, updatedAt),
		s.dashboardEvidenceFreshness(ctx),
		dashboardFreshness("Providers", len(providers)+len(nonAIProviders) > 0, latestProviderTestAt(providers, nonAIProviders)),
	}
	healthScore := dashboardHealthScore(statuses, env, providers, nonAIProviders, freshness, s.evidence != nil)
	commandCenter := DashboardCommandCenterView{
		Health:     healthScore,
		TimeWindow: window,
		Search: DashboardSearchView{
			Action:      "/search",
			Placeholder: "IP, evidence id, ASN, provider, scenario, forensic keyword",
		},
		Activity: activity,
		Threat:   threats,
		KPIs: []DashboardKPIView{
			{Label: "Health", Value: fmt.Sprintf("%d%%", healthScore.Score), Detail: "derived platform score", Href: "/health", Level: healthScore.Level},
			{Label: "AbuseIPDB reports", Value: strconv.Itoa(reportedWindowTotal), Detail: "windowed evidence-backed", Href: "/evidence?filter=reported", Level: "live"},
			{Label: "Providers", Value: strconv.Itoa(len(providers) + len(nonAIProviders)), Detail: "configured provider boundaries", Href: "/providers", Level: "healthy"},
			{Label: "Recent activity", Value: strconv.Itoa(len(activity.Items)), Detail: "bounded live feed", Href: "/timeline", Level: "live"},
		},
		Freshness: freshness,
	}

	return DashboardConsoleView{
		Statuses:      statuses,
		AIProviders:   providers,
		Environment:   env,
		ReportedTotal: reportedTotal,
		EvidenceWired: s.evidence != nil,
		UpdatedAt:     updatedAt.Format(time.RFC3339),
		HealthyCount:  healthyCount,
		WarningCount:  warningCount,
		ErrorCount:    errorCount,
		DisabledCount: disabledCount,
		CommandCenter: commandCenter,
	}
}

func (s *Server) auditTrailView(query, refreshURL string) AuditTrailView {
	reader, ok := s.audit.(AuditReader)
	if !ok || reader == nil {
		return AuditTrailView{Query: strings.TrimSpace(query), RefreshURL: refreshURL}
	}
	entries := reader.Entries()
	if q := strings.TrimSpace(strings.ToLower(query)); q != "" {
		entries = filterAuditEntries(entries, q)
	}
	return AuditTrailView{
		Entries:    entries,
		Query:      strings.TrimSpace(query),
		RefreshURL: refreshURL,
	}
}

// maskedCredentialStoreValue looks up key from the credential store and returns a redacted
// display string. Returns "" if the key is absent or the store is nil; never returns the raw value.
func maskedCredentialStoreValue(ctx context.Context, cs CredentialStorer, key string) string {
	if cs == nil {
		return ""
	}
	v, ok, err := cs.Lookup(ctx, key)
	if err != nil || !ok {
		return ""
	}
	return redactValue(v)
}

func maskedCloudflareValue(token string) string {
	if strings.TrimSpace(token) == "" {
		return "missing"
	}
	return redactValue(token)
}

// cfSentinelToken returns a non-empty string if a Cloudflare API token is configured
// in either the runtime config or the encrypted credential store. The returned string
// is a presence sentinel only — do not log or surface it as an actual token value.
func (s *Server) cfSentinelToken() string {
	if t := strings.TrimSpace(s.cfg.Cloudflare.APIToken); t != "" {
		return t
	}
	if credentialConfigured(context.Background(), s.credentialStore, "cloudflare.api_token") {
		return "ok"
	}
	return ""
}

func (s *Server) cfMaskedKey() string {
	if t := strings.TrimSpace(s.cfg.Cloudflare.APIToken); t != "" {
		return maskedCloudflareValue(t)
	}
	if credentialConfigured(context.Background(), s.credentialStore, "cloudflare.api_token") {
		return "configured (encrypted)"
	}
	return "missing"
}

func openRestyDashboardLevel(detectors []detect.Result) string {
	for _, d := range detectors {
		if d.Name == "openresty" {
			if d.Healthy {
				return "healthy"
			}
			if d.Installed {
				return "degraded"
			}
			return "disabled"
		}
	}
	return "disabled"
}

func openRestyDashboardDetail(detectors []detect.Result, eventsFile string) string {
	for _, d := range detectors {
		if d.Name == "openresty" {
			if d.Healthy {
				if strings.TrimSpace(eventsFile) != "" {
					if _, err := os.Stat(eventsFile); err == nil {
						return "OpenResty active (WAF events)"
					}
				}
				return "OpenResty active (nginx log mode)"
			}
			if d.Installed {
				return "OpenResty installed (service inactive)"
			}
			return "optional — not installed"
		}
	}
	return "optional — not installed"
}

func maskedCrowdSecValue(key string) string {
	if strings.TrimSpace(key) == "" {
		return "missing"
	}
	return redactValue(key)
}

func crowdSecHealthStatus(decisionsLog string) string {
	return crowdSecStatus(decisionsLog)
}

func cloudflareHealthStatus(token, zoneID string, live bool) string {
	return cloudflareStatus(token, zoneID, live)
}

func cloudflareLevel(token, zoneID string, live bool) string {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(zoneID) == "" {
		return "disabled"
	}
	if live {
		return "live"
	}
	return "dry-run"
}

func nginxStatus(logDir string) string {
	if strings.TrimSpace(logDir) == "" {
		return "Nginx unavailable / nginx log mode"
	}
	if _, err := os.Stat(logDir); err != nil {
		return "Nginx unavailable / nginx log mode"
	}
	return "Nginx ready"
}

func sqliteWALStatus(stateDir string) string {
	if strings.TrimSpace(stateDir) == "" {
		return "SQLite WAL unavailable"
	}
	if _, err := os.Stat(stateDir); err != nil {
		return "SQLite WAL unavailable"
	}
	return "SQLite WAL available"
}

func statusLevelFromText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "ready"):
		return "healthy"
	case strings.Contains(lower, "enabled"):
		return "live"
	case strings.Contains(lower, "live mutations"):
		return "live"
	case strings.Contains(lower, "configured dry-run"):
		return "dry-run"
	case strings.Contains(lower, "unavailable"):
		return "degraded"
	case strings.Contains(lower, "available"):
		return "healthy"
	case strings.Contains(lower, "disabled"):
		return "disabled"
	default:
		return "warning"
	}
}

// haFencingLevel/haFencingDetail report the real state of HA/fencing in this
// build: the dedicated HA subsystem (internal/runtime/ha) was deleted as dead
// code (issue #108, zero importers), and no config flag for HA or fencing
// exists in internal/config. "disabled" would wrongly imply an operator could
// turn it on; the honest state is that the feature is not present in this
// build at all. Single-instance fencing tokens/leases (internal/storage/sqlite
// lease.go, runtime/engine state machine) are internal scheduler plumbing, not
// the multi-node HA failover this status row historically described.
func haFencingLevel() string {
	return "unavailable"
}

func haFencingDetail() string {
	return "HA subsystem not present in this build (no multi-node failover support)"
}

func crowdSecStatus(decisionsLog string) string {
	if strings.TrimSpace(decisionsLog) == "" {
		return "CrowdSec unavailable / read-only fallback"
	}
	if _, err := os.Stat(decisionsLog); err != nil {
		return "CrowdSec unavailable / read-only fallback"
	}
	return "CrowdSec ready"
}

func cloudflareStatus(token, zoneID string, live bool) string {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(zoneID) == "" {
		return "Cloudflare disabled"
	}
	if !live {
		return "Cloudflare configured dry-run"
	}
	return "Cloudflare live mutations enabled"
}

func uiStatus(enabled bool, addr string) string {
	if !enabled {
		return "UI disabled"
	}
	if strings.TrimSpace(addr) == "" {
		return "UI enabled"
	}
	return "UI ready on " + addr
}

func providerStatus(enabled bool, configured bool) string {
	switch {
	case !configured && !enabled:
		return "disabled by operator"
	case !enabled:
		return "configured / disabled"
	case !configured:
		return "missing secret"
	default:
		return "configured / enabled"
	}
}

func normalizeAISubjectType(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "timeline_event", "audit_event", "provider", "intelligence", "trusted_network", "diff":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return ""
	}
}

func normalizeAIProviderPreference(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", "auto":
		return "auto"
	case "openai", "anthropic", "gemini":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return ""
	}
}

func (s *Server) forcePasswordChangeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow access to login and password change endpoints
		if r.URL.Path == "/login" || r.URL.Path == "/ui/settings/password/change" {
			next.ServeHTTP(w, r)
			return
		}

		// Check session
		_, ok := s.getSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Force password change: bootstrap (no hash set) or CLI reset flag.
		isBootstrap := s.isBootstrapActive()
		if isBootstrap {
			http.Redirect(w, r, "/ui/settings/password/change", http.StatusFound)
			return
		}
		if s.setupStore != nil {
			if required, err := s.setupStore.GetPasswordChangeRequired(r.Context()); err == nil && required {
				http.Redirect(w, r, "/ui/settings/password/change", http.StatusFound)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isBootstrapActive returns true when no permanent admin password hash is stored in SQLite,
// meaning the operator has not yet completed setup step 2. Returns false if setupStore is nil
// (legacy installs without wizard) or when a hash is present.
func (s *Server) isBootstrapActive() bool {
	if s.setupStore == nil {
		return false
	}
	_, ok, err := s.setupStore.GetSetting(context.Background(), "admin_password_hash")
	if err != nil {
		return false
	}
	return !ok
}

func clientKey(r *http.Request) string {
	info := security.GetRequestInfo(r, nil)
	if info != nil && info.SourceIP != "" {
		return info.SourceIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]*rateBucket
}

type rateBucket struct {
	windowStart time.Time
	count       int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, clients: make(map[string]*rateBucket)}
}

func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	// Evict stale buckets to prevent unbounded map growth.
	for k, b := range r.clients {
		if now.Sub(b.windowStart) > r.window*2 {
			delete(r.clients, k)
		}
	}
	b := r.clients[key]
	if b == nil || now.Sub(b.windowStart) > r.window {
		r.clients[key] = &rateBucket{windowStart: now, count: 1}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}
