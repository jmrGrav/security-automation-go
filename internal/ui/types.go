package ui

import (
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// CFSyncView is the view model for the /sync (Cloudflare ban sync) page.
// It is derived entirely from banlifecycle.Store (runtime.db) — the same
// source of truth the live daemon's reactive ban/cleanup path writes to.
// The legacy periodic "shadow plan" diffing (planned adds/deletes vs a
// JSONL cycle log) belongs to the separate shadow-mode parity-validation
// tooling (cmd/cf-shadow, cmd/crowdsec-sync), which the live cf-sync daemon
// does not run, so this page no longer reads or reflects that data.
type CFSyncView struct {
	Wired          bool // false when banLifecycleStore is not configured in this build
	Error          string
	MutationsOn    bool // true when Cloudflare mutations are enabled
	DryRun         bool // true when CF mutations are disabled (observation-only)
	HasActivity    bool
	ActiveCount    int
	StatusCounts   map[string]int // status -> count, tallied over the recent sample
	SampleSize     int            // number of recent lifecycle entries the tally covers
	LastActivityAt time.Time
	// RuleInventory is a read-only cross-reference of the zone's total live
	// Cloudflare IP access rules against cf_ban_lifecycle's tracked subset
	// (see issue #83). No writes/backfill occur; untracked rules are simply
	// reported as a count.
	RuleInventory cfRuleInventory
}

type ProviderHealth struct {
	Name            string
	Enabled         bool
	Configured      bool
	MaskedKey       string
	Status          string
	Mode            string
	LastValidation  string
	LastSuccess     string
	LastError       string
	ErrorCount      int
	RateLimitCount  int
	QuotaRemaining  string
	QuotaUsed       string
	QuotaReset      string
	AvgLatency      string
	LastLatency     string
	CacheHits       int
	CacheMisses     int
	LastLookup      string
	LastStatusCode  string
	Notes           []string
	ValidationNotes []string
}

type StatusItem struct {
	Label  string
	Level  string
	Detail string
}

// EnvironmentWidget summarizes detection + health for the dashboard.
type EnvironmentWidget struct {
	Green   int
	Yellow  int
	Red     int
	Healthy int // detector healthy count
	Total   int // total detectors
}

type DashboardConsoleView struct {
	Statuses      []StatusItem
	AIProviders   []AIProviderDashboardView
	Environment   EnvironmentWidget
	ReportedTotal int  // historical AbuseIPDB-reported count from evidence store
	EvidenceWired bool // true when evidence store is available
	UpdatedAt     string
	HealthyCount  int
	WarningCount  int
	ErrorCount    int
	DisabledCount int
	CommandCenter DashboardCommandCenterView
}

type DashboardCommandCenterView struct {
	Health     DashboardHealthScoreView
	KPIs       []DashboardKPIView
	TimeWindow DashboardTimeWindowView
	Search     DashboardSearchView
	Activity   DashboardActivityFeedView
	Threat     DashboardThreatView
	Freshness  []DashboardFreshnessView
}

type DashboardHealthScoreView struct {
	Score   int
	Level   string
	Summary string
	Reasons []string
}

type DashboardKPIView struct {
	Label  string
	Value  string
	Detail string
	Href   string
	Level  string
}

type DashboardTimeWindowView struct {
	Active  string
	Options []DashboardTimeWindowOption
}

type DashboardTimeWindowOption struct {
	Label  string
	Value  string
	Href   string
	Active bool
}

type DashboardSearchView struct {
	Query       string
	Action      string
	Placeholder string
}

type DashboardActivityFeedView struct {
	Items      []DashboardActivityItemView
	EmptyText  string
	MoreHref   string
	Limit      int
	Source     string
	SourceHref string
}

type DashboardActivityItemView struct {
	Timestamp string
	Severity  string
	Title     string
	Detail    string
	Href      string
}

type DashboardThreatView struct {
	Wired        bool
	TotalEvents  int
	UnknownCount int
	Countries    []DashboardThreatCountryView
	Campaigns    []DashboardThreatCampaignView
	EmptyText    string
	Source       string
}

type DashboardThreatCountryView struct {
	Country string
	Count   int
	Level   string
}

type DashboardThreatCampaignView struct {
	Source   string
	Country  string
	Scenario string
	Count    int
	Level    string
}

type DashboardFreshnessView struct {
	Label  string
	Level  string
	Detail string
}

type AIProviderDashboardView struct {
	Name            string
	Status          string
	Model           string
	Configured      string
	Enabled         string
	Healthy         string
	ConfiguredState string
	EnabledState    string
	HealthyState    string
	LastTestAt      string
	LastSuccessAt   string
	LastFailureAt   string
	LastLatency     string
	LastError       string
	SecretState     string
}

type AIProviderManagementView struct {
	Providers []AIProviderManagementEntry
	Notice    string
	Error     string
}

type AIProviderManagementEntry struct {
	Name              string
	Status            string
	Model             string
	ConfiguredState   string
	EnabledState      string
	Enabled           bool
	SecretState       string
	HealthyState      string
	SecretPathDisplay string
	LastTestAt        string
	LastSuccessAt     string
	LastFailureAt     string
	LastTestStatus    string
	LastTestLatencyMS string
	LastErrorCode     string
	ValidationMessage string
}

// NonAIProviderEntry represents a single non-AI provider (AbuseIPDB, Spamhaus, VirusTotal,
// Cloudflare, CrowdSec, BetterStack) on the unified providers page.
type NonAIProviderEntry struct {
	Name             string
	Category         string // "reporting", "enrichment", "logging", "detection"
	Configured       bool
	Enabled          bool
	Healthy          bool
	MaskedKey        string
	HasKeyManagement bool // true when a credential-store key exists for this provider
	CredentialKey    string
	Status           string
	ConfiguredState  string
	EnabledState     string
	HealthyState     string
	LastTestAt       string
	LastSuccessAt    string
	LastFailureAt    string
	LastLatencyMS    string
	LastErrorCode    string
	Notes            string
}

// UnifiedProvidersView is the view model for the unified /providers page.
type UnifiedProvidersView struct {
	AI    AIProviderManagementView
	NonAI []NonAIProviderEntry
	Error string
}

type AuditTrailView struct {
	Entries    []audit.AuditEntry
	Query      string
	RefreshURL string
}

type BuildInfoView struct {
	Version        string
	GitCommit      string
	BuildDate      string
	GoVersion      string
	GOOS           string
	GOARCH         string
	PackageCount   string
	GoFileCount    string
	ApproxLOC      string
	FeatureStatus  []StatusItem
	ProviderStatus []string
	AIAttribution  []string
}

// ForensicView holds the result of a forensic IP enrichment lookup.
type ForensicView struct {
	IP              string
	Summary         enrichment.EnrichmentSummary
	Assess          enrichment.Assessment
	LocalEvidence   []reporting.DecisionEvidence
	HasData         bool
	HasEnrichment   bool
	Error           string
	EnrichmentError string
	// NoteFormHTML is the rendered HTML for the operator note form.
	// Empty when noteStore is nil or the IP is not yet known.
	NoteFormHTML string
}

type TrustedNetworkEntryView struct {
	Organization        string
	Kind                string
	CIDRCount           int
	CIDRs               []string
	SourceURL           string
	LastVerified        string
	Status              string
	Notes               []string
	NoHardBan           bool
	HardBanAllowed      bool
	Allowlisted         bool
	CloudflareWhitelist string
	CrowdSecAllowlist   string
}

type TrustedNetworksView struct {
	Entries        []TrustedNetworkEntryView
	SyncMode       string // "shadow", "enforce", or "" if the sync registry has never run
	Error          string
	CrowdSecHelper CrowdSecHelperStatusView
}

// CrowdSecHelperStatusView summarizes the root-owned cf-allowlist-sync
// helper's most recently persisted reconcile result (see
// trustednetworks.CrowdSecAllowlistStatus). The daemon's own CrowdSec spoke
// is always nil (it cannot read CrowdSec's root-only credentials file), so
// this is the only honest source for CrowdSec allowlist status.
type CrowdSecHelperStatusView struct {
	// Available is false when no CrowdSecStatusStore is wired at all (e.g.
	// scoped DB not yet opened by the daemon).
	Available    bool
	Configured   bool
	AuthOK       bool
	LastSyncAt   string // formatted, or "" if never run
	LastError    string
	DesiredCount int
	CurrentCount int
	DriftCount   int
	Mode         string
}

type BanLifecycleEntryView struct {
	IP            string
	Source        string
	Reason        string
	Confidence    int
	CreatedAt     string
	ExpiresAt     string
	Duration      string
	RuleID        string
	RecidiveLevel int
	Status        string

	// Cleanup-failure visibility (see banlifecycle.Entry.CleanupAttempts):
	// set when the cleanup worker has failed to delete this entry's
	// Cloudflare rule at least once. CleanupRetrying is true when the entry
	// is still active with at least one recorded failure, so the UI can
	// show a "retrying" state instead of leaving the failure log-only.
	CleanupRetrying      bool
	CleanupAttempts      int
	LastCleanupError     string
	LastCleanupAttemptAt string
}

type BanLifecycleView struct {
	Entries []BanLifecycleEntryView
	Error   string
	Wired   bool
}

type RuntimeStatusView struct {
	CrowdSec   string
	OpenResty  string
	Cloudflare string
	UI         string
}

type PipelineSuppressionBreakdown struct {
	ProtectedTarget  int
	BenignSignal     int
	LowConfidence    int
	DuplicateReport  int
	RecentlyReported int
	NoCategories     int
	Other            int
}

type PipelineHealthRow struct {
	Source               string
	State                string
	LastEventAt          string
	LastReportAt         string // max timestamp where AbuseIPDBReported=true; "" if none or not derivable
	Freshness            string // human-readable duration since last event; "no events" if none
	LatestEvidenceID     string
	Classified           int
	Reported             int
	Suppressed           int
	Pending              int // Decision == "report_pending", awaiting outbox
	SuppressionBreakdown PipelineSuppressionBreakdown
}

type PipelineHealthView struct {
	Rows  []PipelineHealthRow
	Total PipelineHealthRow
	Error string
}

type EvidenceDetailView struct {
	Evidence          reporting.DecisionEvidence
	GateResult        string
	DecisionResult    string
	ActionResult      string
	NormalizedJSON    string
	RawJSON           string
	ProtectedSummary  string
	SuppressionReason string
}
