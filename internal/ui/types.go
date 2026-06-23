package ui

import (
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// CFSyncView is the view model for the /sync (Cloudflare ban sync) page.
type CFSyncView struct {
	HasData       bool
	CycleAt       time.Time
	AgreementPct  float64
	InSync        bool
	ToAdd         []string // IPs Go would add to CF
	ToDelete      []string // IPs Go would remove from CF
	ActiveBans    int
	CFRules       int
	CycleCount    int // total cycles in store
	Error         string
	NoCycleReason string // explains why HasData is false (no error)
	MutationsOn   bool   // true when Cloudflare mutations are enabled
	DryRun        bool   // true when CF mutations are disabled (observation-only)
}

type ProviderView struct {
	Name       string
	Enabled    bool
	Configured bool
	MaskedKey  string
	Status     string
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

type ComingSoonView struct {
	Title       string
	Description string
	Active      string
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

type DashboardView struct {
	Runtime   RuntimeStatusView
	Providers []ProviderView
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
