package ui

import (
	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

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
	Statuses    []StatusItem
	AIProviders []AIProviderDashboardView
	Environment EnvironmentWidget // new
}

type AIProviderDashboardView struct {
	Name         string
	Status       string
	Model        string
	LastTestAt   string
	LastLatency  string
	SecretState  string
	EnabledState string
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
	Enabled           bool
	SecretState       string
	SecretPathDisplay string
	LastTestAt        string
	LastTestStatus    string
	LastTestLatencyMS string
	LastErrorCode     string
	ValidationMessage string
}

type ComingSoonView struct {
	Title       string
	Description string
	Active      string
}

type AuditTrailView struct {
	Entries []audit.AuditEntry
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
	Entries []TrustedNetworkEntryView
	Error   string
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
