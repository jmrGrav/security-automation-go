package health

// Level is the health status of a check.
type Level string

const (
	Green  Level = "GREEN"
	Yellow Level = "YELLOW"
	Red    Level = "RED"
)

// Check is the result of a single health check.
type Check struct {
	Name        string `json:"name"`
	Status      Level  `json:"status"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation,omitempty"`
}

// Config holds the values health checks need. Callers populate from config.Config and secrets.
type Config struct {
	CloudflareTokenConfigured bool
	CloudflareToken           string
	CloudflareZoneID          string
	AbuseIPDBConfigured       bool
	AbuseIPDBEnabled          bool
	AbuseIPDBKey              string
	BetterStackConfigured     bool
	BetterStackToken          string
	StateDir                  string
	LogDir                    string
	SecretDir                 string
	DecisionsLog              string
	NginxLogDir               string
	OpenRestyEventsFile       string
	// LegacySecretsDir is the pre-V1.4 config directory. When empty, the legacy-layout check is skipped.
	LegacySecretsDir string
	// CanonicalSecretsDir is the canonical runtime credential/state directory. Default: /var/lib/security-automation-go/runtime
	CanonicalSecretsDir string
	// OpenAIEnabled reports whether the OpenAI provider is enabled.
	OpenAIEnabled    bool
	OpenAIConfigured bool
	// OpenAISecretFile is kept for legacy callers but is no longer used by checks.
	OpenAISecretFile string
	// AnthropicEnabled reports whether the Anthropic provider is enabled.
	AnthropicEnabled    bool
	AnthropicConfigured bool
	// AnthropicSecretFile is kept for legacy callers but is no longer used by checks.
	AnthropicSecretFile string
	// GeminiEnabled reports whether the Gemini provider is enabled.
	GeminiEnabled    bool
	GeminiConfigured bool
	// GeminiSecretFile is kept for legacy callers but is no longer used by checks.
	GeminiSecretFile string
	// SetupComplete is true when the operator has completed the first-boot setup wizard.
	// If false, the setup check returns YELLOW to remind the operator to complete setup.
	SetupComplete bool

	// CrowdSec extended health fields.
	// CrowdSecInstalled is true when the cscli binary is present.
	CrowdSecInstalled bool
	// CrowdSecServiceRunning is true when crowdsec.service is active.
	CrowdSecServiceRunning bool
	// CrowdSecLAPIKeyConfigured is true when the LAPI key exists in the credential store.
	CrowdSecLAPIKeyConfigured bool
	// CrowdSecPollerEnabled is true when the CrowdSec poller is enabled in config.
	CrowdSecPollerEnabled bool
	// CrowdSecLAPIURL is the configured LAPI URL (informational).
	CrowdSecLAPIURL string
	// CrowdSecAppSecDetected is true when the AppSec port (7422) is reachable.
	CrowdSecAppSecDetected bool
}

// RunAll runs all 18 health checks and returns their results.
func RunAll(cfg Config) []Check {
	fns := []func(Config) Check{
		CheckCloudflare,
		CheckAbuseIPDB,
		CheckBetterStack,
		CheckSQLite,
		CheckCrowdSec,
		CheckCrowdSecPoller,
		CheckCrowdSecAppSec,
		CheckOpenResty,
		CheckNginx,
		CheckDisk,
		CheckCanonicalSecretsDir,
		CheckAISecrets,
		CheckProductionReady,
		CheckPermissions,
		CheckStateDir,
		CheckLogDir,
		CheckLegacyLayout,
		CheckSetupComplete,
	}
	out := make([]Check, 0, len(fns))
	for _, f := range fns {
		out = append(out, f(cfg))
	}
	return out
}
