package health

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

func CheckCloudflare(cfg Config) Check {
	hasToken := cfg.CloudflareTokenConfigured || strings.TrimSpace(cfg.CloudflareToken) != ""
	hasZone := strings.TrimSpace(cfg.CloudflareZoneID) != ""
	if hasToken && hasZone {
		return Check{Name: "cloudflare", Status: Green, Reason: "API token and zone ID configured"}
	}
	if hasToken {
		return Check{
			Name:        "cloudflare",
			Status:      Yellow,
			Reason:      "API token present but zone ID missing",
			Remediation: "Set cloudflare.zone_id in /etc/security-automation-go/security-automation.yaml",
		}
	}
	return Check{
		Name:        "cloudflare",
		Status:      Red,
		Reason:      "API token not configured",
		Remediation: "Run setup wizard step 4 or set cloudflare.api_token",
	}
}

func CheckAbuseIPDB(cfg Config) Check {
	if cfg.AbuseIPDBConfigured || strings.TrimSpace(cfg.AbuseIPDBKey) != "" {
		return Check{Name: "abuseipdb", Status: Green, Reason: "API key configured"}
	}
	if cfg.AbuseIPDBEnabled {
		return Check{
			Name:        "abuseipdb",
			Status:      Yellow,
			Reason:      "AbuseIPDB enabled but API key missing",
			Remediation: "Set ABUSEIPDB_KEY in the setup wizard or Providers UI",
		}
	}
	return Check{Name: "abuseipdb", Status: Green, Reason: "AbuseIPDB not configured (optional)"}
}

func CheckBetterStack(cfg Config) Check {
	if cfg.BetterStackConfigured || strings.TrimSpace(cfg.BetterStackToken) != "" {
		return Check{Name: "betterstack", Status: Green, Reason: "Source token configured"}
	}
	return Check{Name: "betterstack", Status: Green, Reason: "BetterStack not configured (optional)"}
}

func CheckSQLite(cfg Config) Check {
	if strings.TrimSpace(cfg.StateDir) == "" {
		return Check{
			Name:        "sqlite",
			Status:      Red,
			Reason:      "State directory not configured",
			Remediation: "Set state_dir in configuration or run setup wizard",
		}
	}
	dbPath := cfg.StateDir + "/runtime.db"
	if _, err := os.Stat(dbPath); err != nil {
		if _, err2 := os.Stat(cfg.StateDir); err2 != nil {
			return Check{
				Name:        "sqlite",
				Status:      Red,
				Reason:      "State directory missing: " + cfg.StateDir,
				Remediation: "mkdir -p " + cfg.StateDir,
			}
		}
		return Check{
			Name:        "sqlite",
			Status:      Yellow,
			Reason:      "Database not found (expected on first run): " + dbPath,
			Remediation: "Start cf-sync once to create the database",
		}
	}
	f, err := os.Open(dbPath)
	if err != nil {
		return Check{
			Name:        "sqlite",
			Status:      Red,
			Reason:      "Database not readable: " + err.Error(),
			Remediation: "Check permissions on " + dbPath,
		}
	}
	_ = f.Close()
	return Check{Name: "sqlite", Status: Green, Reason: "Database present and readable"}
}

// checkCrowdSecLegacy is the original decisions-log file existence check,
// preserved for backward compatibility and used as a fallback by CheckCrowdSec.
func checkCrowdSecLegacy(cfg Config) Check {
	if strings.TrimSpace(cfg.DecisionsLog) == "" {
		return Check{Name: "crowdsec", Status: Green, Reason: "CrowdSec not configured (optional)"}
	}
	if _, err := os.Stat(cfg.DecisionsLog); err != nil {
		return Check{
			Name:        "crowdsec",
			Status:      Yellow,
			Reason:      "Decisions log configured but missing: " + cfg.DecisionsLog,
			Remediation: "Install and start CrowdSec, or correct crowdsec.decisions_log",
		}
	}
	return Check{Name: "crowdsec", Status: Green, Reason: "Decisions log present"}
}

// CheckCrowdSec reports the CrowdSec installation and LAPI key status.
// It uses extended Config fields when available, falling back to the
// legacy decisions-log check for operators who have not yet populated
// the new fields.
func CheckCrowdSec(cfg Config) Check {
	// Nothing configured at all — optional component, return green.
	if !cfg.CrowdSecInstalled && strings.TrimSpace(cfg.DecisionsLog) == "" {
		return Check{Name: "crowdsec", Status: Green, Reason: "CrowdSec not configured (optional)"}
	}

	// Installed but service not running.
	if cfg.CrowdSecInstalled && !cfg.CrowdSecServiceRunning {
		return Check{
			Name:        "crowdsec",
			Status:      Yellow,
			Reason:      "CrowdSec installed but service not running",
			Remediation: "sudo systemctl start crowdsec",
		}
	}

	// Service running but LAPI key not configured.
	if cfg.CrowdSecInstalled && cfg.CrowdSecServiceRunning && !cfg.CrowdSecLAPIKeyConfigured {
		return Check{
			Name:        "crowdsec",
			Status:      Yellow,
			Reason:      "CrowdSec running — LAPI key not configured",
			Remediation: "Set the CrowdSec LAPI key via Settings → CrowdSec or the first-run wizard",
		}
	}

	// Fully configured via extended fields.
	if cfg.CrowdSecInstalled && cfg.CrowdSecServiceRunning && cfg.CrowdSecLAPIKeyConfigured {
		return Check{Name: "crowdsec", Status: Green, Reason: "CrowdSec running and LAPI key configured"}
	}

	// Fallback: use original decisions-log check for operators who have not
	// populated the extended fields yet.
	return checkCrowdSecLegacy(cfg)
}

// CheckCrowdSecPoller reports whether the CrowdSec poller is enabled and its
// LAPI key is present.
func CheckCrowdSecPoller(cfg Config) Check {
	if !cfg.CrowdSecPollerEnabled {
		return Check{Name: "crowdsec-poller", Status: Green, Reason: "CrowdSec poller not enabled (optional)"}
	}
	if cfg.CrowdSecLAPIKeyConfigured {
		return Check{Name: "crowdsec-poller", Status: Green, Reason: "CrowdSec poller configured"}
	}
	return Check{
		Name:        "crowdsec-poller",
		Status:      Yellow,
		Reason:      "CrowdSec poller enabled but LAPI key not configured",
		Remediation: "Set the CrowdSec LAPI key via Settings → CrowdSec or the setup wizard",
	}
}

// CheckCrowdSecAppSec reports whether the CrowdSec AppSec component is active.
func CheckCrowdSecAppSec(cfg Config) Check {
	if !cfg.CrowdSecAppSecDetected {
		return Check{Name: "crowdsec-appsec", Status: Green, Reason: "CrowdSec AppSec not detected (optional)"}
	}
	return Check{Name: "crowdsec-appsec", Status: Green, Reason: "CrowdSec AppSec active"}
}

func CheckOpenResty(cfg Config) Check {
	if strings.TrimSpace(cfg.OpenRestyEventsFile) == "" {
		return Check{Name: "openresty", Status: Green, Reason: "OpenResty not configured (optional)"}
	}
	if _, err := os.Stat(cfg.OpenRestyEventsFile); err != nil {
		return Check{
			Name:        "openresty",
			Status:      Yellow,
			Reason:      "Events file configured but missing: " + cfg.OpenRestyEventsFile,
			Remediation: "Ensure OpenResty is running and lua state is being written",
		}
	}
	return Check{Name: "openresty", Status: Green, Reason: "Events file present"}
}

func CheckNginx(cfg Config) Check {
	if strings.TrimSpace(cfg.NginxLogDir) == "" {
		return Check{Name: "nginx", Status: Green, Reason: "Nginx not configured (optional)"}
	}
	if _, err := os.Stat(cfg.NginxLogDir); err != nil {
		return Check{
			Name:        "nginx",
			Status:      Yellow,
			Reason:      "Nginx log directory configured but missing: " + cfg.NginxLogDir,
			Remediation: "Install nginx or correct nginx_log_dir in configuration",
		}
	}
	return Check{Name: "nginx", Status: Green, Reason: "Nginx log directory present"}
}

// diskStatfs is overridable for testing.
var diskStatfs = func(path string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	if st.Bsize <= 0 {
		return 0, 0, fmt.Errorf("invalid block size %d", st.Bsize)
	}
	bsize := uint64(st.Bsize)
	return st.Blocks * bsize, st.Bavail * bsize, nil
}

func CheckDisk(cfg Config) Check {
	path := cfg.StateDir
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/security-automation-go"
	}
	total, free, err := diskStatfs(path)
	if err != nil {
		return Check{
			Name:        "disk",
			Status:      Yellow,
			Reason:      "Cannot check disk: " + err.Error(),
			Remediation: "Ensure " + path + " exists and is mounted",
		}
	}
	if total == 0 {
		return Check{Name: "disk", Status: Yellow, Reason: "Cannot determine disk capacity"}
	}
	pct := float64(free) / float64(total) * 100
	switch {
	case pct >= 20:
		return Check{Name: "disk", Status: Green, Reason: fmt.Sprintf("%.1f%% free", pct)}
	case pct >= 10:
		return Check{
			Name:        "disk",
			Status:      Yellow,
			Reason:      fmt.Sprintf("Low disk: %.1f%% free", pct),
			Remediation: "Free disk space or expand the volume",
		}
	default:
		return Check{
			Name:        "disk",
			Status:      Red,
			Reason:      fmt.Sprintf("Critical disk: %.1f%% free", pct),
			Remediation: "Free disk space immediately",
		}
	}
}

func CheckPermissions(cfg Config) Check {
	path := cfg.SecretDir
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/security-automation-go/runtime"
	}
	info, err := os.Stat(path)
	if err != nil {
		return Check{
			Name:        "permissions",
			Status:      Yellow,
			Reason:      "Runtime directory not found: " + path,
			Remediation: "mkdir -p " + path + " && chmod 750 " + path,
		}
	}
	mode := info.Mode().Perm()
	if mode&0o007 != 0 {
		return Check{
			Name:        "permissions",
			Status:      Red,
			Reason:      fmt.Sprintf("Runtime directory world-accessible: %04o", mode),
			Remediation: "chmod 750 " + path,
		}
	}
	return Check{Name: "permissions", Status: Green, Reason: fmt.Sprintf("Runtime directory permissions: %04o", mode)}
}

func CheckStateDir(cfg Config) Check {
	path := cfg.StateDir
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/security-automation-go"
	}
	if _, err := os.Stat(path); err != nil {
		return Check{
			Name:        "state",
			Status:      Red,
			Reason:      "State directory missing: " + path,
			Remediation: "mkdir -p " + path,
		}
	}
	tmp, err := os.CreateTemp(path, ".health-check-*")
	if err != nil {
		return Check{
			Name:        "state",
			Status:      Yellow,
			Reason:      "State directory not writable: " + err.Error(),
			Remediation: "chown -R $USER " + path,
		}
	}
	_ = tmp.Close()
	_ = os.Remove(tmp.Name())
	return Check{Name: "state", Status: Green, Reason: "State directory present and writable"}
}

func CheckLogDir(cfg Config) Check {
	path := cfg.LogDir
	if strings.TrimSpace(path) == "" {
		path = "/var/log/security-automation"
	}
	if _, err := os.Stat(path); err != nil {
		return Check{
			Name:        "logs",
			Status:      Yellow,
			Reason:      "Log directory missing: " + path,
			Remediation: "mkdir -p " + path,
		}
	}
	return Check{Name: "logs", Status: Green, Reason: "Log directory present"}
}

// CheckSetupComplete reports whether the first-boot setup wizard has been completed.
//   - GREEN: wizard was completed (SetupComplete == true)
//   - YELLOW: wizard has not been completed — service is in setup mode
func CheckSetupComplete(cfg Config) Check {
	if cfg.SetupComplete {
		return Check{Name: "setup", Status: Green, Reason: "First-boot setup complete"}
	}
	return Check{
		Name:        "setup",
		Status:      Yellow,
		Reason:      "First-boot setup wizard not completed",
		Remediation: "Open the UI in a browser and complete the setup wizard (http://<host>:<port>/setup)",
	}
}

func CheckCanonicalSecretsDir(cfg Config) Check {
	path := cfg.CanonicalSecretsDir
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/security-automation-go/runtime"
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Check{Name: "canonical-secrets", Status: Green, Reason: "Canonical secrets directory not required"}
		}
		return Check{
			Name:        "canonical-secrets",
			Status:      Red,
			Reason:      "Cannot inspect canonical secrets directory: " + err.Error(),
			Remediation: "Check permissions on " + path,
		}
	}
	if !info.IsDir() {
		return Check{
			Name:        "canonical-secrets",
			Status:      Red,
			Reason:      "Canonical secrets path is not a directory: " + path,
			Remediation: "mkdir -p " + path,
		}
	}
	return Check{Name: "canonical-secrets", Status: Green, Reason: "Canonical secrets directory present"}
}

type aiSecretSpec struct {
	name       string
	enabled    bool
	configured bool
}

func CheckAISecrets(cfg Config) Check {
	specs := []aiSecretSpec{
		{name: "openai", enabled: cfg.OpenAIEnabled, configured: cfg.OpenAIConfigured},
		{name: "anthropic", enabled: cfg.AnthropicEnabled, configured: cfg.AnthropicConfigured},
		{name: "gemini", enabled: cfg.GeminiEnabled, configured: cfg.GeminiConfigured},
	}
	enabled := make([]string, 0, len(specs))
	missing := make([]string, 0, len(specs))
	for _, spec := range specs {
		if !spec.enabled {
			continue
		}
		enabled = append(enabled, spec.name)
		if !spec.configured {
			missing = append(missing, spec.name)
		}
	}
	if len(enabled) == 0 {
		return Check{Name: "ai", Status: Green, Reason: "AI providers not configured (optional)"}
	}
	if len(missing) > 0 {
		return Check{
			Name:        "ai",
			Status:      Yellow,
			Reason:      "Missing AI credentials: " + strings.Join(missing, ", "),
			Remediation: "Configure the missing AI credentials in the UI",
		}
	}
	return Check{Name: "ai", Status: Green, Reason: "AI credentials configured"}
}

func CheckProductionReady(cfg Config) Check {
	if !cfg.CloudflareTokenConfigured && strings.TrimSpace(cfg.CloudflareToken) == "" {
		return Check{
			Name:        "production",
			Status:      Red,
			Reason:      "Cloudflare API token missing",
			Remediation: "Complete setup step 4 or configure the Cloudflare token in the UI",
		}
	}
	if strings.TrimSpace(cfg.CloudflareZoneID) == "" {
		return Check{
			Name:        "production",
			Status:      Red,
			Reason:      "Cloudflare zone ID missing",
			Remediation: "Complete setup step 4 or configure the Cloudflare zone ID in the UI",
		}
	}
	return Check{Name: "production", Status: Green, Reason: "Production enable prerequisites satisfied"}
}

// CheckLegacyLayout reports whether a pre-V1.4 config directory exists alongside the canonical path.
//   - GREEN: canonical secrets dir exists (or neither exists) — correct state
//   - YELLOW: both legacy and canonical exist — migration in progress
//   - RED: only legacy exists — operator must migrate before secrets load
func CheckLegacyLayout(cfg Config) Check {
	legacy := cfg.LegacySecretsDir
	if strings.TrimSpace(legacy) == "" {
		legacy = "/etc/security-automation/secrets"
	}
	canonical := cfg.CanonicalSecretsDir
	if strings.TrimSpace(canonical) == "" {
		canonical = "/var/lib/security-automation-go/runtime"
	}
	legacyExists, canonicalExists := legacyLayoutState(legacy, canonical)

	switch {
	case !legacyExists:
		return Check{Name: "layout", Status: Green, Reason: "No legacy config directory detected"}
	case legacyExists && canonicalExists:
		return Check{
			Name:        "layout",
			Status:      Yellow,
			Reason:      fmt.Sprintf("Legacy secrets directory %s exists alongside canonical %s — migration in progress", legacy, canonical),
			Remediation: "Complete secret migration to " + canonical + " and remove " + legacy,
		}
	default:
		return Check{
			Name:        "layout",
			Status:      Red,
			Reason:      fmt.Sprintf("Legacy secrets directory %s exists but canonical %s is absent — secrets will not load", legacy, canonical),
			Remediation: "sudo mkdir -p " + canonical + " && sudo cp " + legacy + "/* " + canonical + "/ && sudo chmod 0600 " + canonical + "/*",
		}
	}
}

func legacyLayoutState(legacy, canonical string) (bool, bool) {
	_, legacyErr := os.Stat(legacy)
	_, canonicalErr := os.Stat(canonical)
	return legacyErr == nil, canonicalErr == nil
}
