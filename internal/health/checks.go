package health

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

func CheckCloudflare(cfg Config) Check {
	hasToken := strings.TrimSpace(cfg.CloudflareToken) != ""
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
	if strings.TrimSpace(cfg.AbuseIPDBKey) != "" {
		return Check{Name: "abuseipdb", Status: Green, Reason: "API key configured"}
	}
	if cfg.AbuseIPDBEnabled {
		return Check{
			Name:        "abuseipdb",
			Status:      Yellow,
			Reason:      "AbuseIPDB enabled but API key missing",
			Remediation: "Set ABUSEIPDB_KEY via setup wizard or /etc/security-automation-go/secrets/",
		}
	}
	return Check{Name: "abuseipdb", Status: Green, Reason: "AbuseIPDB not configured (optional)"}
}

func CheckBetterStack(cfg Config) Check {
	if strings.TrimSpace(cfg.BetterStackToken) != "" {
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
	dbPath := cfg.StateDir + "/state.db"
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

func CheckCrowdSec(cfg Config) Check {
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
		path = "/etc/security-automation-go/secrets"
	}
	info, err := os.Stat(path)
	if err != nil {
		return Check{
			Name:        "permissions",
			Status:      Yellow,
			Reason:      "Secret directory not found: " + path,
			Remediation: "mkdir -p " + path + " && chmod 700 " + path,
		}
	}
	mode := info.Mode().Perm()
	if mode&0o007 != 0 {
		return Check{
			Name:        "permissions",
			Status:      Red,
			Reason:      fmt.Sprintf("Secrets directory world-accessible: %04o", mode),
			Remediation: "chmod 700 " + path,
		}
	}
	if mode&0o070 != 0 {
		return Check{
			Name:        "permissions",
			Status:      Yellow,
			Reason:      fmt.Sprintf("Secrets directory group-accessible: %04o", mode),
			Remediation: "chmod 700 " + path,
		}
	}
	return Check{Name: "permissions", Status: Green, Reason: fmt.Sprintf("Secrets directory permissions: %04o", mode)}
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
		canonical = "/etc/security-automation-go/secrets"
	}
	_, legacyErr := os.Stat(legacy)
	_, canonicalErr := os.Stat(canonical)
	legacyExists := legacyErr == nil
	canonicalExists := canonicalErr == nil

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
