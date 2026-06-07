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
	CloudflareToken     string
	CloudflareZoneID    string
	AbuseIPDBKey        string
	AbuseIPDBEnabled    bool
	BetterStackToken    string
	StateDir            string
	LogDir              string
	SecretDir           string
	DecisionsLog        string
	NginxLogDir         string
	OpenRestyEventsFile string
}

// RunAll runs all 11 health checks and returns their results.
func RunAll(cfg Config) []Check {
	fns := []func(Config) Check{
		CheckCloudflare,
		CheckAbuseIPDB,
		CheckBetterStack,
		CheckSQLite,
		CheckCrowdSec,
		CheckOpenResty,
		CheckNginx,
		CheckDisk,
		CheckPermissions,
		CheckStateDir,
		CheckLogDir,
	}
	out := make([]Check, 0, len(fns))
	for _, f := range fns {
		out = append(out, f(cfg))
	}
	return out
}
