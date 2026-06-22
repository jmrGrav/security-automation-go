package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion defines the expected version of the config file.
const SchemaVersion = "v1"

type HTTPConfig struct {
	Timeout      time.Duration `yaml:"timeout"`
	RetryMax     int           `yaml:"retry_max"`
	RetryBackoff time.Duration `yaml:"retry_backoff"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type TracingConfig struct {
	Enabled      bool    `yaml:"enabled"`
	Exporter     string  `yaml:"exporter"`      // "otlp", "stdout"
	Endpoint     string  `yaml:"endpoint"`      // For OTLP
	Insecure     bool    `yaml:"insecure"`      // For OTLP
	SamplingRate float64 `yaml:"sampling_rate"` // 0.0 to 1.0
}

type GlobalConfig struct {
	AppEnv         string        `yaml:"app_env"`
	ServiceName    string        `yaml:"service_name"`
	AdminToken     string        `yaml:"admin_token"`
	AdminTokenFile string        `yaml:"admin_token_file"`
	Log            LogConfig     `yaml:"log"`
	HTTP           HTTPConfig    `yaml:"http"`
	Tracing        TracingConfig `yaml:"tracing"`
	// ProtectedHosts lists operator-controlled IPs/CIDRs that must never be
	// reported to AbuseIPDB or propagated to Cloudflare. Overridable via
	// SECURITY_AUTOMATION_PROTECTED_HOSTS (comma-separated).
	ProtectedHosts []string `yaml:"protected_hosts"`
}

const (
	RuntimeProfileSingleNode = "single-node"
	RuntimeProfileStrictHA   = "strict-ha"
)

type RuntimeConfig struct {
	Profile string `yaml:"profile"`
}

type CloudflareConfig struct {
	APIToken         string `yaml:"api_token"`
	ZoneID           string `yaml:"zone_id"`
	MutationsEnabled bool   `yaml:"mutations_enabled"`
	// AutoBanEnabled gates automatic IP banning by the auto-ban evaluator.
	// Requires MutationsEnabled=true. When false the evaluator runs in shadow mode.
	AutoBanEnabled bool `yaml:"auto_ban_enabled"`
	// CleanupInterval controls how often the autoban ban-lifecycle cleanup
	// worker scans for expired Cloudflare access rules and removes them.
	// Defaults to 5 minutes when unset/zero. Named to compose cleanly under
	// a future `reputation_policy.cloudflare.cleanup_interval` block.
	CleanupInterval time.Duration `yaml:"cleanup_interval"`
}

type CrowdSecConfig struct {
	APIKey        string        `yaml:"api_key"`
	DecisionsLog  string        `yaml:"decisions_log"`
	NginxLogDir   string        `yaml:"nginx_log_dir"`
	BinPath       string        `yaml:"bin_path"`       // cscli binary path; default "cscli"
	Timeout       time.Duration `yaml:"timeout"`        // per-command timeout; default 15s
	AllowlistName string        `yaml:"allowlist_name"` // CrowdSec allowlist name; default "my_allowlist"

	// Poller — Go replacement for crowdsec-poller.py.
	PollerEnabled  bool          `yaml:"poller_enabled"`  // opt-in; default false until cutover
	PollerLAPIURL  string        `yaml:"poller_lapi_url"` // default http://127.0.0.1:8080
	PollerLAPIKey  string        // set from encrypted CredentialStore at runtime; never via YAML or env
	PollerInterval time.Duration `yaml:"poller_interval"` // default 30s
}

type OpenRestyConfig struct {
	EventsFile         string `yaml:"events_file"`
	LuaStatePath       string `yaml:"lua_state_path"`         // default: /run/crowdsec-lua/bans.json
	LuaStatePushEnable bool   `yaml:"lua_state_push_enabled"` // default: false (opt-in)
	ShadowLuaStatePath string `yaml:"shadow_lua_state_path"`  // write path when shadow mode
	WAFRefsFile        string `yaml:"waf_refs_file"`          // default: /run/crowdsec-lua/waf_refs.jsonl
}

type AbuseIPDBConfig struct {
	APIKey           string        `yaml:"api_key"`
	Enabled          bool          `yaml:"enabled"`
	ReportingEnabled *bool         `yaml:"reporting_enabled"`
	Threshold        int           `yaml:"threshold"`
	FailureMode      string        `yaml:"failure_mode"`
	CacheTTL         time.Duration `yaml:"cache_ttl"`
	RequestTimeout   time.Duration `yaml:"request_timeout"`
}

type SpamhausConfig struct {
	APIKey  string `yaml:"api_key"`
	Enabled bool   `yaml:"enabled"`
}

type VirusTotalConfig struct {
	APIKey  string `yaml:"api_key"`
	Enabled bool   `yaml:"enabled"`
}

type UIBoolConfig struct {
	Enabled           bool   `yaml:"enabled"`
	Addr              string `yaml:"addr"`
	Port              int    `yaml:"port"` // extracted from Addr; deprecated
	MutationsEnabled  bool   `yaml:"mutations_enabled"`
	SecretFile        string `yaml:"secret_file"`
	ProviderStateFile string `yaml:"provider_state_file"`
}

type EnrichmentConfig struct {
	Enabled    bool          `yaml:"enabled"`
	DNSEnabled bool          `yaml:"dns_enabled"`
	ASNEnabled bool          `yaml:"asn_enabled"`
	Timeout    time.Duration `yaml:"timeout"`
	CacheTTL   time.Duration `yaml:"cache_ttl"`
}

// HTTPErrorIntelConfig governs the nginxerrors adapter (HTTP status >= 400
// burst intelligence). Ingestion is evidence-only by default — EnforceMode
// must be explicitly set to true before a qualifying burst can ever reach
// the auto-ban evaluator, per the standing rule that WAF/HTTP-error signals
// must never trigger a ban except through an explicit, strict opt-in.
type HTTPErrorIntelConfig struct {
	Enabled bool `yaml:"enabled"` // default true: evidence-only ingestion runs
	// EnforceMode opts a qualifying burst into auto-ban evaluation (still
	// subject to autoban's trust-registry/dedup guards and Cloudflare
	// MutationsEnabled+AutoBanEnabled shadow gating). Default false.
	EnforceMode bool `yaml:"enforce_mode"`
	// MinBurst is the number of same-IP/same-status errors within one poll
	// window required before the burst is even recorded as evidence. A
	// single stray error is noise, not signal.
	MinBurst int `yaml:"min_burst"`
	// BanThreshold is the (higher) burst count required before EnforceMode
	// will consider escalating to the auto-ban evaluator. Must be > 1.
	BanThreshold int `yaml:"ban_threshold"`
}

type BetterStackConfig struct {
	SourceToken   string `yaml:"source_token"`
	IngestingHost string `yaml:"ingesting_host"`
}

// ReputationPolicyAbuseIPDBConfig governs how the reputation gate consults
// AbuseIPDB Check before allowing a report or ban.
type ReputationPolicyAbuseIPDBConfig struct {
	CheckBeforeReport        bool `yaml:"check_before_report"`
	MinConfidenceToReport    int  `yaml:"min_confidence_to_report"`
	MinConfidenceToBan       int  `yaml:"min_confidence_to_ban"`
	SuppressIfConfidenceZero bool `yaml:"suppress_if_confidence_zero"`
}

// ReputationPolicyVirusTotalConfig governs how the reputation gate consults
// VirusTotal as a secondary corroborating signal.
type ReputationPolicyVirusTotalConfig struct {
	Enabled         bool `yaml:"enabled"`
	SuppressIfClean bool `yaml:"suppress_if_clean"`
}

// ReputationPolicyCloudflareConfig governs ban durations and auto-deban
// scheduling driven by the reputation gate / autodeban service.
type ReputationPolicyCloudflareConfig struct {
	DefaultBanDuration time.Duration `yaml:"default_ban_duration"`
	Recidive2Duration  time.Duration `yaml:"recidive_2_duration"`
	Recidive3Duration  time.Duration `yaml:"recidive_3_duration"`
	AutoDebanEnabled   bool          `yaml:"auto_deban_enabled"`
	CleanupInterval    time.Duration `yaml:"cleanup_interval"`
}

// ReputationPolicyConfig is the top-level reputation_policy YAML block. It
// drives internal/security/reputation.Gate and internal/security/autodeban.
//
// Safety invariant: Mode MUST default to "shadow" — both when the entire
// reputation_policy block is omitted from YAML (DefaultConfig sets it) and
// when an operator writes the block but omits `mode:` (Load's strict-mode
// YAML decoder will leave Mode as the zero value "" in that case; callers
// must treat any Mode other than the literal string "enforce" as shadow —
// see (*ReputationPolicyConfig).EffectiveMode). This file must never default
// Mode to "enforce" under any circumstance.
type ReputationPolicyConfig struct {
	Enabled    bool                             `yaml:"enabled"`
	Mode       string                           `yaml:"mode"` // "shadow" or "enforce"
	AbuseIPDB  ReputationPolicyAbuseIPDBConfig  `yaml:"abuseipdb"`
	VirusTotal ReputationPolicyVirusTotalConfig `yaml:"virustotal"`
	Cloudflare ReputationPolicyCloudflareConfig `yaml:"cloudflare"`
}

// EffectiveMode returns "enforce" only when Mode is exactly that literal
// string; every other value (including "", "shadow", or any typo) is
// treated as shadow. This is the single choke point that guarantees the
// safety invariant documented on ReputationPolicyConfig.
func (r ReputationPolicyConfig) EffectiveMode() string {
	if r.Mode == "enforce" {
		return "enforce"
	}
	return "shadow"
}

type Config struct {
	Version          string                 `yaml:"version"`
	Global           GlobalConfig           `yaml:"global"`
	Runtime          RuntimeConfig          `yaml:"runtime"`
	UI               UIBoolConfig           `yaml:"ui"`
	Enrichment       EnrichmentConfig       `yaml:"enrichment"`
	Cloudflare       CloudflareConfig       `yaml:"cloudflare"`
	CrowdSec         CrowdSecConfig         `yaml:"crowdsec"`
	OpenResty        OpenRestyConfig        `yaml:"openresty"`
	AbuseIPDB        AbuseIPDBConfig        `yaml:"abuseipdb"`
	HTTPErrorIntel   HTTPErrorIntelConfig   `yaml:"http_error_intel"`
	Spamhaus         SpamhausConfig         `yaml:"spamhaus"`
	VirusTotal       VirusTotalConfig       `yaml:"virustotal"`
	ReputationPolicy ReputationPolicyConfig `yaml:"reputation_policy"`
	TrustedNetworks  TrustedNetworksConfig  `yaml:"trusted_networks"`
	BetterStack      BetterStackConfig      `yaml:"betterstack"`
	Policies         []PolicyConfig         `yaml:"policies"`
	StateDir         string                 `yaml:"state_dir"`
	Interval         time.Duration          `yaml:"interval"`
}

// TrustedNetworksCrowdSecConfig governs the CrowdSec spoke of the trusted
// networks hub-and-spoke registry.
type TrustedNetworksCrowdSecConfig struct {
	Enabled bool `yaml:"enabled"`
	// AllowlistName is the cscli allowlist the registry pushes to. Defaults
	// to the same allowlist already read by CrowdSecConfig.AllowlistName so
	// existing shadow/drift reporting that reads it benefits automatically.
	AllowlistName string `yaml:"allowlist_name"`
}

// TrustedNetworksCloudflareConfig governs the Cloudflare spoke of the
// trusted networks hub-and-spoke registry.
type TrustedNetworksCloudflareConfig struct {
	Enabled bool `yaml:"enabled"`
	// ZoneID defaults to CloudflareConfig.ZoneID when empty.
	ZoneID string `yaml:"zone_id"`
}

// TrustedNetworksConfig is the top-level trusted_networks YAML block. It
// drives internal/trustednetworks.Registry: a hub-and-spoke source of truth
// pushed independently to CrowdSec and Cloudflare allowlists. CrowdSec and
// Cloudflare must never sync directly to each other — every change flows
// through this registry.
//
// Safety invariant: Mode MUST default to "shadow", mirroring
// ReputationPolicyConfig's invariant — detect and report drift only, never
// push or remove anything, until an operator explicitly opts into
// "enforce". Even in enforce mode the registry never removes a remote
// entry automatically (see internal/trustednetworks.Registry doc comment).
type TrustedNetworksConfig struct {
	Enabled      bool                            `yaml:"enabled"`
	Mode         string                          `yaml:"mode"` // "shadow" or "enforce"
	SyncInterval time.Duration                   `yaml:"sync_interval"`
	CrowdSec     TrustedNetworksCrowdSecConfig   `yaml:"crowdsec"`
	Cloudflare   TrustedNetworksCloudflareConfig `yaml:"cloudflare"`
}

// EffectiveMode returns "enforce" only when Mode is exactly that literal
// string; every other value (including "", "shadow", or any typo) is
// treated as shadow — the single choke point guaranteeing the safety
// invariant documented on TrustedNetworksConfig.
func (t TrustedNetworksConfig) EffectiveMode() string {
	if t.Mode == "enforce" {
		return "enforce"
	}
	return "shadow"
}

type PolicyConfig struct {
	ID      string       `yaml:"id"`
	Name    string       `yaml:"name"`
	Enabled bool         `yaml:"enabled"`
	Rules   []RuleConfig `yaml:"rules"`
}

type RuleConfig struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Target      string `yaml:"target"`
	Condition   string `yaml:"condition"`
	Decision    string `yaml:"decision"`
}

// DefaultConfig returns a base configuration with sane defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: SchemaVersion,
		Global: GlobalConfig{
			AppEnv:      "production",
			ServiceName: "cf-sync",
			Log: LogConfig{
				Level:  "info",
				Format: "json",
			},
			HTTP: HTTPConfig{
				Timeout:      15 * time.Second,
				RetryMax:     3,
				RetryBackoff: time.Second,
			},
			Tracing: TracingConfig{
				Enabled:      false,
				Exporter:     "stdout",
				SamplingRate: 0.2,
			},
		},
		Runtime: RuntimeConfig{
			Profile: RuntimeProfileSingleNode,
		},
		UI: UIBoolConfig{
			Enabled:          false,
			Addr:             "127.0.0.1:9091",
			MutationsEnabled: false,
		},
		Enrichment: EnrichmentConfig{
			Enabled:    true,
			DNSEnabled: true,
			ASNEnabled: true,
			Timeout:    800 * time.Millisecond,
			CacheTTL:   6 * time.Hour,
		},
		AbuseIPDB: AbuseIPDBConfig{
			Threshold:      70,
			FailureMode:    "suppress",
			CacheTTL:       15 * time.Minute,
			RequestTimeout: 2 * time.Second,
		},
		Cloudflare: CloudflareConfig{
			CleanupInterval: 5 * time.Minute,
		},
		Spamhaus:   SpamhausConfig{},
		VirusTotal: VirusTotalConfig{},
		ReputationPolicy: ReputationPolicyConfig{
			Enabled: true,
			// Mode is intentionally "shadow" — never default to "enforce".
			// See ReputationPolicyConfig's doc comment for the invariant
			// this protects.
			Mode: "shadow",
			AbuseIPDB: ReputationPolicyAbuseIPDBConfig{
				CheckBeforeReport:        true,
				MinConfidenceToReport:    25,
				MinConfidenceToBan:       50,
				SuppressIfConfidenceZero: true,
			},
			VirusTotal: ReputationPolicyVirusTotalConfig{
				Enabled:         true,
				SuppressIfClean: true,
			},
			Cloudflare: ReputationPolicyCloudflareConfig{
				DefaultBanDuration: time.Hour,
				Recidive2Duration:  24 * time.Hour,
				Recidive3Duration:  168 * time.Hour,
				AutoDebanEnabled:   true,
				CleanupInterval:    5 * time.Minute,
			},
		},
		HTTPErrorIntel: HTTPErrorIntelConfig{
			Enabled:      true,
			EnforceMode:  false,
			MinBurst:     3,
			BanThreshold: 20,
		},
		TrustedNetworks: TrustedNetworksConfig{
			Enabled: true,
			// Mode is intentionally "shadow" — never default to "enforce".
			// See TrustedNetworksConfig's doc comment for the invariant
			// this protects.
			Mode:         "shadow",
			SyncInterval: 10 * time.Minute,
			CrowdSec: TrustedNetworksCrowdSecConfig{
				Enabled:       true,
				AllowlistName: "my_allowlist",
			},
			Cloudflare: TrustedNetworksCloudflareConfig{
				Enabled: true,
			},
		},
		CrowdSec: CrowdSecConfig{
			DecisionsLog:  "/var/log/crowdsec/decisions.log",
			NginxLogDir:   "/var/log/nginx",
			BinPath:       "cscli",
			Timeout:       15 * time.Second,
			AllowlistName: "my_allowlist",
		},
		OpenResty: OpenRestyConfig{
			EventsFile:  "/run/crowdsec-lua/events.jsonl",
			WAFRefsFile: "/run/crowdsec-lua/waf_refs.jsonl",
		},
		StateDir: "/var/lib/security-automation-go",
		Interval: 60 * time.Second,
	}
}

// Load reads config from a YAML file and applies environment overrides.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open config file %q: %w", path, err)
		}
		defer f.Close()

		decoder := yaml.NewDecoder(f)
		decoder.KnownFields(true) // Strict mode
		if err := decoder.Decode(cfg); err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("failed to decode YAML config %q: %w", path, err)
			}
		}
	}

	applyEnvOverrides(cfg)
	cfg.FinalizePaths()

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// FinalizePaths ensures that derived paths are relative to the current StateDir
// if they haven't been explicitly overridden.
func (c *Config) FinalizePaths() {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/security-automation-go"
	}
	if c.Global.AdminTokenFile == "" {
		c.Global.AdminTokenFile = filepath.Join(c.StateDir, "runtime", "admin_token")
	}
	if c.UI.SecretFile == "" {
		c.UI.SecretFile = filepath.Join(c.StateDir, "runtime", "ui_secret")
	}
	if c.UI.ProviderStateFile == "" {
		c.UI.ProviderStateFile = filepath.Join(c.StateDir, "runtime", "ai-providers.env")
	}
	if c.Cloudflare.CleanupInterval <= 0 {
		c.Cloudflare.CleanupInterval = 5 * time.Minute
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("CF_SYNC_API_TOKEN"); v != "" {
		cfg.Global.AdminToken = v
	}
	if v := os.Getenv("CF_SYNC_API_TOKEN_FILE"); v != "" {
		cfg.Global.AdminTokenFile = v
	}
	if v := os.Getenv("CF_API_TOKEN"); v != "" {
		cfg.Cloudflare.APIToken = v
	}
	if v := os.Getenv("CF_ZONE_ID"); v != "" {
		cfg.Cloudflare.ZoneID = v
	}
	if v := os.Getenv("CS_API_KEY"); v != "" {
		cfg.CrowdSec.APIKey = v
	}
	if v := os.Getenv("DECISIONS_LOG"); v != "" {
		cfg.CrowdSec.DecisionsLog = v
	}
	if v := os.Getenv("CS_POLLER_LAPI_URL"); v != "" {
		cfg.CrowdSec.PollerLAPIURL = v
	}
	if v := os.Getenv("CS_POLLER_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CrowdSec.PollerInterval = d
		}
	}
	if v := os.Getenv("NGINX_LOG_DIR"); v != "" {
		cfg.CrowdSec.NginxLogDir = v
	}
	if v := os.Getenv("LUA_EVENTS_FILE"); v != "" {
		cfg.OpenResty.EventsFile = v
	}
	if v := os.Getenv("LUA_WAF_REFS_FILE"); v != "" {
		cfg.OpenResty.WAFRefsFile = v
	}
	if v := os.Getenv("ABUSEIPDB_KEY"); v != "" {
		cfg.AbuseIPDB.APIKey = v
	}
	if v := os.Getenv("SPAMHAUS_API_KEY"); v != "" {
		cfg.Spamhaus.APIKey = v
	}
	if v := os.Getenv("SPAMHAUS_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Spamhaus.Enabled = enabled
		}
	}
	if v := os.Getenv("VIRUSTOTAL_API_KEY"); v != "" {
		cfg.VirusTotal.APIKey = v
	}
	if v := os.Getenv("VIRUSTOTAL_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.VirusTotal.Enabled = enabled
		}
	}
	if v := os.Getenv("UI_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.UI.Enabled = enabled
		}
	}
	if v := os.Getenv("UI_ADDR"); v != "" {
		cfg.UI.Addr = v
	}
	bindAddr := os.Getenv("SECURITY_AUTOMATION_BIND_ADDR")
	webPort := os.Getenv("SECURITY_AUTOMATION_WEB_PORT")
	if bindAddr != "" || webPort != "" {
		host, portStr, _ := net.SplitHostPort(cfg.UI.Addr)
		if bindAddr != "" {
			host = bindAddr
		}
		if webPort != "" {
			portStr = webPort
		}
		cfg.UI.Addr = net.JoinHostPort(host, portStr)
	}
	if v := os.Getenv("UI_MUTATIONS_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.UI.MutationsEnabled = enabled
		}
	}
	if v := os.Getenv("UI_SECRET_FILE"); v != "" {
		cfg.UI.SecretFile = v
	}
	if v := os.Getenv("UI_PROVIDER_STATE_FILE"); v != "" {
		cfg.UI.ProviderStateFile = v
	}
	if v := os.Getenv("ENRICHMENT_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Enrichment.Enabled = enabled
		}
	}
	if v := os.Getenv("ENRICHMENT_DNS_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Enrichment.DNSEnabled = enabled
		}
	}
	if v := os.Getenv("ENRICHMENT_ASN_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Enrichment.ASNEnabled = enabled
		}
	}
	if v := os.Getenv("ENRICHMENT_TIMEOUT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			cfg.Enrichment.Timeout = time.Duration(ms) * time.Millisecond
		}
	}
	if v := os.Getenv("ENRICHMENT_CACHE_TTL"); v != "" {
		if ttl, err := time.ParseDuration(v); err == nil {
			cfg.Enrichment.CacheTTL = ttl
		}
	}
	if v := os.Getenv("BETTERSTACK_SOURCE_TOKEN"); v != "" {
		cfg.BetterStack.SourceToken = v
	}
	if v := os.Getenv("BETTERSTACK_INGESTING_HOST"); v != "" {
		cfg.BetterStack.IngestingHost = v
	}
	if v := os.Getenv("STATE_DIR"); v != "" {
		cfg.StateDir = v
	}
	if v := os.Getenv("RUNTIME_PROFILE"); v != "" {
		cfg.Runtime.Profile = v
	}
	if v := os.Getenv("SECURITY_AUTOMATION_PROTECTED_HOSTS"); v != "" {
		for _, host := range strings.Split(v, ",") {
			if h := strings.TrimSpace(host); h != "" {
				cfg.Global.ProtectedHosts = append(cfg.Global.ProtectedHosts, h)
			}
		}
	}
}

func validate(cfg *Config) error {
	if cfg.Version != SchemaVersion {
		return fmt.Errorf("unsupported config schema version: %s (expected %s)", cfg.Version, SchemaVersion)
	}
	if cfg.UI.Enabled && cfg.UI.Addr == "" {
		return errors.New("ui.addr is required when UI is enabled (set UI_ADDR or ui.addr in the config file)")
	}
	if v := os.Getenv("SECURITY_AUTOMATION_BIND_ADDR"); v != "" {
		if net.ParseIP(v) == nil {
			return fmt.Errorf("SECURITY_AUTOMATION_BIND_ADDR %q is not a valid IP address", v)
		}
	}
	if v := os.Getenv("SECURITY_AUTOMATION_WEB_PORT"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("SECURITY_AUTOMATION_WEB_PORT %q is not a valid port (1-65535)", v)
		}
	}
	if cfg.Interval <= 0 {
		return errors.New("interval must be positive (set global.interval or interval in the config file)")
	}
	switch cfg.Runtime.Profile {
	case "", RuntimeProfileSingleNode:
		cfg.Runtime.Profile = RuntimeProfileSingleNode
	case RuntimeProfileStrictHA:
	default:
		return fmt.Errorf("unsupported runtime profile %q (allowed: %q, %q)", cfg.Runtime.Profile, RuntimeProfileSingleNode, RuntimeProfileStrictHA)
	}
	return nil
}

// MaskedString returns a safe representation of the config for logging.
func (c *Config) MaskedString() string {
	maskedToken := "****"
	if len(c.Cloudflare.APIToken) > 8 {
		maskedToken = c.Cloudflare.APIToken[:4] + "..." + c.Cloudflare.APIToken[len(c.Cloudflare.APIToken)-4:]
	}
	return fmt.Sprintf(
		"version=%s env=%s service=%s zone=%s token=%s admin_token_file=%s abuseipdb=%t spamhaus=%t virustotal=%t ui=%t ui_addr=%s ui_secret_file=%s ui_provider_state_file=%s state=%s interval=%s",
		c.Version,
		c.Global.AppEnv,
		c.Global.ServiceName,
		c.Cloudflare.ZoneID,
		maskedToken,
		c.Global.AdminTokenFile,
		c.AbuseIPDB.Enabled,
		c.Spamhaus.Enabled,
		c.VirusTotal.Enabled,
		c.UI.Enabled,
		c.UI.Addr,
		c.UI.SecretFile,
		c.UI.ProviderStateFile,
		c.StateDir,
		c.Interval,
	)
}

// GetAdminToken returns the administrative token from environment/config or file.
func (c *Config) GetAdminToken() string {
	if c.Global.AdminToken != "" {
		return c.Global.AdminToken
	}
	if c.Global.AdminTokenFile != "" {
		b, err := os.ReadFile(c.Global.AdminTokenFile)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// ResolveAdminToken returns the admin API token for daemon startup.
// Precedence: CF_SYNC_API_TOKEN_FILE (file) > CF_SYNC_API_TOKEN (env).
// If CF_SYNC_API_TOKEN_FILE is set but the file cannot be read or is empty,
// an error is returned and startup must fail. Token values are never logged.
func ResolveAdminToken() (string, error) {
	if path := strings.TrimSpace(os.Getenv("CF_SYNC_API_TOKEN_FILE")); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("CF_SYNC_API_TOKEN_FILE: read %q: %w", path, err)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return "", fmt.Errorf("CF_SYNC_API_TOKEN_FILE: file %q is empty", path)
		}
		return token, nil
	}
	token := strings.TrimSpace(os.Getenv("CF_SYNC_API_TOKEN"))
	if token == "" {
		return "", errors.New("CF_SYNC_API_TOKEN is required (or set CF_SYNC_API_TOKEN_FILE)")
	}
	return token, nil
}
