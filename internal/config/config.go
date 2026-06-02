package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
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
	AppEnv      string        `yaml:"app_env"`
	ServiceName string        `yaml:"service_name"`
	Log         LogConfig     `yaml:"log"`
	HTTP        HTTPConfig    `yaml:"http"`
	Tracing     TracingConfig `yaml:"tracing"`
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
}

type CrowdSecConfig struct {
	APIKey        string        `yaml:"api_key"`
	DecisionsLog  string        `yaml:"decisions_log"`
	NginxLogDir   string        `yaml:"nginx_log_dir"`
	BinPath       string        `yaml:"bin_path"`       // cscli binary path; default "cscli"
	Timeout       time.Duration `yaml:"timeout"`        // per-command timeout; default 15s
	AllowlistName string        `yaml:"allowlist_name"` // CrowdSec allowlist name; default "my_allowlist"
}

type OpenRestyConfig struct {
	EventsFile         string `yaml:"events_file"`
	LuaStatePath       string `yaml:"lua_state_path"`         // default: /run/crowdsec-lua/bans.json
	LuaStatePushEnable bool   `yaml:"lua_state_push_enabled"` // default: false (opt-in)
	ShadowLuaStatePath string `yaml:"shadow_lua_state_path"`  // write path when shadow mode
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

type BetterStackConfig struct {
	SourceToken   string `yaml:"source_token"`
	IngestingHost string `yaml:"ingesting_host"`
}

type Config struct {
	Version     string            `yaml:"version"`
	Global      GlobalConfig      `yaml:"global"`
	Runtime     RuntimeConfig     `yaml:"runtime"`
	UI          UIBoolConfig      `yaml:"ui"`
	Enrichment  EnrichmentConfig  `yaml:"enrichment"`
	Cloudflare  CloudflareConfig  `yaml:"cloudflare"`
	CrowdSec    CrowdSecConfig    `yaml:"crowdsec"`
	OpenResty   OpenRestyConfig   `yaml:"openresty"`
	AbuseIPDB   AbuseIPDBConfig   `yaml:"abuseipdb"`
	Spamhaus    SpamhausConfig    `yaml:"spamhaus"`
	VirusTotal  VirusTotalConfig  `yaml:"virustotal"`
	BetterStack BetterStackConfig `yaml:"betterstack"`
	Policies    []PolicyConfig    `yaml:"policies"`
	StateDir    string            `yaml:"state_dir"`
	Interval    time.Duration     `yaml:"interval"`
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
			Addr:              "127.0.0.1:9090",
			SecretFile:        "/var/lib/cf-sync/secrets.local",
			ProviderStateFile: "/etc/security-automation/providers/ai-providers.env",
			MutationsEnabled:  false,
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
		Spamhaus:   SpamhausConfig{},
		VirusTotal: VirusTotalConfig{},
		CrowdSec: CrowdSecConfig{
			DecisionsLog:  "/var/log/crowdsec/decisions.log",
			NginxLogDir:   "/var/log/nginx",
			BinPath:       "cscli",
			Timeout:       15 * time.Second,
			AllowlistName: "my_allowlist",
		},
		OpenResty: OpenRestyConfig{
			EventsFile: "/run/crowdsec-lua/events.jsonl",
		},
		StateDir: "/var/lib/cf-sync",
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

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("CF_API_TOKEN"); v != "" {
		cfg.Cloudflare.APIToken = v
	}
	if v := os.Getenv("CF_ZONE_ID"); v != "" {
		cfg.Cloudflare.ZoneID = v
	}
	if v := os.Getenv("CLOUDFLARE_MUTATIONS_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.Cloudflare.MutationsEnabled = enabled
		}
	}
	if v := os.Getenv("CS_API_KEY"); v != "" {
		cfg.CrowdSec.APIKey = v
	}
	if v := os.Getenv("DECISIONS_LOG"); v != "" {
		cfg.CrowdSec.DecisionsLog = v
	}
	if v := os.Getenv("NGINX_LOG_DIR"); v != "" {
		cfg.CrowdSec.NginxLogDir = v
	}
	if v := os.Getenv("LUA_EVENTS_FILE"); v != "" {
		cfg.OpenResty.EventsFile = v
	}
	if v := os.Getenv("ABUSEIPDB_KEY"); v != "" {
		cfg.AbuseIPDB.APIKey = v
	}
	if v := os.Getenv("ABUSEIPDB_ENABLED"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.AbuseIPDB.Enabled = enabled
		}
	}
	if v := os.Getenv("ABUSEIPDB_REPORTING_ENABLED"); v != "" {
		enabled, err := strconv.ParseBool(v)
		if err == nil {
			cfg.AbuseIPDB.ReportingEnabled = &enabled
		}
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
}

func validate(cfg *Config) error {
	if cfg.Version != SchemaVersion {
		return fmt.Errorf("unsupported config schema version: %s (expected %s)", cfg.Version, SchemaVersion)
	}
	if cfg.Cloudflare.APIToken == "" {
		return errors.New("cloudflare.api_token is required (set CF_API_TOKEN or cloudflare.api_token in the config file)")
	}
	if cfg.Cloudflare.ZoneID == "" {
		return errors.New("cloudflare.zone_id is required (set CF_ZONE_ID or cloudflare.zone_id in the config file)")
	}
	if cfg.UI.Enabled && cfg.UI.Addr == "" {
		return errors.New("ui.addr is required when UI is enabled (set UI_ADDR or ui.addr in the config file)")
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
		"version=%s env=%s service=%s zone=%s token=%s abuseipdb=%t spamhaus=%t virustotal=%t ui=%t ui_addr=%s ui_secret_file=%s ui_provider_state_file=%s state=%s interval=%s",
		c.Version,
		c.Global.AppEnv,
		c.Global.ServiceName,
		c.Cloudflare.ZoneID,
		maskedToken,
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
