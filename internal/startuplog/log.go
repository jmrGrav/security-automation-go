package startuplog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const DefaultLogDir = "/var/log/security-automation"

// StartupInfo holds non-sensitive facts logged at startup.
type StartupInfo struct {
	Version    string
	Mode       string
	BindAddr   string
	ConfigFile string
	DBPath     string
	DryRun     bool
	Providers  []string
}

// Logger writes startup diagnostics to three files in a directory:
// startup.log, config-check.log, and healthcheck.log.
// All writes are best-effort; errors are silently discarded.
type Logger struct {
	dir     string
	startup io.WriteCloser
	config  io.WriteCloser
	health  io.WriteCloser
}

// New creates a Logger, opening (or creating) the three log files.
// If the directory cannot be created or files cannot be opened, New
// returns the error so callers can skip startup logging gracefully.
func New(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("startuplog: create log dir %q: %w", dir, err)
	}
	open := func(name string) (io.WriteCloser, error) {
		return os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	}
	startup, err := open("startup.log")
	if err != nil {
		return nil, fmt.Errorf("startuplog: open startup.log: %w", err)
	}
	config, err := open("config-check.log")
	if err != nil {
		startup.Close()
		return nil, fmt.Errorf("startuplog: open config-check.log: %w", err)
	}
	health, err := open("healthcheck.log")
	if err != nil {
		startup.Close()
		config.Close()
		return nil, fmt.Errorf("startuplog: open healthcheck.log: %w", err)
	}
	return &Logger{dir: dir, startup: startup, config: config, health: health}, nil
}

// WriteStartup appends a single-line startup record to startup.log.
// Secrets must never be included in StartupInfo.
func (l *Logger) WriteStartup(info StartupInfo) {
	if l == nil {
		return
	}
	fmt.Fprintf(l.startup, "%s startup version=%s mode=%s bind=%s config=%s db=%s dry_run=%v providers=%v\n",
		ts(), info.Version, info.Mode, info.BindAddr, info.ConfigFile, info.DBPath, info.DryRun, info.Providers)
}

// WriteConfigCheck appends a single config-check line to config-check.log.
func (l *Logger) WriteConfigCheck(key, result string) {
	if l == nil {
		return
	}
	fmt.Fprintf(l.config, "%s config_check key=%s result=%s\n", ts(), key, result)
}

// WriteHealthcheck appends a single healthcheck result line to healthcheck.log.
func (l *Logger) WriteHealthcheck(endpoint, status string) {
	if l == nil {
		return
	}
	fmt.Fprintf(l.health, "%s healthcheck endpoint=%s status=%s\n", ts(), endpoint, status)
}

// Close releases all file handles.
func (l *Logger) Close() {
	if l == nil {
		return
	}
	l.startup.Close()
	l.config.Close()
	l.health.Close()
}

func ts() string {
	return time.Now().UTC().Format(time.RFC3339)
}
