package detect

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// Status describes whether a component was found.
type Status string

const (
	Present Status = "present"
	Missing Status = "missing"
)

// Result is what each detector returns.
type Result struct {
	Name       string            `json:"name"`
	Installed  bool              `json:"installed"`
	Configured bool              `json:"configured"`
	Healthy    bool              `json:"healthy"`
	Details    map[string]string `json:"details"`
}

// Config holds paths and tokens used by detectors. Callers populate from config.Config.
type Config struct {
	StateDir            string
	LogDir              string
	SecretDir           string
	DecisionsLog        string
	NginxLogDir         string
	OpenRestyEventsFile string
	CloudflareToken     string
	CloudflareZoneID    string
}

// RunAll runs all detectors and returns their results.
func RunAll(cfg Config) []Result {
	fns := []func(Config) Result{
		DetectCrowdSec,
		DetectOpenResty,
		DetectNginx,
		DetectCloudflareConfig,
		DetectSQLite,
		DetectSystemd,
		DetectStateDir,
		DetectLogDir,
		DetectSecretDir,
	}
	out := make([]Result, 0, len(fns))
	for _, f := range fns {
		out = append(out, f(cfg))
	}
	return out
}

// ToJSON serializes results to indented JSON.
func ToJSON(results []Result) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

// These vars are overridable for testing.
var binaryInstalled = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var fileExists = func(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

var dirWritable = func(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	tmp, err := os.CreateTemp(path, ".detect-write-check-*")
	if err != nil {
		return false
	}
	_ = tmp.Close()
	_ = os.Remove(tmp.Name())
	return true
}

var systemdServiceActive = func(name string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", name)
	return cmd.Run() == nil
}

func presentOrMissing(ok bool) string {
	if ok {
		return string(Present)
	}
	return string(Missing)
}

func valueOrMissing(s string) string {
	if strings.TrimSpace(s) == "" {
		return string(Missing)
	}
	return s
}
