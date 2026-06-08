package detect

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
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

	// CrowdSec detection tunables.
	LAPIURL       string // if empty, probe defaults (127.0.0.1:8080 then 127.0.0.1:8088)
	CscliBin      string // if empty, default "cscli"
	PollerEnabled bool   // from cfg.CrowdSec.PollerEnabled
	PollerLAPIURL string // from cfg.CrowdSec.PollerLAPIURL (may be empty)
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

// httpProbe makes a GET request to url with the given timeout and returns the HTTP status code.
// A non-nil error means the request could not be completed (connection refused, timeout, etc.).
var httpProbe = func(url string, timeout time.Duration) (int, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// tcpDial attempts a TCP connection to addr and returns true if it succeeds within the timeout.
var tcpDial = func(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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
