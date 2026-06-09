package detect

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// defaultLAPIURLs are the candidate CrowdSec LAPI base URLs probed in order.
var defaultLAPIURLs = []string{
	"http://127.0.0.1:8080",
	"http://127.0.0.1:8088",
}

// lapiReachable returns true when the HTTP status is 200 or 401 (auth required but LAPI is up).
func lapiReachable(statusCode int, err error) bool {
	return err == nil && (statusCode == 200 || statusCode == 401)
}

// DetectCrowdSecLAPIURL probes the candidate LAPI base URLs in order and returns the first
// reachable one. Returns ("", false) if none responds within the timeout.
func DetectCrowdSecLAPIURL(timeout time.Duration) (string, bool) {
	for _, base := range defaultLAPIURLs {
		code, err := httpProbe(base+"/v1/decisions?limit=1", timeout)
		if lapiReachable(code, err) {
			return base, true
		}
	}
	return "", false
}

func DetectCrowdSec(cfg Config) Result {
	r := Result{Name: "crowdsec", Details: map[string]string{}}

	// Determine which cscli binary to use.
	cscliPath := "cscli"
	if strings.TrimSpace(cfg.CscliBin) != "" {
		cscliPath = cfg.CscliBin
	}

	r.Installed = binaryInstalled(cscliPath)
	r.Details["cscli"] = presentOrMissing(r.Installed)

	// Service state.
	serviceActive := systemdServiceActive("crowdsec")
	r.Details["service"] = presentOrMissing(serviceActive)

	// LAPI reachability.
	lapiURL, lapiOK := "", false
	if strings.TrimSpace(cfg.LAPIURL) != "" {
		code, err := httpProbe(cfg.LAPIURL+"/v1/decisions?limit=1", 3*time.Second)
		lapiOK = lapiReachable(code, err)
		if lapiOK {
			lapiURL = cfg.LAPIURL
		}
	} else {
		lapiURL, lapiOK = DetectCrowdSecLAPIURL(3 * time.Second)
	}
	r.Details["lapi_reachable"] = presentOrMissing(lapiOK)
	if lapiOK {
		r.Details["lapi_url"] = lapiURL
	} else {
		r.Details["lapi_url"] = string(Missing)
	}

	// AppSec: port 7422.
	appsecUp := tcpDial("127.0.0.1:7422", 1*time.Second)
	r.Details["appsec"] = presentOrMissing(appsecUp)

	// Decisions log.
	r.Configured = strings.TrimSpace(cfg.DecisionsLog) != ""
	logExists := fileExists(cfg.DecisionsLog)
	r.Details["decisions_log"] = presentOrMissing(logExists)

	// Poller config.
	r.Details["poller_enabled"] = presentOrMissing(cfg.PollerEnabled)

	r.Healthy = r.Installed && r.Configured && serviceActive
	return r
}

func DetectOpenResty(cfg Config) Result {
	r := Result{Name: "openresty", Details: map[string]string{}}
	r.Installed = binaryInstalled("openresty")
	r.Details["binary"] = presentOrMissing(r.Installed)
	r.Configured = strings.TrimSpace(cfg.OpenRestyEventsFile) != ""
	r.Details["events_file"] = valueOrMissing(cfg.OpenRestyEventsFile)
	eventsExist := fileExists(cfg.OpenRestyEventsFile)
	r.Details["events_exist"] = presentOrMissing(eventsExist)
	r.Details["service"] = presentOrMissing(systemdServiceActive("openresty"))
	r.Healthy = r.Installed && r.Configured && eventsExist
	return r
}

func DetectNginx(cfg Config) Result {
	r := Result{Name: "nginx", Details: map[string]string{}}
	r.Installed = binaryInstalled("nginx")
	r.Details["binary"] = presentOrMissing(r.Installed)
	r.Configured = strings.TrimSpace(cfg.NginxLogDir) != ""
	r.Details["log_dir"] = valueOrMissing(cfg.NginxLogDir)
	logDirExists := fileExists(cfg.NginxLogDir)
	r.Details["log_dir_exists"] = presentOrMissing(logDirExists)
	r.Details["service"] = presentOrMissing(systemdServiceActive("nginx"))
	r.Healthy = r.Configured && logDirExists
	return r
}

func DetectCloudflareConfig(cfg Config) Result {
	r := Result{Name: "cloudflare", Details: map[string]string{}}
	r.Installed = true // cloud service — always "installed"
	r.Details["type"] = "cloud-service"
	hasToken := strings.TrimSpace(cfg.CloudflareToken) != ""
	hasZone := strings.TrimSpace(cfg.CloudflareZoneID) != ""
	r.Configured = hasToken && hasZone
	r.Details["token"] = presentOrMissing(hasToken)
	r.Details["zone_id"] = presentOrMissing(hasZone)
	r.Healthy = r.Configured
	return r
}

func DetectSQLite(cfg Config) Result {
	r := Result{Name: "sqlite", Details: map[string]string{}}
	r.Installed = true // embedded — always installed
	r.Details["type"] = "embedded"
	r.Configured = strings.TrimSpace(cfg.StateDir) != ""
	r.Details["state_dir"] = valueOrMissing(cfg.StateDir)
	dbPath := ""
	if r.Configured {
		dbPath = cfg.StateDir + "/state.db"
	}
	dbExists := fileExists(dbPath)
	r.Details["db_exists"] = presentOrMissing(dbExists)
	r.Healthy = r.Configured && dbExists
	return r
}

func DetectSystemd(cfg Config) Result {
	r := Result{Name: "systemd", Details: map[string]string{}}
	r.Installed = binaryInstalled("systemctl")
	r.Details["binary"] = presentOrMissing(r.Installed)
	r.Configured = r.Installed
	r.Details["cf-sync"] = presentOrMissing(systemdServiceActive("cf-sync"))
	r.Details["crowdsec"] = presentOrMissing(systemdServiceActive("crowdsec"))
	r.Healthy = r.Installed
	return r
}

func DetectStateDir(cfg Config) Result {
	r := Result{Name: "state-directory", Details: map[string]string{}}
	path := cfg.StateDir
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/security-automation-go"
	}
	r.Details["path"] = path
	r.Configured = strings.TrimSpace(cfg.StateDir) != ""
	exists := fileExists(path)
	r.Installed = exists
	r.Details["exists"] = presentOrMissing(exists)
	writable := dirWritable(path)
	r.Details["writable"] = presentOrMissing(writable)
	r.Healthy = exists && writable
	return r
}

func DetectLogDir(cfg Config) Result {
	r := Result{Name: "log-directory", Details: map[string]string{}}
	path := cfg.LogDir
	if strings.TrimSpace(path) == "" {
		path = "/var/log/security-automation-go"
	}
	r.Details["path"] = path
	r.Configured = true
	exists := fileExists(path)
	r.Installed = exists
	r.Details["exists"] = presentOrMissing(exists)
	r.Healthy = exists
	return r
}

func DetectSecretDir(cfg Config) Result {
	r := Result{Name: "secret-directory", Details: map[string]string{}}
	path := cfg.SecretDir
	if strings.TrimSpace(path) == "" {
		path = "/etc/security-automation-go/secrets"
	}
	r.Details["path"] = path
	r.Configured = true
	exists := fileExists(path)
	r.Installed = exists
	r.Details["exists"] = presentOrMissing(exists)
	if exists {
		if info, err := os.Stat(path); err == nil {
			mode := info.Mode().Perm()
			r.Details["mode"] = fmt.Sprintf("%04o", mode)
			r.Healthy = mode&0o007 == 0
			r.Details["secure"] = presentOrMissing(r.Healthy)
		}
	}
	return r
}
