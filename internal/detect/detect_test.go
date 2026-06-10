package detect

import (
	"strings"
	"testing"
	"time"
)

func TestRunAll_ReturnsNineResults(t *testing.T) {
	cfg := Config{}
	results := RunAll(cfg)
	if len(results) != 9 {
		t.Fatalf("expected 9 results, got %d", len(results))
	}
}

func TestToJSON_Valid(t *testing.T) {
	results := []Result{{Name: "test", Installed: true, Details: map[string]string{"key": "val"}}}
	data, err := ToJSON(results)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}
}

func TestRunAll_AllHaveNames(t *testing.T) {
	results := RunAll(Config{})
	for i, r := range results {
		if r.Name == "" {
			t.Errorf("result[%d] has empty name", i)
		}
	}
}

func TestDetectCrowdSec_NotConfigured(t *testing.T) {
	origBin := binaryInstalled
	origFile := fileExists
	origSvc := systemdServiceActive
	binaryInstalled = func(string) bool { return false }
	fileExists = func(string) bool { return false }
	systemdServiceActive = func(string) bool { return false }
	defer func() {
		binaryInstalled = origBin
		fileExists = origFile
		systemdServiceActive = origSvc
	}()

	r := DetectCrowdSec(Config{})
	if r.Name != "crowdsec" {
		t.Errorf("expected name crowdsec, got %q", r.Name)
	}
	if r.Healthy {
		t.Error("expected not healthy when nothing configured")
	}
	if r.Configured {
		t.Error("expected not configured when DecisionsLog is empty")
	}
}

func TestDetectCrowdSec_FullyConfigured(t *testing.T) {
	origBin := binaryInstalled
	origFile := fileExists
	origSvc := systemdServiceActive
	binaryInstalled = func(string) bool { return true }
	fileExists = func(string) bool { return true }
	systemdServiceActive = func(string) bool { return true }
	defer func() {
		binaryInstalled = origBin
		fileExists = origFile
		systemdServiceActive = origSvc
	}()

	r := DetectCrowdSec(Config{DecisionsLog: "/var/log/crowdsec/decisions.json"})
	if !r.Installed || !r.Configured || !r.Healthy {
		t.Errorf("expected installed+configured+healthy, got installed=%v configured=%v healthy=%v",
			r.Installed, r.Configured, r.Healthy)
	}
}

func TestDetectCloudflare_BothMissing(t *testing.T) {
	r := DetectCloudflareConfig(Config{})
	if r.Configured || r.Healthy {
		t.Error("expected not configured when both token and zone missing")
	}
	if !r.Installed {
		t.Error("cloudflare is a cloud service and should always be installed=true")
	}
}

func TestDetectCloudflare_BothPresent(t *testing.T) {
	r := DetectCloudflareConfig(Config{CloudflareToken: "tok", CloudflareZoneID: "zone"})
	if !r.Configured || !r.Healthy {
		t.Error("expected configured+healthy when both token and zone set")
	}
}

func TestDetectSQLite_DBExists(t *testing.T) {
	origFile := fileExists
	fileExists = func(path string) bool { return strings.HasSuffix(path, "runtime.db") }
	defer func() { fileExists = origFile }()

	r := DetectSQLite(Config{StateDir: "/var/lib/security-automation-go"})
	if !r.Healthy {
		t.Error("expected healthy when runtime.db exists")
	}
}

func TestDetectSQLite_UsesRuntimeDB(t *testing.T) {
	var checkedPath string
	origFile := fileExists
	fileExists = func(path string) bool { checkedPath = path; return true }
	defer func() { fileExists = origFile }()

	DetectSQLite(Config{StateDir: "/var/lib/security-automation-go"})
	if !strings.HasSuffix(checkedPath, "runtime.db") {
		t.Errorf("expected to check runtime.db, got %q", checkedPath)
	}
}

func TestDetectOpenResty_InstalledAndRunning(t *testing.T) {
	origBin := binaryInstalled
	origSvc := systemdServiceActive
	binaryInstalled = func(string) bool { return true }
	systemdServiceActive = func(string) bool { return true }
	defer func() {
		binaryInstalled = origBin
		systemdServiceActive = origSvc
	}()

	r := DetectOpenResty(Config{})
	if !r.Healthy {
		t.Error("expected healthy when binary installed and service active")
	}
	if !r.Installed {
		t.Error("expected installed=true")
	}
}

func TestDetectOpenResty_InstalledNoEventsFile_StillHealthy(t *testing.T) {
	origBin := binaryInstalled
	origSvc := systemdServiceActive
	binaryInstalled = func(string) bool { return true }
	systemdServiceActive = func(string) bool { return true }
	defer func() {
		binaryInstalled = origBin
		systemdServiceActive = origSvc
	}()

	// Events file not configured — should not affect Healthy status.
	r := DetectOpenResty(Config{OpenRestyEventsFile: ""})
	if !r.Healthy {
		t.Error("expected healthy even when events file not configured")
	}
	if r.Configured {
		t.Error("expected configured=false when events file path is empty")
	}
}

func TestDetectSQLite_NoDB(t *testing.T) {
	origFile := fileExists
	fileExists = func(string) bool { return false }
	defer func() { fileExists = origFile }()

	r := DetectSQLite(Config{StateDir: "/var/lib/security-automation-go"})
	if r.Healthy {
		t.Error("expected not healthy when DB missing")
	}
	if !r.Configured {
		t.Error("expected configured when StateDir is set")
	}
}

func TestDetectStateDir_WritableDir(t *testing.T) {
	origFile := fileExists
	origWrite := dirWritable
	fileExists = func(string) bool { return true }
	dirWritable = func(string) bool { return true }
	defer func() { fileExists = origFile; dirWritable = origWrite }()

	r := DetectStateDir(Config{StateDir: "/var/lib/security-automation-go"})
	if !r.Healthy {
		t.Error("expected healthy for existing writable dir")
	}
}

func TestDetectStateDir_DefaultPath(t *testing.T) {
	origFile := fileExists
	origWrite := dirWritable
	fileExists = func(string) bool { return false }
	dirWritable = func(string) bool { return false }
	defer func() { fileExists = origFile; dirWritable = origWrite }()

	r := DetectStateDir(Config{}) // empty StateDir — should use default
	if r.Details["path"] != "/var/lib/security-automation-go" {
		t.Errorf("expected default path, got %q", r.Details["path"])
	}
}

func TestDetectLogDir_DefaultPath(t *testing.T) {
	origFile := fileExists
	fileExists = func(string) bool { return false }
	defer func() { fileExists = origFile }()

	r := DetectLogDir(Config{})
	if r.Details["path"] != "/var/log/security-automation-go" {
		t.Errorf("expected default log path, got %q", r.Details["path"])
	}
}

func TestDetectSecretDir_DefaultPath(t *testing.T) {
	origFile := fileExists
	fileExists = func(string) bool { return false }
	defer func() { fileExists = origFile }()

	r := DetectSecretDir(Config{})
	if r.Details["path"] != "/etc/security-automation-go/secrets" {
		t.Errorf("expected default secret path, got %q", r.Details["path"])
	}
}

func TestDetectSystemd_NoSystemctl(t *testing.T) {
	origBin := binaryInstalled
	origSvc := systemdServiceActive
	binaryInstalled = func(string) bool { return false }
	systemdServiceActive = func(string) bool { return false }
	defer func() { binaryInstalled = origBin; systemdServiceActive = origSvc }()

	r := DetectSystemd(Config{})
	if r.Installed {
		t.Error("expected not installed when systemctl missing")
	}
	if r.Healthy {
		t.Error("expected not healthy when systemctl missing")
	}
}

func TestDetectOpenResty_NotConfigured(t *testing.T) {
	origBin := binaryInstalled
	origFile := fileExists
	origSvc := systemdServiceActive
	binaryInstalled = func(string) bool { return false }
	fileExists = func(string) bool { return false }
	systemdServiceActive = func(string) bool { return false }
	defer func() {
		binaryInstalled = origBin
		fileExists = origFile
		systemdServiceActive = origSvc
	}()

	r := DetectOpenResty(Config{})
	if r.Configured {
		t.Error("expected not configured when OpenRestyEventsFile is empty")
	}
	if r.Healthy {
		t.Error("expected not healthy when not configured")
	}
}

func TestDetectNginx_ConfiguredLogDirExists(t *testing.T) {
	origFile := fileExists
	origSvc := systemdServiceActive
	fileExists = func(string) bool { return true }
	systemdServiceActive = func(string) bool { return false }
	defer func() {
		fileExists = origFile
		systemdServiceActive = origSvc
	}()

	r := DetectNginx(Config{NginxLogDir: "/var/log/nginx"})
	if !r.Configured {
		t.Error("expected configured when NginxLogDir is set")
	}
	if !r.Healthy {
		t.Error("expected healthy when log dir exists (nginx healthy does not require binary)")
	}
}

// ---------------------------------------------------------------------------
// CrowdSec extended detection tests
// ---------------------------------------------------------------------------

func setupCrowdSecOverrides(binOK, svcOK, fileOK bool) (restore func()) {
	origBin := binaryInstalled
	origSvc := systemdServiceActive
	origFile := fileExists
	origHTTP := httpProbe
	origTCP := tcpDial
	binaryInstalled = func(string) bool { return binOK }
	systemdServiceActive = func(string) bool { return svcOK }
	fileExists = func(string) bool { return fileOK }
	// Default: LAPI and AppSec are not reachable.
	httpProbe = func(string, time.Duration) (int, error) { return 0, errRefused }
	tcpDial = func(string, time.Duration) bool { return false }
	return func() {
		binaryInstalled = origBin
		systemdServiceActive = origSvc
		fileExists = origFile
		httpProbe = origHTTP
		tcpDial = origTCP
	}
}

// stubErr is a minimal error type for test fakes.
type stubErr struct{ msg string }

func (e *stubErr) Error() string { return e.msg }

var errRefused = &stubErr{"connection refused"}

// TestDetectCrowdSec_Absent: binary missing, service missing → Installed=false, lapi_reachable=missing.
func TestDetectCrowdSec_Absent(t *testing.T) {
	restore := setupCrowdSecOverrides(false, false, false)
	defer restore()

	r := DetectCrowdSec(Config{})
	if r.Installed {
		t.Error("expected Installed=false when cscli not found")
	}
	if r.Details["lapi_reachable"] != "missing" {
		t.Errorf("expected lapi_reachable=missing, got %q", r.Details["lapi_reachable"])
	}
	if r.Healthy {
		t.Error("expected Healthy=false when absent")
	}
}

// TestDetectCrowdSec_InstalledServiceDown: cscli present, service down, LAPI unreachable → Healthy=false.
func TestDetectCrowdSec_InstalledServiceDown(t *testing.T) {
	restore := setupCrowdSecOverrides(true, false, false)
	defer restore()

	r := DetectCrowdSec(Config{DecisionsLog: "/var/log/crowdsec/decisions.json"})
	if !r.Installed {
		t.Error("expected Installed=true when cscli found")
	}
	if r.Healthy {
		t.Errorf("expected Healthy=false when service is down")
	}
	if r.Details["service"] != "missing" {
		t.Errorf("expected service=missing, got %q", r.Details["service"])
	}
}

// TestDetectCrowdSec_LAPIReachable: cscli present, service active, probe returns 401 →
// lapi_reachable=present, lapi_url=http://127.0.0.1:8080.
func TestDetectCrowdSec_LAPIReachable(t *testing.T) {
	restore := setupCrowdSecOverrides(true, true, true)
	defer restore()
	httpProbe = func(url string, _ time.Duration) (int, error) {
		if strings.Contains(url, "8080") {
			return 401, nil
		}
		return 0, errRefused
	}

	r := DetectCrowdSec(Config{DecisionsLog: "/var/log/crowdsec/decisions.json"})
	if r.Details["lapi_reachable"] != "present" {
		t.Errorf("expected lapi_reachable=present, got %q", r.Details["lapi_reachable"])
	}
	if r.Details["lapi_url"] != "http://127.0.0.1:8080" {
		t.Errorf("expected lapi_url=http://127.0.0.1:8080, got %q", r.Details["lapi_url"])
	}
	if !r.Healthy {
		t.Error("expected Healthy=true when installed+configured+service active")
	}
}

// TestDetectCrowdSec_LAPIFallback: first URL (8080) not reachable, second (8088) returns 401 →
// lapi_url=http://127.0.0.1:8088.
func TestDetectCrowdSec_LAPIFallback(t *testing.T) {
	restore := setupCrowdSecOverrides(true, true, true)
	defer restore()
	httpProbe = func(url string, _ time.Duration) (int, error) {
		if strings.Contains(url, "8088") {
			return 401, nil
		}
		return 0, errRefused
	}

	r := DetectCrowdSec(Config{DecisionsLog: "/var/log/crowdsec/decisions.json"})
	if r.Details["lapi_reachable"] != "present" {
		t.Errorf("expected lapi_reachable=present, got %q", r.Details["lapi_reachable"])
	}
	if r.Details["lapi_url"] != "http://127.0.0.1:8088" {
		t.Errorf("expected lapi_url=http://127.0.0.1:8088, got %q", r.Details["lapi_url"])
	}
}

// TestDetectCrowdSecLAPIURL_NoneReachable: both fail → returns ("", false).
func TestDetectCrowdSecLAPIURL_NoneReachable(t *testing.T) {
	origHTTP := httpProbe
	httpProbe = func(string, time.Duration) (int, error) { return 0, errRefused }
	defer func() { httpProbe = origHTTP }()

	url, ok := DetectCrowdSecLAPIURL(100 * time.Millisecond)
	if ok {
		t.Errorf("expected ok=false, got url=%q", url)
	}
	if url != "" {
		t.Errorf("expected empty url, got %q", url)
	}
}
