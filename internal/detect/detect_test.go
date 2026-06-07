package detect

import (
	"strings"
	"testing"
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
	fileExists = func(path string) bool { return strings.HasSuffix(path, "state.db") }
	defer func() { fileExists = origFile }()

	r := DetectSQLite(Config{StateDir: "/var/lib/security-automation-go"})
	if !r.Healthy {
		t.Error("expected healthy when DB exists")
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
	if r.Details["path"] != "/var/log/security-automation" {
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
