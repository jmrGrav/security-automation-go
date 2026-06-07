package health_test

import (
	"os"
	"testing"

	"github.com/jm/security-automation-go/internal/health"
)

func TestCheckCloudflare_BothPresent(t *testing.T) {
	c := health.CheckCloudflare(health.Config{CloudflareToken: "tok", CloudflareZoneID: "zone"})
	if c.Status != health.Green {
		t.Errorf("expected GREEN, got %s: %s", c.Status, c.Reason)
	}
}

func TestCheckCloudflare_TokenOnlyMissingZone(t *testing.T) {
	c := health.CheckCloudflare(health.Config{CloudflareToken: "tok"})
	if c.Status != health.Yellow {
		t.Errorf("expected YELLOW when zone missing, got %s", c.Status)
	}
}

func TestCheckCloudflare_BothMissing(t *testing.T) {
	c := health.CheckCloudflare(health.Config{})
	if c.Status != health.Red {
		t.Errorf("expected RED when token missing, got %s", c.Status)
	}
}

func TestCheckAbuseIPDB_KeyPresent(t *testing.T) {
	c := health.CheckAbuseIPDB(health.Config{AbuseIPDBKey: "key"})
	if c.Status != health.Green {
		t.Errorf("expected GREEN, got %s", c.Status)
	}
}

func TestCheckAbuseIPDB_EnabledNoKey(t *testing.T) {
	c := health.CheckAbuseIPDB(health.Config{AbuseIPDBEnabled: true})
	if c.Status != health.Yellow {
		t.Errorf("expected YELLOW when enabled but no key, got %s", c.Status)
	}
}

func TestCheckAbuseIPDB_NotConfigured(t *testing.T) {
	c := health.CheckAbuseIPDB(health.Config{})
	if c.Status != health.Green {
		t.Errorf("expected GREEN (optional not configured), got %s", c.Status)
	}
}

func TestCheckBetterStack_TokenPresent(t *testing.T) {
	c := health.CheckBetterStack(health.Config{BetterStackToken: "tok"})
	if c.Status != health.Green {
		t.Errorf("expected GREEN, got %s", c.Status)
	}
}

func TestCheckBetterStack_Optional(t *testing.T) {
	c := health.CheckBetterStack(health.Config{})
	if c.Status != health.Green {
		t.Errorf("expected GREEN for optional unconfigured, got %s", c.Status)
	}
}

func TestCheckSQLite_StateDirMissing(t *testing.T) {
	c := health.CheckSQLite(health.Config{StateDir: "/nonexistent-path-xyz-test"})
	if c.Status != health.Red {
		t.Errorf("expected RED for missing state dir, got %s", c.Status)
	}
}

func TestCheckSQLite_StateDirExistsNoDB(t *testing.T) {
	dir := t.TempDir()
	c := health.CheckSQLite(health.Config{StateDir: dir})
	if c.Status != health.Yellow {
		t.Errorf("expected YELLOW when dir exists but no DB, got %s", c.Status)
	}
}

func TestCheckSQLite_DBPresent(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.Create(dir + "/state.db")
	_ = f.Close()
	c := health.CheckSQLite(health.Config{StateDir: dir})
	if c.Status != health.Green {
		t.Errorf("expected GREEN when DB exists, got %s: %s", c.Status, c.Reason)
	}
}

func TestCheckSQLite_EmptyStateDir(t *testing.T) {
	c := health.CheckSQLite(health.Config{})
	if c.Status != health.Red {
		t.Errorf("expected RED when StateDir empty, got %s", c.Status)
	}
}

func TestCheckCrowdSec_NotConfigured(t *testing.T) {
	c := health.CheckCrowdSec(health.Config{})
	if c.Status != health.Green {
		t.Errorf("expected GREEN for optional unconfigured, got %s", c.Status)
	}
}

func TestCheckCrowdSec_ConfiguredLogMissing(t *testing.T) {
	c := health.CheckCrowdSec(health.Config{DecisionsLog: "/nonexistent-log-xyz-test"})
	if c.Status != health.Yellow {
		t.Errorf("expected YELLOW when log configured but missing, got %s", c.Status)
	}
}

func TestCheckCrowdSec_LogPresent(t *testing.T) {
	dir := t.TempDir()
	f, _ := os.Create(dir + "/decisions.json")
	_ = f.Close()
	c := health.CheckCrowdSec(health.Config{DecisionsLog: dir + "/decisions.json"})
	if c.Status != health.Green {
		t.Errorf("expected GREEN when log exists, got %s", c.Status)
	}
}

func TestCheckOpenResty_NotConfigured(t *testing.T) {
	c := health.CheckOpenResty(health.Config{})
	if c.Status != health.Green {
		t.Errorf("expected GREEN for optional unconfigured, got %s", c.Status)
	}
}

func TestCheckNginx_NotConfigured(t *testing.T) {
	c := health.CheckNginx(health.Config{})
	if c.Status != health.Green {
		t.Errorf("expected GREEN for optional unconfigured, got %s", c.Status)
	}
}

func TestCheckDisk_MissingPath(t *testing.T) {
	c := health.CheckDisk(health.Config{StateDir: "/nonexistent-state-dir-xyz-test"})
	if c.Status == health.Red {
		t.Errorf("expected YELLOW for unstatfs-able path, got RED: %s", c.Reason)
	}
}

func TestCheckPermissions_DirMissing(t *testing.T) {
	c := health.CheckPermissions(health.Config{SecretDir: "/nonexistent-secret-dir-xyz-test"})
	if c.Status != health.Yellow {
		t.Errorf("expected YELLOW when secret dir missing, got %s", c.Status)
	}
}

func TestCheckPermissions_SecureMode(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	c := health.CheckPermissions(health.Config{SecretDir: dir})
	if c.Status != health.Green {
		t.Errorf("expected GREEN for mode 700, got %s: %s", c.Status, c.Reason)
	}
}

func TestCheckStateDir_Missing(t *testing.T) {
	c := health.CheckStateDir(health.Config{StateDir: "/nonexistent-state-xyz-test"})
	if c.Status != health.Red {
		t.Errorf("expected RED for missing state dir, got %s", c.Status)
	}
}

func TestCheckStateDir_ExistsWritable(t *testing.T) {
	dir := t.TempDir()
	c := health.CheckStateDir(health.Config{StateDir: dir})
	if c.Status != health.Green {
		t.Errorf("expected GREEN for writable temp dir, got %s: %s", c.Status, c.Reason)
	}
}

func TestCheckLogDir_Missing(t *testing.T) {
	c := health.CheckLogDir(health.Config{LogDir: "/nonexistent-log-xyz-test"})
	if c.Status != health.Yellow {
		t.Errorf("expected YELLOW for missing log dir, got %s", c.Status)
	}
}

func TestRunAll_ReturnsElevenChecks(t *testing.T) {
	results := health.RunAll(health.Config{})
	if len(results) != 11 {
		t.Fatalf("expected 11 checks, got %d", len(results))
	}
}

func TestRunAll_AllHaveNames(t *testing.T) {
	results := health.RunAll(health.Config{})
	for i, c := range results {
		if c.Name == "" {
			t.Errorf("check[%d] has empty name", i)
		}
	}
}
