package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile_MissingFile(t *testing.T) {
	if err := LoadEnvFile("/tmp/nonexistent-security-automation-test.env"); err != nil {
		t.Errorf("missing file should be a no-op, got: %v", err)
	}
}

func TestLoadEnvFile_SetsUnsetVars(t *testing.T) {
	const key = "SA_TEST_ENVFILE_KEY"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	f := filepath.Join(t.TempDir(), "test.env")
	os.WriteFile(f, []byte(key+"=hello\n"), 0o600)

	if err := LoadEnvFile(f); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if got := os.Getenv(key); got != "hello" {
		t.Errorf("expected hello, got %q", got)
	}
}

func TestLoadEnvFile_DoesNotOverrideExistingVars(t *testing.T) {
	const key = "SA_TEST_ENVFILE_KEY2"
	os.Setenv(key, "original")
	t.Cleanup(func() { os.Unsetenv(key) })

	f := filepath.Join(t.TempDir(), "test.env")
	os.WriteFile(f, []byte(key+"=override\n"), 0o600)

	if err := LoadEnvFile(f); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if got := os.Getenv(key); got != "original" {
		t.Errorf("expected original (env wins over file), got %q", got)
	}
}

func TestLoadEnvFile_StripsQuotes(t *testing.T) {
	const key = "SA_TEST_ENVFILE_QUOTED"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	f := filepath.Join(t.TempDir(), "test.env")
	os.WriteFile(f, []byte(key+`="quoted value"`+"\n"), 0o600)

	if err := LoadEnvFile(f); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if got := os.Getenv(key); got != "quoted value" {
		t.Errorf("expected 'quoted value', got %q", got)
	}
}

func TestLoadEnvFile_SkipsCommentsAndBlanks(t *testing.T) {
	const key = "SA_TEST_ENVFILE_COMMENT"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	f := filepath.Join(t.TempDir(), "test.env")
	content := "# this is a comment\n\n" + key + "=set\n"
	os.WriteFile(f, []byte(content), 0o600)

	if err := LoadEnvFile(f); err != nil {
		t.Fatalf("LoadEnvFile: %v", err)
	}
	if got := os.Getenv(key); got != "set" {
		t.Errorf("expected set, got %q", got)
	}
}

func TestApplyEnvOverrides_BindAddrAndWebPort(t *testing.T) {
	os.Setenv("SECURITY_AUTOMATION_BIND_ADDR", "0.0.0.0")
	os.Setenv("SECURITY_AUTOMATION_WEB_PORT", "8080")
	t.Cleanup(func() {
		os.Unsetenv("SECURITY_AUTOMATION_BIND_ADDR")
		os.Unsetenv("SECURITY_AUTOMATION_WEB_PORT")
	})

	cfg := DefaultConfig()
	cfg.UI.Addr = "127.0.0.1:9091"
	applyEnvOverrides(cfg)

	if cfg.UI.Addr != "0.0.0.0:8080" {
		t.Errorf("expected 0.0.0.0:8080, got %s", cfg.UI.Addr)
	}
}

func TestApplyEnvOverrides_BindAddrOnly(t *testing.T) {
	os.Setenv("SECURITY_AUTOMATION_BIND_ADDR", "0.0.0.0")
	t.Cleanup(func() { os.Unsetenv("SECURITY_AUTOMATION_BIND_ADDR") })

	cfg := DefaultConfig()
	cfg.UI.Addr = "127.0.0.1:9091"
	applyEnvOverrides(cfg)

	if cfg.UI.Addr != "0.0.0.0:9091" {
		t.Errorf("expected 0.0.0.0:9091, got %s", cfg.UI.Addr)
	}
}

func TestValidate_InvalidBindAddr(t *testing.T) {
	os.Setenv("SECURITY_AUTOMATION_BIND_ADDR", "not-an-ip")
	t.Cleanup(func() { os.Unsetenv("SECURITY_AUTOMATION_BIND_ADDR") })

	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = "zone"
	cfg.Interval = 30e9

	if err := validate(cfg); err == nil {
		t.Error("expected error for invalid SECURITY_AUTOMATION_BIND_ADDR")
	}
}

func TestValidate_InvalidWebPort(t *testing.T) {
	os.Setenv("SECURITY_AUTOMATION_WEB_PORT", "99999")
	t.Cleanup(func() { os.Unsetenv("SECURITY_AUTOMATION_WEB_PORT") })

	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = "zone"
	cfg.Interval = 30e9

	if err := validate(cfg); err == nil {
		t.Error("expected error for invalid SECURITY_AUTOMATION_WEB_PORT")
	}
}
