package startuplog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew_CreatesLogFiles(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer l.Close()

	for _, name := range []string{"startup.log", "config-check.log", "healthcheck.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}
}

func TestWriteStartup_WritesLine(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	defer l.Close()

	l.WriteStartup(StartupInfo{
		Version:  "v1.2.3",
		Mode:     "daemon",
		BindAddr: "127.0.0.1:9091",
		DryRun:   true,
	})
	l.Close()

	data, err := os.ReadFile(filepath.Join(dir, "startup.log"))
	if err != nil {
		t.Fatalf("read startup.log: %v", err)
	}
	content := string(data)
	for _, want := range []string{"version=v1.2.3", "mode=daemon", "bind=127.0.0.1:9091", "dry_run=true"} {
		if !strings.Contains(content, want) {
			t.Errorf("startup.log missing %q, got: %s", want, content)
		}
	}
}

func TestWriteConfigCheck_WritesLine(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	defer l.Close()

	l.WriteConfigCheck("cloudflare_token", "ok")
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "config-check.log"))
	if !strings.Contains(string(data), "key=cloudflare_token result=ok") {
		t.Errorf("config-check.log missing expected content: %s", data)
	}
}

func TestWriteHealthcheck_WritesLine(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	defer l.Close()

	l.WriteHealthcheck("/healthz", "200 OK")
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "healthcheck.log"))
	if !strings.Contains(string(data), "endpoint=/healthz status=200 OK") {
		t.Errorf("healthcheck.log missing expected content: %s", data)
	}
}

func TestNilLogger_NoPanic(t *testing.T) {
	var l *Logger
	l.WriteStartup(StartupInfo{})
	l.WriteConfigCheck("k", "v")
	l.WriteHealthcheck("/h", "ok")
	l.Close()
}

func TestNew_NonExistentParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "nested")
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New with deep path should succeed: %v", err)
	}
	defer l.Close()
}

func TestCheckLayout_NeitherExists(t *testing.T) {
	got := CheckLayout("/nonexistent-legacy-xyz-test", "/nonexistent-canonical-xyz-test")
	if got != LayoutOK {
		t.Errorf("expected LayoutOK when neither dir exists, got %d", got)
	}
}

func TestCheckLayout_OnlyCanonicalExists(t *testing.T) {
	canonical := t.TempDir()
	got := CheckLayout("/nonexistent-legacy-xyz-test", canonical)
	if got != LayoutOK {
		t.Errorf("expected LayoutOK when only canonical exists, got %d", got)
	}
}

func TestCheckLayout_BothExist(t *testing.T) {
	legacy := t.TempDir()
	canonical := t.TempDir()
	got := CheckLayout(legacy, canonical)
	if got != LayoutBoth {
		t.Errorf("expected LayoutBoth when both exist, got %d", got)
	}
}

func TestCheckLayout_OnlyLegacyExists(t *testing.T) {
	legacy := t.TempDir()
	got := CheckLayout(legacy, "/nonexistent-canonical-xyz-test")
	if got != LayoutLegacy {
		t.Errorf("expected LayoutLegacy when only legacy exists, got %d", got)
	}
}

func TestWriteLayoutWarning_BothExist(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	defer l.Close()

	l.WriteLayoutWarning(LayoutBoth, "/etc/security-automation", "/etc/security-automation-go/secrets")
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "startup.log"))
	content := string(data)
	if !strings.Contains(content, "layout_warning") {
		t.Errorf("expected layout_warning in startup.log, got: %s", content)
	}
	if !strings.Contains(content, "status=BOTH_EXIST") {
		t.Errorf("expected status=BOTH_EXIST, got: %s", content)
	}
}

func TestWriteLayoutWarning_LegacyOnly(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	defer l.Close()

	l.WriteLayoutWarning(LayoutLegacy, "/etc/security-automation", "/etc/security-automation-go/secrets")
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "startup.log"))
	if !strings.Contains(string(data), "status=LEGACY_ONLY") {
		t.Errorf("expected status=LEGACY_ONLY in startup.log, got: %s", data)
	}
}

func TestWriteLayoutWarning_OK_NoWrite(t *testing.T) {
	dir := t.TempDir()
	l, _ := New(dir)
	defer l.Close()

	l.WriteLayoutWarning(LayoutOK, "/etc/security-automation", "/etc/security-automation-go/secrets")
	l.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "startup.log"))
	if strings.Contains(string(data), "layout_warning") {
		t.Errorf("expected no layout_warning for LayoutOK, got: %s", data)
	}
}

func TestWriteLayoutWarning_NilLogger_NoPanic(t *testing.T) {
	var l *Logger
	l.WriteLayoutWarning(LayoutLegacy, "/etc/security-automation", "/etc/security-automation-go/secrets")
}

// TestLogger_CopyTruncate_WritesAfterTruncate proves that Logger opened with
// O_APPEND correctly writes to position 0 after the file is truncated in place
// by logrotate's copytruncate strategy — no SIGUSR1 or file reopen required.
func TestLogger_CopyTruncate_WritesAfterTruncate(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	l.WriteStartup(StartupInfo{Mode: "before-rotate"})

	// Simulate copytruncate: truncate the file to zero while the Logger
	// still holds its fd open. O_APPEND must seek to end (== 0) before writing.
	startupPath := filepath.Join(dir, "startup.log")
	if err := os.Truncate(startupPath, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	l.WriteStartup(StartupInfo{Mode: "after-rotate"})
	l.Close()

	data, err := os.ReadFile(startupPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "mode=after-rotate") {
		t.Errorf("expected post-truncate write in file, got: %q", got)
	}
	if strings.Contains(got, "mode=before-rotate") {
		t.Errorf("truncated content should be gone, still present: %q", got)
	}
}
