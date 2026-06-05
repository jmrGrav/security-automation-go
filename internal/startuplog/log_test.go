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
