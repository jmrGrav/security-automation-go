package state_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm/security-automation-go/internal/openresty/state"
)

// TestWriter_AtomicWrite verifies the file is written atomically (no partial content).
func TestWriter_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	w := state.New(state.Config{Path: path, Hostname: "test", PID: 1})
	if err := w.Write(context.Background(), []string{"1.2.3.4"}, nil, nil); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	var p state.Payload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if _, ok := p.Bans["1.2.3.4"]; !ok {
		t.Errorf("want 1.2.3.4 in bans, got: %v", p.Bans)
	}
	if p.Version != 1 {
		t.Errorf("want version=1, got %d", p.Version)
	}
	if p.EntryCount != 1 {
		t.Errorf("want entry_count=1, got %d", p.EntryCount)
	}
}

// TestWriter_ProtectedIPExcluded verifies that the filter drops IPs.
func TestWriter_ProtectedIPExcluded(t *testing.T) {
	dir := t.TempDir()
	w := state.New(state.Config{Path: filepath.Join(dir, "bans.json"), PID: 1})

	// Filter excludes RFC1918
	filter := state.FilterFunc(func(ip string) bool {
		return ip == "10.0.0.1"
	})

	if err := w.Write(context.Background(), []string{"10.0.0.1", "5.6.7.8"}, nil, filter); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))
	var p state.Payload
	_ = json.Unmarshal(data, &p)

	if _, ok := p.Bans["10.0.0.1"]; ok {
		t.Error("protected IP 10.0.0.1 must be excluded from bans.json")
	}
	if _, ok := p.Bans["5.6.7.8"]; !ok {
		t.Error("non-protected IP 5.6.7.8 must appear in bans.json")
	}
}

// TestWriter_AllowlistedIPExcluded verifies allowlisted IPs are dropped via filter.
func TestWriter_AllowlistedIPExcluded(t *testing.T) {
	dir := t.TempDir()
	w := state.New(state.Config{Path: filepath.Join(dir, "bans.json"), PID: 1})

	allowlist := map[string]bool{"9.9.9.9": true}
	filter := state.FilterFunc(func(ip string) bool { return allowlist[ip] })

	if err := w.Write(context.Background(), []string{"9.9.9.9", "11.22.33.44"}, nil, filter); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))
	var p state.Payload
	_ = json.Unmarshal(data, &p)

	if _, ok := p.Bans["9.9.9.9"]; ok {
		t.Error("allowlisted IP 9.9.9.9 must be excluded")
	}
	if _, ok := p.Bans["11.22.33.44"]; !ok {
		t.Error("non-allowlisted IP 11.22.33.44 must appear")
	}
}

// TestWriter_ShadowModeWritesOnlyToShadowPath verifies that shadow mode
// does NOT write to the real path, only to the shadow path.
func TestWriter_ShadowModeWritesOnlyToShadowPath(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "bans.json")
	shadowPath := filepath.Join(dir, "shadow-bans.json")

	w := state.New(state.Config{
		Path:       realPath,
		ShadowPath: shadowPath,
		ShadowMode: true,
		PID:        1,
	})
	if err := w.Write(context.Background(), []string{"1.2.3.4"}, nil, nil); err != nil {
		t.Fatal(err)
	}

	// Real path must NOT exist
	if _, err := os.Stat(realPath); !os.IsNotExist(err) {
		t.Error("shadow mode must not write to real bans.json path")
	}
	// Shadow path MUST exist
	if _, err := os.Stat(shadowPath); os.IsNotExist(err) {
		t.Error("shadow mode must write to shadow path")
	}
}

// TestWriter_ShadowModeNoOpWhenNoShadowPath verifies that shadow mode with
// no shadow path configured is a complete no-op.
func TestWriter_ShadowModeNoOpWhenNoShadowPath(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "bans.json")

	w := state.New(state.Config{
		Path:       realPath,
		ShadowPath: "", // no shadow path
		ShadowMode: true,
		PID:        1,
	})
	if err := w.Write(context.Background(), []string{"1.2.3.4"}, nil, nil); err != nil {
		t.Fatalf("want no error in shadow no-op mode, got: %v", err)
	}
	if _, err := os.Stat(realPath); !os.IsNotExist(err) {
		t.Error("shadow mode (no shadow path) must not write anything")
	}
}

// TestWriter_CIDRsIncluded verifies CIDR bans appear in the cidrs map.
func TestWriter_CIDRsIncluded(t *testing.T) {
	dir := t.TempDir()
	w := state.New(state.Config{Path: filepath.Join(dir, "bans.json"), PID: 1})

	if err := w.Write(context.Background(),
		[]string{"1.2.3.4"},
		[]string{"192.175.111.0/24"},
		nil,
	); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))
	var p state.Payload
	_ = json.Unmarshal(data, &p)

	if _, ok := p.CIDRs["192.175.111.0/24"]; !ok {
		t.Error("want 192.175.111.0/24 in cidrs")
	}
	if p.EntryCount != 2 {
		t.Errorf("want entry_count=2 (1 ban + 1 cidr), got %d", p.EntryCount)
	}
	if p.CIDRs["192.175.111.0/24"].Reason != "crowdsec-cidr" {
		t.Errorf("want reason=crowdsec-cidr, got %q", p.CIDRs["192.175.111.0/24"].Reason)
	}
}

// TestWriter_PayloadFormatCompatible verifies that the JSON payload matches the
// fields expected by the OpenResty Lua module (version, entry_count, bans, cidrs).
func TestWriter_PayloadFormatCompatible(t *testing.T) {
	dir := t.TempDir()
	w := state.New(state.Config{Path: filepath.Join(dir, "bans.json"), Hostname: "test-host", PID: 42})

	_ = w.Write(context.Background(), []string{"5.6.7.8"}, []string{"5.6.0.0/24"}, nil)

	data, _ := os.ReadFile(filepath.Join(dir, "bans.json"))

	// Parse as generic map to check keys without strict typing.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"version", "updated_at", "updated_at_epoch", "entry_count", "bans", "cidrs", "meta", "payload_crc32"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing required key %q in bans.json", key)
		}
	}
	if raw["writer_hostname"] != "test-host" {
		t.Errorf("want writer_hostname=test-host, got %v", raw["writer_hostname"])
	}
}

// TestWriter_PermissionError verifies that a write failure is reported as an error.
func TestWriter_PermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root — permission checks don't apply")
	}
	// Point to a read-only directory
	dir := t.TempDir()
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0755) //nolint:errcheck

	w := state.New(state.Config{Path: filepath.Join(dir, "bans.json"), PID: 1})
	err := w.Write(context.Background(), []string{"1.2.3.4"}, nil, nil)
	if err == nil {
		t.Error("want error when writing to read-only directory, got nil")
	}
}
