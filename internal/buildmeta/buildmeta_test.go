package buildmeta

import (
	"runtime"
	"strings"
	"testing"
)

func TestCurrentDefaultsToDevAndLocal(t *testing.T) {
	origVersion, origCommit, origBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() {
		Version = origVersion
		Commit = origCommit
		BuildDate = origBuildDate
	})

	Version = ""
	Commit = ""
	BuildDate = ""

	got := Current()
	if got.Version != "dev" {
		t.Fatalf("expected dev version by default, got %q", got.Version)
	}
	if got.Commit != "local" {
		t.Fatalf("expected local commit by default, got %q", got.Commit)
	}
	if got.BuildDate != "local" {
		t.Fatalf("expected local build date by default, got %q", got.BuildDate)
	}
	if got.GoVersion != runtime.Version() {
		t.Fatalf("expected runtime Go version %q, got %q", runtime.Version(), got.GoVersion)
	}
	if got.GOOS != runtime.GOOS || got.GOARCH != runtime.GOARCH {
		t.Fatalf("expected runtime GOOS/GOARCH %s/%s, got %s/%s", runtime.GOOS, runtime.GOARCH, got.GOOS, got.GOARCH)
	}
}

func TestCurrentUsesInjectedValues(t *testing.T) {
	origVersion, origCommit, origBuildDate := Version, Commit, BuildDate
	t.Cleanup(func() {
		Version = origVersion
		Commit = origCommit
		BuildDate = origBuildDate
	})

	Version = "v1.7.1"
	Commit = "abc1234"
	BuildDate = "2026-06-15T00:00:00Z"

	got := Current()
	if got.Version != Version {
		t.Fatalf("expected version %q, got %q", Version, got.Version)
	}
	if got.Commit != Commit {
		t.Fatalf("expected commit %q, got %q", Commit, got.Commit)
	}
	if got.BuildDate != BuildDate {
		t.Fatalf("expected build date %q, got %q", BuildDate, got.BuildDate)
	}
}

func TestInfoStringIncludesAllFields(t *testing.T) {
	info := Info{
		Version:   "v1.7.1",
		Commit:    "abc1234",
		BuildDate: "2026-06-15T00:00:00Z",
		GoVersion: "go1.25.0",
		GOOS:      "linux",
		GOARCH:    "amd64",
	}

	got := info.String()
	for _, want := range []string{
		"Version:    v1.7.1",
		"Commit:     abc1234",
		"Build date: 2026-06-15T00:00:00Z",
		"Go version: go1.25.0",
		"OS / arch:  linux / amd64",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("string form missing %q: %q", want, got)
		}
	}
}
