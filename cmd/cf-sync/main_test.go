package main

import (
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/buildmeta"
)

func TestVersionTextUsesSharedBuildMetadata(t *testing.T) {
	origVersion, origCommit, origBuildDate := buildmeta.Version, buildmeta.Commit, buildmeta.BuildDate
	t.Cleanup(func() {
		buildmeta.Version = origVersion
		buildmeta.Commit = origCommit
		buildmeta.BuildDate = origBuildDate
	})

	buildmeta.Version = "1.7.0-dev"
	buildmeta.Commit = "abc1234"
	buildmeta.BuildDate = "2026-06-13T12:34:56Z"

	got := versionText()

	for _, want := range []string{
		"Version:    1.7.0-dev",
		"Commit:     abc1234",
		"Build date: 2026-06-13T12:34:56Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("version text missing %q: %q", want, got)
		}
	}
}
