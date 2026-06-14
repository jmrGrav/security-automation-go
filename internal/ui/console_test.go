package ui

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/buildmeta"
	"github.com/jm/security-automation-go/internal/config"
)

func TestConsoleLayoutIncludesLivePanelAndOperatorScript(t *testing.T) {
	comp := ConsoleLayout(shellView{
		Title:    "x",
		Headline: "x",
		Subtitle: "x",
		Active:   "/providers",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			_, _ = io.WriteString(w, `<div>body</div>`)
			return nil
		}),
	})
	var buf strings.Builder
	if err := comp.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render console layout: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		`data-live-panel-root`,
		`data-live-panel-body`,
		`data-live-toast-region`,
		`operator-live.js`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("console layout missing %q: %s", want, body)
		}
	}
}

func TestBuildInfoFromConfigUsesSharedBuildMetadata(t *testing.T) {
	origVersion, origCommit, origBuildDate := buildmeta.Version, buildmeta.Commit, buildmeta.BuildDate
	t.Cleanup(func() {
		buildmeta.Version = origVersion
		buildmeta.Commit = origCommit
		buildmeta.BuildDate = origBuildDate
	})

	buildmeta.Version = "1.7.0-dev"
	buildmeta.Commit = "abc1234"
	buildmeta.BuildDate = "2026-06-13T12:34:56Z"

	view := BuildInfoFromConfig(&config.Config{Version: "v1"}, nil, nil)

	if view.Version != buildmeta.Version {
		t.Fatalf("expected UI version %q, got %q", buildmeta.Version, view.Version)
	}
	if view.GitCommit != buildmeta.Commit {
		t.Fatalf("expected UI commit %q, got %q", buildmeta.Commit, view.GitCommit)
	}
	if view.BuildDate != buildmeta.BuildDate {
		t.Fatalf("expected UI build date %q, got %q", buildmeta.BuildDate, view.BuildDate)
	}
}
