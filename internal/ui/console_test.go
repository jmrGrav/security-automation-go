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

func TestConsoleLayoutIncludesCommandPaletteShell(t *testing.T) {
	comp := ConsoleLayout(shellView{
		Title:    "Test",
		Headline: "Test",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			_, err := io.WriteString(w, `<button data-command-palette-trigger="true">Ctrl+K</button>`)
			return err
		}),
	})
	var buf strings.Builder
	if err := comp.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render console layout: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"data-command-palette-root", "/search", "command-palette-input"} {
		if !strings.Contains(body, want) {
			t.Fatalf("console missing command palette shell artifact %q: %s", want, body)
		}
	}

	script := operatorLiveScript()
	for _, want := range []string{"bindCommandPalette", "keydown", "commandPaletteRoot"} {
		if !strings.Contains(script, want) {
			t.Fatalf("operator live script missing command palette artifact %q: %s", want, script)
		}
	}
}

func TestConsoleLayoutIncludesPR4DesignSystemShell(t *testing.T) {
	comp := ConsoleLayout(shellView{
		Title:    "Design System",
		Headline: "Design System",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			_, err := io.WriteString(w, `<div class="panel"><span class="badge warning">warning</span><div class="empty">empty</div></div>`)
			return err
		}),
	})
	var buf strings.Builder
	if err := comp.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render console layout: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		`data-theme-toggle="true"`,
		`--surface-bg`,
		`--surface-panel`,
		`--state-healthy`,
		`--state-warning`,
		`--state-error`,
		`body[data-theme="operations-dark"]`,
		`data-ui-surface="panel"`,
		`data-ui-state="empty"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PR4 design system shell missing %q: %s", want, body)
		}
	}
}

func TestOperatorLiveScriptSupportsThemePreference(t *testing.T) {
	script := operatorLiveScript()
	for _, want := range []string{
		"applyThemePreference",
		"bindThemeToggle",
		"security-automation:theme",
		"operations-dark",
		`data-theme-toggle="true"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("operator live script missing theme artifact %q: %s", want, script)
		}
	}
}

func TestConsoleLayoutIncludesPR5WatchlistShell(t *testing.T) {
	comp := ConsoleLayout(shellView{
		Title:    "Watchlist Test",
		Headline: "Watchlist Test",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			_, err := io.WriteString(w, `<div>body</div>`)
			return err
		}),
	})
	var buf strings.Builder
	if err := comp.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render console layout: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		`data-watchlist-widget="true"`,
		`security-automation:watchlist`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PR5 watchlist shell missing HTML artifact %q: %s", want, body)
		}
	}

	script := operatorLiveScript()
	for _, want := range []string{
		`renderWatchlist`,
		`bindWatchlistAdd`,
		`data-watchlist-add="true"`,
		`security-automation:watchlist`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("PR5 watchlist shell missing JS artifact %q", want)
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
