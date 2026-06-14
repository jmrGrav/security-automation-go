package ui

import (
	"context"
	"strings"
	"testing"
)

func TestAboutPageSplitsReleaseRuntimeAndRepositoryData(t *testing.T) {
	view := BuildInfoView{
		Version:       "v1.7.0-dev",
		GitCommit:     "abc1234",
		BuildDate:     "2026-06-12T10:00:00Z",
		GoVersion:     "go1.24.3",
		GOOS:          "linux",
		GOARCH:        "amd64",
		PackageCount:  "12",
		GoFileCount:   "87",
		ApproxLOC:     "12345",
		FeatureStatus: []StatusItem{{Label: "UI mode", Level: "healthy", Detail: "enabled"}},
		ProviderStatus: []string{
			"OpenAI: READY",
		},
		AIAttribution: []string{
			"OpenAI Codex",
		},
	}

	var buf strings.Builder
	if err := AboutPage("/about", view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render about page: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"Release",
		"Runtime",
		"Features",
		"Providers",
		"AI assistance / development tools",
		"v1.7.0-dev",
		"abc1234",
		"go1.24.3",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("about page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Repository") {
		t.Fatalf("about page should not render repository block anymore: %s", body)
	}
}

func TestAboutPageOmitsRepositoryPanelWhenMetricsUnavailable(t *testing.T) {
	view := BuildInfoView{
		Version:   "v1.7.0-dev",
		GitCommit: "abc1234",
		BuildDate: "2026-06-12T10:00:00Z",
		GoVersion: "go1.24.3",
		GOOS:      "linux",
		GOARCH:    "amd64",
	}

	var buf strings.Builder
	if err := AboutPage("/about", view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render about page: %v", err)
	}
	body := buf.String()
	if strings.Contains(body, "Repository") {
		t.Fatalf("about page should omit repository panel when metrics are unavailable: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "unknown") {
		t.Fatalf("about page should not render unknown placeholders: %s", body)
	}
}
