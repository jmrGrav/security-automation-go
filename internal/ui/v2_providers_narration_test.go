package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

func TestV2ProvidersShowsAliveStateNarration(t *testing.T) {
	lastTest := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	view := UnifiedProvidersView{
		AI: AIProviderManagementView{
			Providers: []AIProviderManagementEntry{
				{
					Name:              "TestAI",
					Status:            "active",
					Model:             "test-model",
					EnabledState:      "enabled",
					SecretState:       "present",
					HealthyState:      "healthy",
					LastTestAt:        lastTest,
					LastTestLatencyMS: "142ms",
				},
			},
		},
	}
	out := renderV2ProvidersPage(view, "tok")

	// Must show alive narration with "online"
	if !strings.Contains(out, "online") {
		t.Errorf("provider row must show alive state narration containing 'online'; got no such text")
	}
	// Must show tested freshness ("5m ago" or "just now")
	if !strings.Contains(out, "ago") && !strings.Contains(out, "just now") {
		t.Errorf("provider row must show freshness label ('ago' or 'just now'); output: %s", out)
	}
}

func TestV2ProvidersShowsOfflineNarration(t *testing.T) {
	view := UnifiedProvidersView{
		AI: AIProviderManagementView{
			Providers: []AIProviderManagementEntry{
				{
					Name:          "FailAI",
					Status:        "error",
					EnabledState:  "enabled",
					SecretState:   "present",
					HealthyState:  "unhealthy",
					LastErrorCode: "auth_failed",
				},
			},
		},
	}
	out := renderV2ProvidersPage(view, "tok")

	if !strings.Contains(out, "offline") {
		t.Errorf("error-state provider must show 'offline' narration; output: %s", out)
	}
}

func TestV2HealthShowsSituationLine(t *testing.T) {
	checks := []health.Check{
		{Name: "sqlite", Status: health.Green, Reason: "ok"},
	}
	detectors := []detect.Result{
		{Name: "crowdsec", Installed: true, Configured: true, Healthy: true},
	}
	pipeline := PipelineHealthView{}

	out := renderV2HealthPage(checks, detectors, pipeline)

	// Situation line: "All systems operational" when everything green
	if !strings.Contains(out, "All systems operational") {
		t.Errorf("health page must show situation line 'All systems operational'; output: %s", out)
	}
}

func TestV2HealthShowsSituationLineWithIssue(t *testing.T) {
	checks := []health.Check{
		{Name: "cloudflare", Status: health.Yellow, Reason: "token missing"},
	}
	detectors := []detect.Result{}
	pipeline := PipelineHealthView{}

	out := renderV2HealthPage(checks, detectors, pipeline)

	// Situation line with issues: "N issue(s) detected"
	if !strings.Contains(out, "issue") {
		t.Errorf("health page must show situation line with issue count; output: %s", out)
	}
}

func TestV2CloudflareShowsBoundarySummaryFirst(t *testing.T) {
	view := v2CloudflareView{
		Tab:             "boundary",
		APITokenPresent: true,
		ZoneIDPresent:   true,
	}
	out := renderV2Cloudflare(view)

	// Topbar title must be present
	topbar := strings.Index(out, `class="v2-topbar-title"`)
	if topbar == -1 {
		t.Fatal("cloudflare page missing topbar title element")
	}

	// Boundary posture block must appear before the HTML tab nav.
	// renderV2CFPosture always renders "Boundary converged" as its headline.
	posture := strings.Index(out, "Boundary converged")
	if posture == -1 {
		t.Fatal("cloudflare page missing posture block ('Boundary converged' not found)")
	}

	// Tab nav is the <div class="v2-cf-tabs"> element
	tabs := strings.Index(out, `<div class="v2-cf-tabs"`)
	if tabs == -1 {
		t.Fatal("cloudflare page missing tab nav element")
	}

	if posture > tabs {
		t.Errorf("cloudflare boundary summary must appear before tab nav (posture=%d, tabs=%d)", posture, tabs)
	}
}
