package ui

import (
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

func TestRenderV2HealthPage_AllGreen(t *testing.T) {
	checks := []health.Check{
		{Name: "cloudflare", Status: health.Green, Reason: "ok"},
		{Name: "sqlite", Status: health.Green, Reason: "ok"},
	}
	detectors := []detect.Result{
		{Name: "crowdsec", Installed: true, Configured: true, Healthy: true},
		{Name: "openresty", Installed: true, Configured: true, Healthy: false, Details: map[string]string{"events_exist": "missing"}},
	}
	pipeline := PipelineHealthView{
		Rows: []PipelineHealthRow{
			{Source: "Cloudflare WAF", Classified: 100, Suppressed: 90, Pending: 5, Reported: 5, Freshness: "just now"},
		},
		Total: PipelineHealthRow{
			Source:     "Total",
			Classified: 100,
			Suppressed: 90,
			Pending:    5,
			Reported:   5,
		},
	}

	out := renderV2HealthPage(checks, detectors, pipeline)

	mustContain := []string{
		"System Health",
		"All systems operational",
		"2 / 2 passing",
		"Event pipeline",
		"Classified",
		"Suppressed",
		"Reported",
		"By source",
		"Subsystems",
		"Health checks",
		"/v2/health",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("expected output to contain %q", s)
		}
	}
}

func TestRenderV2HealthPage_WithAdvisory(t *testing.T) {
	checks := []health.Check{
		{Name: "openresty", Status: health.Yellow, Reason: "events file missing", Remediation: "check nginx log"},
		{Name: "sqlite", Status: health.Green, Reason: "ok"},
	}
	detectors := []detect.Result{
		{Name: "openresty", Installed: true, Configured: true, Healthy: false},
	}
	pipeline := PipelineHealthView{}

	out := renderV2HealthPage(checks, detectors, pipeline)

	if strings.Contains(out, "All systems operational") {
		t.Error("should not show 'All systems operational' when issues exist")
	}
	if !strings.Contains(out, "advisory") {
		t.Error("expected advisory banner")
	}
	if !strings.Contains(out, "events file missing") {
		t.Error("expected advisory reason in output")
	}
}

func TestFmtCount(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{49984, "49,984"},
		{1000000, "1,000,000"},
	}
	for _, c := range cases {
		got := fmtCount(c.in)
		if got != c.want {
			t.Errorf("fmtCount(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestV2ShellUsesWorkflowNavigationAndDarkOnly(t *testing.T) {
	out := v2Page("Test", "/v2/timeline", `<h1>content</h1>`)

	for _, want := range []string{
		`data-theme="operations-dark"`,
		"Investigate",
		"Infrastructure",
		"Operations",
		"/v2/timeline",
		"/v2/notes",
		"/v2/audit",
		"Sign out",
		"Search",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v2 shell missing %q: %s", want, out)
		}
	}
	for _, forbidden := range []string{"Comfort light", `data-theme-toggle="true"`, "Watchlist", "Classic UI"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("v2 shell should omit %q: %s", forbidden, out)
		}
	}
}
