package ui

import (
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/security/audit"
)

// ---------------------------------------------------------------------------
// Task 1: Situation banner tests
// ---------------------------------------------------------------------------

func makeV2DashboardView(healthScore, healthyCount, totalStatuses, activeThreats int) DashboardConsoleView {
	statuses := make([]StatusItem, totalStatuses)
	for i := range statuses {
		if i < healthyCount {
			statuses[i] = StatusItem{Label: "svc", Level: "healthy", Detail: "ok"}
		} else {
			statuses[i] = StatusItem{Label: "svc", Level: "error", Detail: "down"}
		}
	}

	countries := make([]DashboardThreatCountryView, activeThreats)
	for i := range countries {
		countries[i] = DashboardThreatCountryView{Country: "CN", Count: 1, Level: "info"}
	}

	return DashboardConsoleView{
		Statuses:     statuses,
		HealthyCount: healthyCount,
		CommandCenter: DashboardCommandCenterView{
			Health: DashboardHealthScoreView{
				Score: healthScore,
				Level: "healthy",
			},
			Threat: DashboardThreatView{
				Countries: countries,
			},
		},
	}
}

func TestV2DashboardBanner_Healthy(t *testing.T) {
	view := makeV2DashboardView(98, 3, 3, 0)
	out := renderV2Dashboard(view)
	if !strings.Contains(out, "HEALTHY") {
		t.Errorf("expected HEALTHY banner when score>=95 and no active threats; got output missing 'HEALTHY'")
	}
	if !strings.Contains(out, "no active threats") {
		t.Errorf("expected 'no active threats' in HEALTHY banner")
	}
	if !strings.Contains(out, "#4cc79a") {
		t.Errorf("expected green color #4cc79a in HEALTHY banner")
	}
}

func TestV2DashboardBanner_Active(t *testing.T) {
	view := makeV2DashboardView(97, 3, 3, 3)
	out := renderV2Dashboard(view)
	if !strings.Contains(out, "ACTIVE") {
		t.Errorf("expected ACTIVE banner when activeThreats>0; got output missing 'ACTIVE'")
	}
	if !strings.Contains(out, "3 origins detected") {
		t.Errorf("expected '3 origins detected' in ACTIVE banner")
	}
	if !strings.Contains(out, "#f5a443") {
		t.Errorf("expected orange color #f5a443 in ACTIVE banner")
	}
}

func TestV2DashboardBanner_Degraded(t *testing.T) {
	view := makeV2DashboardView(60, 1, 4, 0)
	out := renderV2Dashboard(view)
	if !strings.Contains(out, "DEGRADED") {
		t.Errorf("expected DEGRADED banner when score<70; got output missing 'DEGRADED'")
	}
	if !strings.Contains(out, "components failing") {
		t.Errorf("expected 'components failing' in DEGRADED banner")
	}
	if !strings.Contains(out, "#ef5f6b") {
		t.Errorf("expected red color #ef5f6b in DEGRADED banner")
	}
}

func TestV2DashboardBanner_Monitoring(t *testing.T) {
	// Score 70–94, no active threats → MONITORING
	view := makeV2DashboardView(85, 3, 3, 0)
	out := renderV2Dashboard(view)
	if !strings.Contains(out, "MONITORING") {
		t.Errorf("expected MONITORING banner for score 70-94 with no threats; got output missing 'MONITORING'")
	}
	if !strings.Contains(out, "systems nominal") {
		t.Errorf("expected 'systems nominal' in MONITORING banner")
	}
	if !strings.Contains(out, "#9b8cff") {
		t.Errorf("expected purple color #9b8cff in MONITORING banner")
	}
}

// Active takes precedence over Healthy score when threats exist.
func TestV2DashboardBanner_ActiveTakesPrecedenceOverHealthy(t *testing.T) {
	view := makeV2DashboardView(99, 5, 5, 5)
	out := renderV2Dashboard(view)
	if !strings.Contains(out, "ACTIVE") {
		t.Errorf("expected ACTIVE banner to take precedence when score>=95 but threats exist")
	}
	if strings.Contains(out, "HEALTHY") {
		t.Errorf("HEALTHY banner should not appear when there are active threats")
	}
}

// ---------------------------------------------------------------------------
// Task 2: Compact timeline row tests
// ---------------------------------------------------------------------------

func TestV2TimelineRow_PrimaryPillsVisible(t *testing.T) {
	ev := audit.TimelineEvent{
		Timestamp:     "2026-06-27T10:00:00",
		ActorSource:   "nginx",
		Action:        "ban",
		Target:        "1.2.3.4",
		Result:        "blocked",
		Summary:       "Repeated probe",
		CorrelationID: "corr-abc123",
		EvidenceID:    "ev-xyz",
	}
	row := renderV2TimelineRow(ev)

	// Primary pills must be visible (outside <details>)
	detailsIdx := strings.Index(row, "<details>")
	if detailsIdx < 0 {
		t.Fatalf("expected <details> element in timeline row, got: %s", row)
	}
	primaryPart := row[:detailsIdx]

	if !strings.Contains(primaryPart, "action:") {
		t.Errorf("action pill should be visible before <details>; primary part: %s", primaryPart)
	}
	if !strings.Contains(primaryPart, "ip:") {
		t.Errorf("ip pill should be visible before <details>; primary part: %s", primaryPart)
	}
	if !strings.Contains(primaryPart, "1.2.3.4") {
		t.Errorf("target IP should be visible before <details>; primary part: %s", primaryPart)
	}
}

func TestV2TimelineRow_SecondaryPillsInDetails(t *testing.T) {
	ev := audit.TimelineEvent{
		Timestamp:     "2026-06-27T10:00:00",
		ActorSource:   "nginx",
		Action:        "ban",
		Target:        "1.2.3.4",
		Result:        "blocked",
		Summary:       "Repeated probe",
		CorrelationID: "corr-abc123",
		EvidenceID:    "ev-xyz",
	}
	row := renderV2TimelineRow(ev)

	detailsIdx := strings.Index(row, "<details>")
	if detailsIdx < 0 {
		t.Fatalf("expected <details> element in timeline row, got: %s", row)
	}
	secondaryPart := row[detailsIdx:]

	// Secondary pills must be inside <details>
	for _, want := range []string{"result:", "Repeated probe", "corr:", "ev:"} {
		if !strings.Contains(secondaryPart, want) {
			t.Errorf("expected %q to be inside <details>, got secondary part: %s", want, secondaryPart)
		}
	}

	// Secondary pills must NOT appear before <details>
	primaryPart := row[:detailsIdx]
	for _, notWant := range []string{"result:", "Repeated probe", "corr:", "ev:"} {
		if strings.Contains(primaryPart, notWant) {
			t.Errorf("%q should be inside <details>, not visible by default; primary part: %s", notWant, primaryPart)
		}
	}
}

func TestV2TimelineRow_NoDetailsWhenNoSecondaryContent(t *testing.T) {
	ev := audit.TimelineEvent{
		Timestamp:   "2026-06-27T10:00:00",
		ActorSource: "ui",
		Action:      "login",
	}
	row := renderV2TimelineRow(ev)
	if strings.Contains(row, "<details>") {
		t.Errorf("row with no secondary content should not render <details>: %s", row)
	}
}

func TestV2TimelineRow_ActionLinksInDetails(t *testing.T) {
	ev := audit.TimelineEvent{
		Timestamp:   "2026-06-27T10:00:00",
		ActorSource: "nginx",
		Action:      "ban",
		Target:      "5.6.7.8",
	}
	row := renderV2TimelineRow(ev)

	detailsIdx := strings.Index(row, "<details>")
	if detailsIdx < 0 {
		t.Fatalf("expected <details> element in timeline row, got: %s", row)
	}
	secondaryPart := row[detailsIdx:]

	for _, want := range []string{
		"/v2/incident?ip=5.6.7.8",
		"/v2/investigate?q=5.6.7.8",
		"/v2/timeline?q=5.6.7.8",
	} {
		if !strings.Contains(secondaryPart, want) {
			t.Errorf("expected action link %q inside <details>; secondary part: %s", want, secondaryPart)
		}
	}
}
