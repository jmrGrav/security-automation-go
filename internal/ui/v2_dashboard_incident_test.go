package ui

import (
	"strings"
	"testing"
)

func TestV2Dashboard_CurrentIncidentPanel(t *testing.T) {
	// with threats: panel appears
	view := makeV2DashboardView(97, 3, 3, 3)
	out := renderV2Dashboard(view)
	if !strings.Contains(out, "Current Incident") {
		t.Error("expected Current Incident panel when activeThreats>0")
	}

	// without threats: panel absent
	view2 := makeV2DashboardView(98, 3, 3, 0)
	out2 := renderV2Dashboard(view2)
	if strings.Contains(out2, "Current Incident") {
		t.Error("Current Incident panel should not appear when no active threats")
	}
}
