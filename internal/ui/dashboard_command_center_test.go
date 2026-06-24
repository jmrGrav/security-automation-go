package ui

import "testing"

func TestCommandCenterViewDefaultsAreSafe(t *testing.T) {
	view := DashboardCommandCenterView{}

	if view.Health.Score != 0 {
		t.Fatalf("zero-value health score must be 0, got %d", view.Health.Score)
	}
	if view.Health.Level != "" {
		t.Fatalf("zero-value health level should be empty until derived, got %q", view.Health.Level)
	}
	if len(view.Activity.Items) != 0 {
		t.Fatalf("zero-value activity feed should be empty")
	}
	if view.Search.Action != "" {
		t.Fatalf("zero-value search action should be empty until rendered")
	}
}
