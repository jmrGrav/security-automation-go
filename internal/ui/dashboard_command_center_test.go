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

func TestDashboardHealthScoreDerivesHealthyState(t *testing.T) {
	score := dashboardHealthScore([]StatusItem{
		{Label: "Runtime", Level: "healthy", Detail: "UI mode active"},
		{Label: "Cloudflare", Level: "live", Detail: "mutations live"},
	}, EnvironmentWidget{Healthy: 2, Total: 2, Green: 2}, nil, true)

	if score.Score != 100 {
		t.Fatalf("Score: want 100, got %d", score.Score)
	}
	if score.Level != "healthy" {
		t.Fatalf("Level: want healthy, got %q", score.Level)
	}
	if len(score.Reasons) == 0 {
		t.Fatalf("expected health score reasons")
	}
}

func TestDashboardHealthScoreSurfacesDegradedReasons(t *testing.T) {
	score := dashboardHealthScore([]StatusItem{
		{Label: "Runtime", Level: "healthy", Detail: "UI mode active"},
		{Label: "Cloudflare", Level: "warning", Detail: "zone missing"},
		{Label: "HA / fencing", Level: "unavailable", Detail: "no HA subsystem configured"},
	}, EnvironmentWidget{Healthy: 1, Total: 3, Green: 1, Yellow: 1, Red: 1}, nil, false)

	if score.Score >= 100 {
		t.Fatalf("degraded inputs must reduce score, got %d", score.Score)
	}
	if score.Level == "healthy" {
		t.Fatalf("degraded inputs must not report healthy")
	}
	for _, want := range []string{"Cloudflare: zone missing", "HA / fencing: no HA subsystem configured", "Evidence store: unavailable"} {
		if !stringSliceContains(score.Reasons, want) {
			t.Fatalf("missing reason %q in %#v", want, score.Reasons)
		}
	}
}

func stringSliceContains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
