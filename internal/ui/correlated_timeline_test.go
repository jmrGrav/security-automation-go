package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
)

func TestGroupTimelineByIP_BasicGrouping(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.TimelineEvent{
		{Target: "1.2.3.4", ActorSource: "crowdsec", Timestamp: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)},
		{Target: "1.2.3.4", ActorSource: "cloudflare", Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339Nano)},
		{Target: "5.6.7.8", ActorSource: "crowdsec", Timestamp: now.Format(time.RFC3339Nano)},
	}
	groups := groupTimelineByIP(events, "")
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	// Most recent first: 5.6.7.8 (now), then 1.2.3.4.
	if groups[0].Key != "5.6.7.8" {
		t.Errorf("first group should be 5.6.7.8, got %s", groups[0].Key)
	}
	if groups[1].EventCount != 2 {
		t.Errorf("1.2.3.4 group should have 2 events, got %d", groups[1].EventCount)
	}
}

func TestGroupTimelineByIP_FilterIP(t *testing.T) {
	now := time.Now().UTC()
	events := []audit.TimelineEvent{
		{Target: "1.2.3.4", Timestamp: now.Format(time.RFC3339Nano)},
		{Target: "9.9.9.9", Timestamp: now.Format(time.RFC3339Nano)},
	}
	groups := groupTimelineByIP(events, "1.2.3.4")
	if len(groups) != 1 || groups[0].Key != "1.2.3.4" {
		t.Fatalf("filter should return 1 group for 1.2.3.4, got %d groups", len(groups))
	}
}

func TestGroupTimelineByIP_EmptyTarget(t *testing.T) {
	events := []audit.TimelineEvent{
		{Target: "", ActorSource: "test", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)},
	}
	groups := groupTimelineByIP(events, "")
	if len(groups) != 0 {
		t.Error("events with empty Target should be excluded from grouping")
	}
}

func TestCorrelatedTimelinePage_Renders(t *testing.T) {
	now := time.Now().UTC()
	view := CorrelatedTimelineView{
		Groups: []CorrelatedGroup{
			{
				Key:        "1.2.3.4",
				EventCount: 3,
				Sources:    []string{"crowdsec"},
				FirstSeen:  now.Add(-time.Hour),
				LastSeen:   now,
			},
		},
		Total: 1,
	}
	var buf strings.Builder
	if err := CorrelatedTimelinePage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"1.2.3.4", "crowdsec", "3 events", "Focus Incident"} {
		if !strings.Contains(body, want) {
			t.Errorf("correlated timeline page missing %q", want)
		}
	}
}
