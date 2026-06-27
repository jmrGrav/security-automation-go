package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/audit"
)

func TestRenderV2TimelineHistogramClickable(t *testing.T) {
	now := time.Now()
	events := []audit.TimelineEvent{
		{
			Timestamp:   now.Add(-1 * time.Hour).Format(time.RFC3339),
			ActorSource: "test",
			Action:      "burst_malicious",
			Target:      "1.2.3.4",
			Severity:    "error",
		},
		{
			Timestamp:   now.Add(-2 * time.Hour).Format(time.RFC3339),
			ActorSource: "test",
			Action:      "flag",
			Target:      "5.6.7.8",
			Severity:    "warning",
		},
	}

	out := renderV2TimelineHistogram(events)

	if !strings.Contains(out, `href="/v2/timeline?from=`) {
		t.Errorf("histogram bars should contain href with from= param, got:\n%s", out[:min(len(out), 500)])
	}
	if !strings.Contains(out, `&amp;to=`) {
		t.Errorf("histogram bars should contain to= param in href, got:\n%s", out[:min(len(out), 500)])
	}
}

func TestRenderV2TimelineRowWhyItMatters(t *testing.T) {
	tests := []struct {
		action  string
		want    string
		wantNot string
	}{
		{
			action: "burst_malicious",
			want:   "High confidence threat",
		},
		{
			action: "ban_ip",
			want:   "High confidence threat",
		},
		{
			action: "burst_suspicious",
			want:   "Borderline signal",
		},
		{
			action: "flag_ip",
			want:   "Borderline signal",
		},
		{
			action: "whitelist_ip",
			want:   "Operator-trusted source",
		},
		{
			action: "allow_ip",
			want:   "Operator-trusted source",
		},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			ev := audit.TimelineEvent{
				Timestamp:   time.Now().Format(time.RFC3339),
				ActorSource: "test",
				Action:      tc.action,
				Target:      "1.2.3.4",
			}
			out := renderV2TimelineRow(ev)
			if !strings.Contains(out, tc.want) {
				t.Errorf("renderV2TimelineRow with action=%q: expected %q in output\ngot:\n%s", tc.action, tc.want, out)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
