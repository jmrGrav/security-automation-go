package ui

import (
	"strings"
	"testing"
)

func TestRenderV2ActionSummary(t *testing.T) {
	out := renderV2ActionSummary("action", "Dashboard", "2 threats require attention")
	if !strings.Contains(out, "ACTION") {
		t.Error("expected ACTION label")
	}
	if !strings.Contains(out, "#f5a443") {
		t.Error("expected orange color for action level")
	}
	if !strings.Contains(out, "Dashboard") {
		t.Error("expected title in output")
	}
	if !strings.Contains(out, "2 threats require attention") {
		t.Error("expected summary in output")
	}
}

func TestRenderV2ActionSummary_Levels(t *testing.T) {
	tests := []struct {
		level string
		color string
		label string
	}{
		{"ok", "#4cc79a", "OK"},
		{"surveillance", "#9b8cff", "SURVEILLANCE"},
		{"action", "#f5a443", "ACTION NEEDED"},
		{"urgent", "#ef5f6b", "URGENT"},
	}
	for _, tt := range tests {
		out := renderV2ActionSummary(tt.level, "Test", "desc")
		if !strings.Contains(out, tt.color) {
			t.Errorf("level %q: expected color %s", tt.level, tt.color)
		}
		if !strings.Contains(out, tt.label) {
			t.Errorf("level %q: expected label %q", tt.level, tt.label)
		}
	}
}

func TestRenderV2PriorityBadge(t *testing.T) {
	tests := []struct{ level, want string }{
		{"no-action", "NO ACTION"},
		{"surveillance", "SURVEILLANCE"},
		{"action-needed", "ACTION NEEDED"},
		{"urgent", "URGENT"},
	}
	for _, tt := range tests {
		out := renderV2PriorityBadge(tt.level)
		if !strings.Contains(out, tt.want) {
			t.Errorf("badge %q missing %q", tt.level, tt.want)
		}
	}
}
