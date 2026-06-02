package engine

import "testing"

func TestIsTransitionAllowedUnknownState(t *testing.T) {
	sm := NewStateMachine(nil, nil)
	if sm.isTransitionAllowed("mystery", "idle") {
		t.Fatal("unknown from-state must be rejected")
	}
}
