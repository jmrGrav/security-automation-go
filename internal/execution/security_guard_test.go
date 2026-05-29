package execution

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
)

type stubReputationChecker struct {
	result reputation.Result
	err    error
	calls  int
}

func (s *stubReputationChecker) Check(context.Context, netip.Addr) (reputation.Result, error) {
	s.calls++
	return s.result, s.err
}

func TestCloudflarePropagationGuard(t *testing.T) {
	now := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		op           MutationOperation
		checker      *stubReputationChecker
		failureMode  reputation.FailureMode
		wantAllowed  bool
		wantContains string
		wantCalls    int
	}{
		{
			name: "protected IP suppressed",
			op: MutationOperation{
				Type:         "create",
				ResourceType: "ip_access_rules",
				OperationID:  "op-1",
				Payload:      map[string]any{"configuration": map[string]any{"value": "127.0.0.1"}},
			},
			checker:      &stubReputationChecker{},
			wantAllowed:  false,
			wantContains: "protected target",
			wantCalls:    0,
		},
		{
			name: "low score suppressed",
			op: MutationOperation{
				Type:         "create",
				ResourceType: "ip_access_rules",
				OperationID:  "op-2",
				Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.8.8"}},
			},
			checker: &stubReputationChecker{result: reputation.Result{
				IP:        netip.MustParseAddr("8.8.8.8"),
				Provider:  "abuseipdb",
				Score:     12,
				CheckedAt: now,
			}},
			wantAllowed:  false,
			wantContains: "below threshold",
			wantCalls:    1,
		},
		{
			name: "high score allowed",
			op: MutationOperation{
				Type:         "create",
				ResourceType: "ip_access_rules",
				OperationID:  "op-3",
				Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.8.8"}},
			},
			checker: &stubReputationChecker{result: reputation.Result{
				IP:        netip.MustParseAddr("8.8.8.8"),
				Provider:  "abuseipdb",
				Score:     90,
				CheckedAt: now,
			}},
			wantAllowed: true,
			wantCalls:   1,
		},
		{
			name: "cannot derive IP suppressed for ruleset block",
			op: MutationOperation{
				Type:         "update",
				ResourceType: "ruleset_rules",
				OperationID:  "op-4",
				Payload:      map[string]any{"action": "block"},
			},
			checker:      &stubReputationChecker{},
			wantAllowed:  false,
			wantContains: "cannot derive target ip",
			wantCalls:    0,
		},
		{
			name: "reputation timeout suppressed by default",
			op: MutationOperation{
				Type:         "create",
				ResourceType: "ip_access_rules",
				OperationID:  "op-5",
				Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.4.4"}},
			},
			checker:      &stubReputationChecker{err: errors.New("timeout")},
			wantAllowed:  false,
			wantContains: "reputation unavailable",
			wantCalls:    1,
		},
		{
			name: "reputation timeout allowed in allow mode",
			op: MutationOperation{
				Type:         "create",
				ResourceType: "ip_access_rules",
				OperationID:  "op-6",
				Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.4.4"}},
			},
			checker:     &stubReputationChecker{err: errors.New("timeout")},
			failureMode: reputation.FailureModeAllow,
			wantAllowed: true,
			wantCalls:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := NewCloudflarePropagationGuard(tt.checker, trust.DefaultRegistry())
			if tt.failureMode != "" {
				guard.SetFailureMode(tt.failureMode)
			}
			decision, err := guard.EvaluateMutation(context.Background(), tt.op)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Allowed != tt.wantAllowed {
				t.Fatalf("allowed mismatch: got=%v reason=%s", decision.Allowed, decision.Reason)
			}
			if tt.wantContains != "" && !contains(decision.Reason, tt.wantContains) {
				t.Fatalf("expected reason to contain %q, got %q", tt.wantContains, decision.Reason)
			}
			if tt.checker.calls != tt.wantCalls {
				t.Fatalf("checker calls mismatch: got=%d want=%d", tt.checker.calls, tt.wantCalls)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && (stringIndex(s, sub) >= 0)))
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
