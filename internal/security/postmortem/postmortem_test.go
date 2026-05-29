package postmortem

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/risk"
	"github.com/jm/security-automation-go/internal/security/trust"
)

type fixedChecker struct {
	result reputation.Result
	err    error
}

func (f fixedChecker) Check(context.Context, netip.Addr) (reputation.Result, error) {
	return f.result, f.err
}

func TestPostmortemRegressionMatrix(t *testing.T) {
	timestamp := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name            string
		event           risk.Event
		wantAbuse       string
		wantDecision    string
		wantPropagation bool
		reputationScore int
	}{
		{
			name:            "sonarr legitimate api route",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/api/v3/calendar?start=2026-05-27"}, UserAgent: "Sonarr/4.0", Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignProbe,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "health check",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/healthz"}, UserAgent: "UptimeRobot", Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignProbe,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "favicon only",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/favicon.ico"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignBootstrap,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "robots only",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/robots.txt"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignBootstrap,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "benign bootstrap assets",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/", "/assets/app.js", "/favicon.ico"}, Hits: 3, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignBootstrap,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "absent ua benign request",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/api/status"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignProbe,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "isolated 404 benign request",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/missing-page"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryBenignProbe,
			wantDecision:    risk.DecisionObserveOnly,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "wp-login repeated",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/wp-login.php"}, Hits: 5, Timestamp: timestamp},
			wantAbuse:       risk.CategoryWordPressProbe,
			wantDecision:    risk.DecisionSoftMitigation,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "xmlrpc burst",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/xmlrpc.php"}, Hits: 10, Timestamp: timestamp},
			wantAbuse:       risk.CategoryWordPressProbe,
			wantDecision:    risk.DecisionLocalBlock,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "confirmed abuse burst",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/search?q=union+select+1"}, Hits: 10, Timestamp: timestamp},
			wantAbuse:       risk.CategoryConfirmedAbuse,
			wantDecision:    risk.DecisionPropagableBan,
			wantPropagation: true,
			reputationScore: 95,
		},
		{
			name:            "env probing",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/.env"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryExploitAttempt,
			wantDecision:    risk.DecisionLocalBlock,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "traversal payload",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/../../etc/passwd"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryExploitAttempt,
			wantDecision:    risk.DecisionLocalBlock,
			wantPropagation: false,
			reputationScore: 12,
		},
		{
			name:            "sqli payload",
			event:           risk.Event{IP: "8.8.8.8", URIs: []string{"/search?q=union+select+1"}, Hits: 1, Timestamp: timestamp},
			wantAbuse:       risk.CategoryExploitAttempt,
			wantDecision:    risk.DecisionLocalBlock,
			wantPropagation: false,
			reputationScore: 12,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessment := risk.Assess(tc.event)
			if assessment.AbuseType != tc.wantAbuse {
				t.Fatalf("unexpected abuse type: want %s got %s", tc.wantAbuse, assessment.AbuseType)
			}
			if assessment.Decision != tc.wantDecision {
				t.Fatalf("unexpected decision: want %s got %s", tc.wantDecision, assessment.Decision)
			}

			cls := classifier.Classify(classifier.Event{
				IP:        tc.event.IP,
				URI:       tc.event.URIs[0],
				UserAgent: tc.event.UserAgent,
				Action:    "block",
				RuleID:    "test-rule",
				Source:    "postmortem_replay",
				Timestamp: tc.event.Timestamp,
				Hits:      tc.event.Hits,
				WindowSec: tc.event.WindowSeconds,
			})
			if cls.AbuseType != assessment.AbuseType {
				t.Fatalf("classifier mismatch: want %s got %s", assessment.AbuseType, cls.AbuseType)
			}

			guard := execution.NewCloudflarePropagationGuard(fixedChecker{
				result: reputation.Result{
					IP:        netip.MustParseAddr(tc.event.IP),
					Provider:  "abuseipdb",
					Score:     tc.reputationScore,
					CheckedAt: timestamp,
				},
			}, trust.DefaultRegistry())
			decision, err := guard.EvaluateMutation(context.Background(), execution.MutationOperation{
				Type:         "create",
				ResourceType: "ip_access_rules",
				OperationID:  "op-" + tc.name,
				Payload:      map[string]any{"configuration": map[string]any{"value": tc.event.IP}},
			})
			if err != nil {
				t.Fatalf("guard evaluation failed: %v", err)
			}
			if decision.Allowed != tc.wantPropagation {
				t.Fatalf("unexpected propagation decision: want %v got %+v", tc.wantPropagation, decision)
			}
		})
	}
}
