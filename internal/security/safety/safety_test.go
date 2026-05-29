package safety

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/risk"
	"github.com/jm/security-automation-go/internal/security/trust"
)

type stubChecker struct {
	result reputation.Result
	err    error
}

func (s stubChecker) Check(context.Context, netip.Addr) (reputation.Result, error) {
	return s.result, s.err
}

func TestFaviconOnlyObserve(t *testing.T) {
	a := risk.Assess(risk.Event{URIs: []string{"/favicon.ico"}, Hits: 1, Timestamp: time.Now().UTC()})
	if a.Decision != risk.DecisionObserveOnly || a.AbuseType != risk.CategoryBenignBootstrap {
		t.Fatalf("expected benign bootstrap observe-only, got %+v", a)
	}
}

func TestRobotsOnlyObserve(t *testing.T) {
	a := risk.Assess(risk.Event{URIs: []string{"/robots.txt"}, Hits: 1, Timestamp: time.Now().UTC()})
	if a.Decision != risk.DecisionObserveOnly {
		t.Fatalf("expected observe-only, got %+v", a)
	}
}

func TestBaselineAssetsOnlyObserve(t *testing.T) {
	a := risk.Assess(risk.Event{URIs: []string{"/", "/assets/app.js", "/favicon.ico"}, Hits: 3, Timestamp: time.Now().UTC()})
	if a.AbuseType != risk.CategoryBenignBootstrap || a.Decision != risk.DecisionObserveOnly {
		t.Fatalf("expected benign bootstrap, got %+v", a)
	}
}

func TestWordPressProbeElevates(t *testing.T) {
	a := risk.Assess(risk.Event{URIs: []string{"/wp-login.php"}, Hits: 5, Timestamp: time.Now().UTC()})
	if a.AbuseType != risk.CategoryWordPressProbe || a.Score < 5 {
		t.Fatalf("expected wordpress probe escalation, got %+v", a)
	}
}

func TestTraversalHighRisk(t *testing.T) {
	a := risk.Assess(risk.Event{URIs: []string{"/../../etc/passwd"}, Hits: 1, Timestamp: time.Now().UTC()})
	if a.Score < 10 {
		t.Fatalf("expected high-risk traversal, got %+v", a)
	}
}

func TestLowAbuseIPDBScoreSuppressesPropagation(t *testing.T) {
	guard := execution.NewCloudflarePropagationGuard(stubChecker{
		result: reputation.Result{
			IP:        netip.MustParseAddr("8.8.8.8"),
			Provider:  "abuseipdb",
			Score:     12,
			CheckedAt: time.Now().UTC(),
		},
	}, trust.DefaultRegistry())
	decision, err := guard.EvaluateMutation(context.Background(), execution.MutationOperation{
		Type:         "create",
		ResourceType: "ip_access_rules",
		OperationID:  "op-1",
		Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.8.8"}},
	})
	if err != nil {
		t.Fatalf("evaluate mutation: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected low-score suppression")
	}
}

func TestHighAbuseIPDBScoreAllowsPropagation(t *testing.T) {
	guard := execution.NewCloudflarePropagationGuard(stubChecker{
		result: reputation.Result{
			IP:        netip.MustParseAddr("8.8.8.8"),
			Provider:  "abuseipdb",
			Score:     90,
			CheckedAt: time.Now().UTC(),
		},
	}, trust.DefaultRegistry())
	decision, err := guard.EvaluateMutation(context.Background(), execution.MutationOperation{
		Type:         "create",
		ResourceType: "ip_access_rules",
		OperationID:  "op-2",
		Payload:      map[string]any{"configuration": map[string]any{"value": "8.8.8.8"}},
	})
	if err != nil {
		t.Fatalf("evaluate mutation: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected propagation allow, got %+v", decision)
	}
}

func TestProtectedServiceNoPropagation(t *testing.T) {
	guard := execution.NewCloudflarePropagationGuard(stubChecker{
		result: reputation.Result{
			IP:        netip.MustParseAddr("127.0.0.1"),
			Provider:  "abuseipdb",
			Score:     100,
			CheckedAt: time.Now().UTC(),
		},
	}, trust.DefaultRegistry())
	decision, err := guard.EvaluateMutation(context.Background(), execution.MutationOperation{
		Type:         "create",
		ResourceType: "ip_access_rules",
		OperationID:  "op-3",
		Payload:      map[string]any{"configuration": map[string]any{"value": "127.0.0.1"}},
	})
	if err != nil {
		t.Fatalf("evaluate mutation: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected localhost propagation to be denied")
	}
}

func TestCloudflareReplayUsesCanonicalComment(t *testing.T) {
	ev, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "8.8.8.8",
		URI:       "/xmlrpc.php",
		Action:    "block",
		RuleID:    "cf-1",
		RuleName:  "WordPress probe",
		Source:    "cloudflare_waf",
		Timestamp: time.Now().UTC(),
		UserAgent: "Mozilla/5.0",
		Hits:      9,
		WindowSec: 300,
		Hostname:  "arleo.eu",
	})
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	cls := classifier.Classify(ev)
	comment := abuseformat.Build(abuseformat.Input{
		Source:     abuseformat.SourceCloudflareWAF,
		Hits:       ev.Hits,
		WindowSec:  ev.WindowSec,
		Action:     ev.Action,
		AbuseType:  cls.AbuseType,
		Categories: cls.Categories,
		RuleID:     ev.RuleID,
		URIs:       []string{ev.URI},
		Confidence: cls.Confidence,
	})
	if !strings.Contains(comment, "Cloudflare WAF: 9 hits in 300s") {
		t.Fatalf("unexpected comment: %s", comment)
	}
}

func TestCrowdSecCanonicalComment(t *testing.T) {
	comment := abuseformat.Build(abuseformat.Input{
		Source:     abuseformat.SourceCrowdSecWAF,
		Hits:       9,
		WindowSec:  300,
		Action:     "block",
		AbuseType:  risk.CategoryWordPressProbe,
		Categories: []string{"Web App Attack", "Bad Web Bot"},
		RuleID:     "crowdsec-1",
		URIs:       []string{"/wp-login.php", "/xmlrpc.php"},
		Confidence: 0.91,
	})
	if !strings.Contains(comment, "CrowdSec WAF: 9 hits in 300s") {
		t.Fatalf("unexpected canonical comment: %s", comment)
	}
}
