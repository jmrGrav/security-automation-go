package execution

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/blastradius"
	"github.com/jm/security-automation-go/internal/security/confidence"
	"github.com/jm/security-automation-go/internal/security/fp_memory"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/snapshot"
)

type SecurityGuard interface {
	EvaluateMutation(ctx context.Context, op MutationOperation) (GuardDecision, error)
}

type GuardDecision struct {
	Allowed          bool
	Reason           string
	TargetIP         string
	Source           string
	RuleID           string
	RiskScore        int
	Confidence       float64
	EnforcementStage string
	Reputation       *reputation.Result
	Metadata         map[string]any
}

type CloudflarePropagationGuard struct {
	checker     reputation.Checker
	trust       *trust.Registry
	limits      blastradius.Limits
	policy      confidence.Policy
	threshold   int
	failureMode reputation.FailureMode
	memory      *fp_memory.Store
}

func NewCloudflarePropagationGuard(checker reputation.Checker, registry *trust.Registry) *CloudflarePropagationGuard {
	return &CloudflarePropagationGuard{
		checker:     checker,
		trust:       registry,
		limits:      blastradius.DefaultLimits(),
		policy:      confidence.DefaultPolicy(),
		threshold:   70,
		failureMode: reputation.FailureModeSuppress,
	}
}

func (g *CloudflarePropagationGuard) SetFalsePositiveMemory(memory *fp_memory.Store) {
	g.memory = memory
}

func (g *CloudflarePropagationGuard) SetFailureMode(mode reputation.FailureMode) {
	if mode != "" {
		g.failureMode = mode
	}
}

func (g *CloudflarePropagationGuard) SetThreshold(threshold int) {
	if threshold > 0 {
		g.threshold = threshold
	}
}

func (g *CloudflarePropagationGuard) EvaluateMutation(ctx context.Context, op MutationOperation) (GuardDecision, error) {
	decision := GuardDecision{
		Allowed:          true,
		Source:           extractSource(op),
		RuleID:           extractRuleID(op),
		EnforcementStage: "propagable_ban",
		Metadata:         map[string]any{"resource_type": op.ResourceType, "operation_type": string(op.Type)},
	}

	if !isProtectedCloudflareMutation(op) {
		return decision, nil
	}

	targetIP := extractTargetIP(op)
	decision.TargetIP = targetIP
	if targetIP == "" && requiresTargetedDecision(op) {
		return g.suppressed(decision, "cannot derive target ip"), nil
	}
	if targetIP == "" {
		return decision, nil
	}

	if g.checker == nil {
		return GuardDecision{}, apperr.New("execution.CloudflarePropagationGuard.EvaluateMutation", "reputation checker is required")
	}
	metrics.AbuseIPDBPreBanChecksTotal.Inc()

	addr, err := netip.ParseAddr(targetIP)
	if err != nil {
		metrics.AbuseIPDBPreBanSuppressedTotal.Inc()
		return g.suppressed(decision, "invalid target ip"), nil
	}

	if g.trust != nil {
		if matches := g.trust.MatchIP(targetIP); len(matches) > 0 {
			metrics.AbuseIPDBPreBanSuppressedTotal.Inc()
			metrics.AbuseIPDBPreBanFalsePositiveSuspectedTotal.Inc()
			return g.suppressed(decision, "protected target"), nil
		}
	}

	rep, err := g.checker.Check(ctx, addr)
	if err != nil {
		metrics.AbuseIPDBPreBanAPIErrorsTotal.Inc()
		if g.failureMode == reputation.FailureModeAllow {
			metrics.AbuseIPDBPreBanAllowedTotal.Inc()
			decision.Metadata["reputation_unavailable"] = true
			return decision, nil
		}
		metrics.AbuseIPDBPreBanSuppressedTotal.Inc()
		return g.suppressed(decision, "reputation unavailable"), nil
	}
	metrics.AbuseIPDBPreBanScore.Observe(float64(rep.Score))
	decision.Reputation = &rep
	decision.Metadata["reputation_provider"] = rep.Provider
	decision.Metadata["reputation_score"] = rep.Score
	decision.Metadata["cache_hit"] = rep.CacheHit

	if rep.Score < g.threshold {
		metrics.AbuseIPDBPreBanSuppressedTotal.Inc()
		metrics.AbuseIPDBPreBanFalsePositiveSuspectedTotal.Inc()
		if g.memory != nil {
			g.memory.Remember("preban:"+targetIP+":"+decision.RuleID, "abuseipdb_preban", decision.Source, true, time.Now().UTC())
		}
		return g.suppressed(decision, fmt.Sprintf("abuse score below threshold: %d < %d", rep.Score, g.threshold)), nil
	}
	metrics.AbuseIPDBPreBanAllowedTotal.Inc()

	conf := confidence.Score([]confidence.Evidence{
		{Source: decision.Source, Category: "local_detection", Weight: 0.60, Reference: decision.RuleID},
		{Source: rep.Provider, Category: "reputation_check", Weight: float64(rep.Score) / 100.0, Reference: rep.Provider + "/check", ReplayToken: targetIP},
	}, "preban", g.policy)
	decision.Confidence = conf.Score
	decision.RiskScore = rep.Score
	decision.Metadata["replay_evidence"] = conf.ReplayEvidence

	verdict := blastradius.Evaluate([]blastradius.ProposedAction{{
		ScopeID:         "default",
		TargetIP:        targetIP,
		Action:          "cloudflare_ban",
		Count:           1,
		ConfidenceScore: conf.Score,
	}}, g.trust, g.limits)
	if !verdict.Allowed {
		return g.suppressed(decision, verdict.Reason), nil
	}

	return decision, nil
}

func (g *CloudflarePropagationGuard) suppressed(decision GuardDecision, reason string) GuardDecision {
	decision.Allowed = false
	decision.Reason = reason
	decision.EnforcementStage = "suppressed"
	if decision.Metadata == nil {
		decision.Metadata = map[string]any{}
	}
	decision.Metadata["suppression_reason"] = reason
	return decision
}

func extractTargetIP(op MutationOperation) string {
	payload, ok := op.Payload.(map[string]any)
	if ok {
		if cfg, ok := payload["configuration"].(map[string]any); ok {
			if value, ok := cfg["value"].(string); ok {
				return value
			}
		}
		if value, ok := payload["ip"].(string); ok {
			return value
		}
		if expression, ok := payload["expression"].(string); ok {
			if ip := extractIPFromString(expression); ip != "" {
				return ip
			}
		}
		if items, ok := payload["items"].([]any); ok {
			for _, item := range items {
				if m, ok := item.(map[string]any); ok {
					if ip, ok := m["ip"].(string); ok {
						return ip
					}
					if expr, ok := m["expression"].(string); ok {
						if ip := extractIPFromString(expr); ip != "" {
							return ip
						}
					}
				}
			}
		}
	}
	parts := strings.Split(op.StableIdentityKey, ":")
	if len(parts) >= 4 && parts[0] == "ip" {
		return parts[2]
	}
	if len(parts) >= 2 && parts[0] == "list_item" {
		return parts[1]
	}
	if len(parts) >= 2 && parts[0] == "rule" {
		return extractIPFromString(op.StableIdentityKey)
	}
	return ""
}

func extractSource(op MutationOperation) string {
	payload, ok := op.Payload.(map[string]any)
	if ok {
		if notes, ok := payload["notes"].(string); ok && notes != "" {
			return notes
		}
	}
	return "local"
}

func extractRuleID(op MutationOperation) string {
	return fmt.Sprintf("%s:%s", op.ResourceType, op.OperationID)
}

func isProtectedCloudflareMutation(op MutationOperation) bool {
	if op.Type != "create" && op.Type != "update" {
		return false
	}
	switch op.ResourceType {
	case string(snapshot.ResourceIPAccessRules), string(snapshot.ResourceListItems), string(snapshot.ResourceRulesetRules), string(snapshot.ResourceRulesets):
		return true
	default:
		return false
	}
}

func requiresTargetedDecision(op MutationOperation) bool {
	if op.ResourceType == string(snapshot.ResourceIPAccessRules) || op.ResourceType == string(snapshot.ResourceListItems) {
		return true
	}
	payload, ok := op.Payload.(map[string]any)
	if !ok {
		return false
	}
	action, _ := payload["action"].(string)
	action = strings.ToLower(action)
	return action == "block" || action == "managed_challenge" || action == "challenge" || action == "js_challenge"
}

func extractIPFromString(in string) string {
	fields := strings.FieldsFunc(in, func(r rune) bool {
		return !(r == '.' || r == ':' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
	})
	for _, field := range fields {
		if ip := net.ParseIP(field); ip != nil {
			return ip.String()
		}
	}
	return ""
}
