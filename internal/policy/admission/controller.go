package admission

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/policy/engine"
	"github.com/jm/security-automation-go/internal/policy/explain"
	"github.com/jm/security-automation-go/internal/policy/federation"
	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/policy/opa"
	"github.com/jm/security-automation-go/internal/policy/replay/canonical"
	"github.com/jm/security-automation-go/internal/policy/replay/evidence"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

// Controller integrates policy engine, ownership resolver, and federation into the runtime flow.
type Controller struct {
	engine   *engine.Engine
	opa      *opa.Engine
	ownerRes *ownership.Resolver
	fedRes   *federation.Resolver
	recorder *recorder.Recorder
	logger   *slog.Logger
}

func New(e *engine.Engine, oe *opa.Engine, or *ownership.Resolver, fr *federation.Resolver, rec *recorder.Recorder, logger *slog.Logger) *Controller {
	return &Controller{
		engine:   e,
		opa:      oe,
		ownerRes: or,
		fedRes:   fr,
		recorder: rec,
		logger:   logger,
	}
}

func (c *Controller) GetOwnershipResolver() *ownership.Resolver {
	return c.ownerRes
}

func (c *Controller) GetRecorder() *recorder.Recorder {
	return c.recorder
}

func (c *Controller) GetFederationResolver() *federation.Resolver {
	return c.fedRes
}

// ExplainDecision builds a causal graph for a decision if evidence is found.
func (c *Controller) ExplainDecision(ctx context.Context, evidenceID string) (*explain.DecisionGraph, error) {
	const op = "policy.admission.ExplainDecision"

	ev, ok := c.recorder.Get(evidenceID)
	if !ok {
		return nil, apperr.Newf(op, "evidence not found: %s", evidenceID)
	}

	// Reconstruct a FederatedDecision from evidence
	// (Simplified mapping for Phase 1)
	fedDec := federation.FederatedDecision{
		FinalDecision: ev.FinalDecision,
		TraceID:       ev.TraceID,
		Reason:        "reconstructed from evidence",
	}

	for _, dr := range ev.Decisions {
		fedDec.Contributors = append(fedDec.Contributors, federation.ScopedDecision{
			BundleID: dr.PolicyID,
			RuleID:   dr.RuleID,
			Decision: dr.Outcome,
			Reason:   dr.Reason,
		})
	}

	builder := explain.NewBuilder()
	return builder.Build(fedDec), nil
}

// Authorize checks if an action is allowed based on the current context and ownership.
func (c *Controller) Authorize(ctx context.Context, evalCtx models.EvaluationContext) (models.AdmissionDecision, error) {
	// 1. Ownership check
	for _, sik := range evalCtx.ResourceIDs {
		outcome, err := c.ownerRes.Resolve(ctx, "cf-sync", sik, ownership.RightUpdate)
		if err != nil {
			return models.AdmissionDecision{}, err
		}
		if !outcome.Allowed {
			return models.AdmissionDecision{
				Allowed:  false,
				Decision: models.DecisionDeny,
				Reason:   fmt.Sprintf("ownership violation on %s: %s", sik, outcome.Reason),
			}, nil
		}
	}

	// 2. Legacy Engine evaluation
	decision := c.engine.Evaluate(ctx, evalCtx)

	c.logger.Info("admission_decision",
		"target", evalCtx.TargetType,
		"allowed", decision.Allowed,
		"decision", decision.Decision,
		"reason", decision.Reason,
		"trace_id", evalCtx.TraceID,
	)

	return decision, nil
}

// AuthorizeFederated performs hierarchical policy-as-code evaluation across multiple scopes.
func (c *Controller) AuthorizeFederated(ctx context.Context, input models.PolicyInput) (federation.FederatedDecision, error) {
	const op = "policy.admission.AuthorizeFederated"

	// 1. Resolve scope hierarchy
	_ = c.fedRes.ResolveScopeHierarchy(input.Scope.Tenant, input.Scope.ZoneID)

	var decisions []federation.ScopedDecision

	// 2. Evaluate each bundle in the hierarchy
	// Note: In Phase 1, we still use the single OPA engine, but we'll eventually
	// support switching OPA modules per bundle. For now, we simulate the merge.

	decision, reason, err := c.opa.Evaluate(ctx, input)
	if err != nil {
		return federation.FederatedDecision{}, err
	}

	decisions = append(decisions, federation.ScopedDecision{
		Scope:    federation.ScopeGlobal,
		BundleID: "global-default",
		Decision: decision,
		Reason:   reason,
	})

	// 3. Merge decisions
	final := c.fedRes.MergeDecisions(decisions)

	// 4. Record evidence
	inputCS, _ := canonical.Checksum(input)
	ev := evidence.GovernanceEvidence{
		EvidenceID:      fmt.Sprintf("ev-%d", time.Now().UnixNano()),
		Timestamp:       time.Now().UTC(),
		ScopeID:         input.Scope.ID(),
		TenantID:        input.Scope.Tenant,
		FinalDecision:   final.FinalDecision,
		InputChecksum:   inputCS,
		LifecycleStatus: string(input.Lifecycle.Status),
		TraceID:         input.Batch.ID, // Simplified
	}
	_ = c.recorder.Record(ctx, ev)

	c.logger.Info("federated_admission_decision",
		"scope", input.Scope.ID(),
		"final_decision", final.FinalDecision,
		"contributor_count", len(decisions),
	)

	return final, nil
}
