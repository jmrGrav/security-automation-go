package pipeline

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/crowdsec/translator"
	"github.com/jm/security-automation-go/internal/crowdsec/validation"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/orchestrator/result"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/reconciliation"
	rolexecutor "github.com/jm/security-automation-go/internal/rollback/executor"
	rolplanner "github.com/jm/security-automation-go/internal/rollback/planner"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/bus"
	"github.com/jm/security-automation-go/internal/runtime/convergence"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/drift"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/snapshot"
	"go.opentelemetry.io/otel/trace"
)

type Orchestrator struct {
	cfClient     *client.Client
	abuseClient  *abuseipdb.Client
	planner      reconciliation.Planner
	csTranslator *translator.Translator
	csValidator  *validation.Validator
	admission    *admission.Controller
	leaseMgr     *coordination.LeaseManager
	sm           *engine.StateMachine
	driftEng     *drift.Engine
	gov          *governor.ResourceGovernor

	// Convergence components
	convVal *convergence.Validator
	invEng  *invariants.Engine

	// Rollback components
	rolPlanner  *rolplanner.Planner
	rolExecutor *rolexecutor.Executor

	// Runtime components
	journal        journal.JournalStore
	state          *state.StateStore
	breaker        *breaker.CircuitBreaker
	bus            *bus.EventBus
	health         *health.HealthManager
	killSwitchPath string
}

func NewOrchestrator(
	cfClient *client.Client,
	abuseClient *abuseipdb.Client,
	planner reconciliation.Planner,
	csTranslator *translator.Translator,
	csValidator *validation.Validator,
	admissionController *admission.Controller,
	leaseManager *coordination.LeaseManager,
	stateMachine *engine.StateMachine,
	driftEngine *drift.Engine,
	resourceGovernor *governor.ResourceGovernor,
	convergenceValidator *convergence.Validator,
	invariantEngine *invariants.Engine,
	rolPlanner *rolplanner.Planner,
	rolExecutor *rolexecutor.Executor,
	journal journal.JournalStore,
	state *state.StateStore,
	breaker *breaker.CircuitBreaker,
	eventBus *bus.EventBus,
	healthManager *health.HealthManager,
	killSwitchPath string,
) *Orchestrator {
	return &Orchestrator{
		cfClient:       cfClient,
		abuseClient:    abuseClient,
		planner:        planner,
		csTranslator:   csTranslator,
		csValidator:    csValidator,
		admission:      admissionController,
		leaseMgr:       leaseManager,
		sm:             stateMachine,
		driftEng:       driftEngine,
		gov:            resourceGovernor,
		convVal:        convergenceValidator,
		invEng:         invariantEngine,
		rolPlanner:     rolPlanner,
		rolExecutor:    rolExecutor,
		journal:        journal,
		state:          state,
		breaker:        breaker,
		bus:            eventBus,
		health:         healthManager,
		killSwitchPath: killSwitchPath,
	}
}

// DryRun executes the full pipeline in dry-run mode.
func (o *Orchestrator) DryRun(ctx context.Context, zoneID string, rt snapshot.ResourceType, provenance snapshot.ProvenanceMetadata) (result.PipelineResult, error) {
	const op = "orchestrator.pipeline.DryRun"

	tracer := tracing.GetTracer()
	ctx, span := tracer.Start(ctx, "reconciliation.run", trace.WithAttributes(
		tracing.AttrZoneScope.String(zoneID),
		tracing.AttrResourceKind.String(string(rt)),
		tracing.AttrRunID.String(fmt.Sprintf("run-%d", time.Now().Unix())),
	))
	defer span.End()

	metrics.ReconciliationRunsTotal.Inc()

	res := result.PipelineResult{
		StartTime:  time.Now().UTC(),
		Provenance: provenance,
	}

	o.bus.Emit(models.EventRunStarted, "", map[string]interface{}{"zone": zoneID, "resource": rt, "mode": "dry-run"})

	rules, err := o.runDiscoveryStage(ctx, tracer, zoneID, rt)
	if err != nil {
		span.RecordError(err)
		return res, apperr.Wrap(op, err)
	}
	res.Discovery.ResourceCount = len(rules)

	if err := o.sm.Transition(ctx, models.StatusPlanning, "discovery completed"); err != nil {
		return res, err
	}

	// 3. Normalization & Assembly
	snap, err := o.runNormalizationStage(ctx, tracer, rt, rules, provenance, &res)
	if err != nil {
		return res, apperr.Wrap(op, err)
	}

	// 4. Planning (Dry-run always diffs discovery vs empty for display)
	_, planningSpan := tracer.Start(ctx, "reconciliation.plan")
	plan, err := o.runPlanningStage(snap)
	if err != nil {
		metrics.ReconciliationFailuresTotal.Inc()
		planningSpan.RecordError(err)
		planningSpan.End()
		_ = o.sm.Transition(ctx, models.StatusFailed, "planning failed")
		return res, apperr.Wrap(op, err)
	}
	planningSpan.SetAttributes(
		tracing.AttrPlanID.String(plan.PlanID),
		tracing.AttrObjectCount.Int(len(plan.Operations)),
	)
	planningSpan.End()
	res.Plan = plan
	res.Planning.OperationCount = len(plan.Operations)

	// 5. Admission Control
	admDecision, err := o.runAdmissionStage(ctx, tracer, plan, span.SpanContext().TraceID().String())
	if err != nil {
		_ = o.sm.Transition(ctx, models.StatusFailed, "admission check failed")
		return res, apperr.Wrap(op, err)
	}

	if !admDecision.Allowed {
		_ = o.sm.Transition(ctx, models.StatusIdle, "admission denied")
		return res, apperr.Newf(op, "admission denied: %s", admDecision.Reason)
	}

	if err := o.sm.Transition(ctx, models.StatusExecuting, "admission granted"); err != nil {
		return res, err
	}

	for _, pop := range plan.Operations {
		metrics.MutationOperationsTotal.WithLabelValues(string(pop.Type)).Inc()
	}

	// 6. Translation (CrowdSec)
	actions, err := o.runTranslationStage(ctx, tracer, plan, provenance)
	if err != nil {
		_ = o.sm.Transition(ctx, models.StatusFailed, "translation failed")
		return res, apperr.Wrap(op, err)
	}
	res.Actions = actions
	res.Translation.ActionCount = len(actions)

	// 7. Reporting Translation (AbuseIPDB)
	o.runReportingStage(ctx, tracer, plan, snap.SnapshotID)

	// 8. Final Validation
	if err := o.runValidationStage(ctx, actions); err != nil {
		span.RecordError(err)
		return res, apperr.Wrap(op, err)
	}

	return res, o.runCompletionStage(ctx, &res, snap, plan, span)
}

// Rollback executes a compensation batch for a failed mutation run.
func (o *Orchestrator) Rollback(ctx context.Context, forwardBatch execution.MutationBatch, reason string) error {
	const op = "orchestrator.pipeline.Rollback"

	// 1. Acquire Rollback Lease
	lease, epoch, err := o.leaseMgr.Acquire(ctx, "orchestrator", "rollback", "")
	if err != nil {
		return apperr.Wrap(op, err)
	}
	defer o.leaseMgr.Release(ctx, lease.ID)
	leaseExec := o.newLeaseBoundExecution(ctx, *lease, time.Minute, 10*time.Minute, 3)
	defer leaseExec.heartbeat.Stop()
	defer leaseExec.cancel(nil)

	o.bus.Emit(models.EventRunStarted, "", map[string]interface{}{"batch": forwardBatch.ID, "mode": "rollback", "reason": reason, "epoch": epoch.ID})

	_ = o.sm.Transition(ctx, models.StatusRollbackRequired, "triggering rollback")

	// 2. Generate Rollback Plan
	rollbackBatch, err := o.rolPlanner.GenerateRollbackBatch(forwardBatch, reason)
	if err != nil {
		_ = o.sm.Transition(ctx, models.StatusFailed, "rollback planning failed")
		return apperr.Wrap(op, err)
	}
	rollbackBatch.EpochID = epoch.ID
	rollbackBatch.Generation = epoch.Generation
	rollbackBatch.LeaseID = lease.ID
	rollbackBatch.FencingToken = lease.FencingToken
	rollbackBatch.LeaseAction = lease.Action
	for i := range rollbackBatch.Operations {
		rollbackBatch.Operations[i].LeaseID = lease.ID
		rollbackBatch.Operations[i].FencingToken = lease.FencingToken
		rollbackBatch.Operations[i].LeaseAction = lease.Action
	}

	// 3. Admission Control for Rollback
	rollbackDecision, err := o.runRollbackAdmissionStage(leaseExec.ctx, rollbackBatch)
	if err != nil {
		_ = o.sm.Transition(ctx, models.StatusFailed, "rollback admission failed")
		return apperr.Wrap(op, err)
	}
	if !rollbackDecision.Allowed {
		_ = o.sm.Transition(ctx, models.StatusRollbackRequired, "rollback admission denied")
		return apperr.Newf(op, "rollback admission denied: %s", rollbackDecision.Reason)
	}

	_ = o.sm.Transition(ctx, models.StatusRollingBack, "executing rollback")

	// 4. Execute Rollback
	if err := o.runExecutionStage(leaseExec.ctx, rollbackBatch); err != nil {
		return apperr.Wrap(op, err)
	}

	o.bus.Emit(models.EventRunCompleted, rollbackBatch.ID, map[string]interface{}{"status": "rolled_back"})
	_ = o.sm.Transition(ctx, models.StatusIdle, "rollback completed")

	return nil
}

// IsKilled checks for the existence of a manual kill-switch file.
func (o *Orchestrator) IsKilled() bool {
	if o.killSwitchPath == "" {
		return false
	}
	_, err := os.Stat(o.killSwitchPath)
	return err == nil
}

func (o *Orchestrator) GetOwnershipResolver() *ownership.Resolver {
	return o.admission.GetOwnershipResolver()
}

func (o *Orchestrator) GetGovernor() *governor.ResourceGovernor {
	return o.gov
}

func (o *Orchestrator) GetWorkerPool() *pool.Pool {
	return nil // To be injected
}

func (o *Orchestrator) SetWorkerPool(p *pool.Pool) {
	// Optional setter if needed
}

func (o *Orchestrator) deriveScope(zoneID string) scope.RuntimeScope {
	return scope.RuntimeScope{
		Tenant: "default",
		ZoneID: zoneID,
	}
}
