package main

import (
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/execution"
	rolexecutor "github.com/jm/security-automation-go/internal/rollback/executor"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/wiring"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type startupWiringInputs struct {
	profile string

	executor         *execution.GovernedExecutor
	rollback         *rolexecutor.Executor
	leaseManager     *coordination.LeaseManager
	auditJournal     journal.JournalStore
	ownership        any
	policyEngine     any
	opaEngine        any
	governor         any
	outboxWorker     *reporting.OutboxWorker
	outboxLeaseGuard reporting.OutboxLeaseGuard
}

func buildStartupWiringMatrix(in startupWiringInputs) wiring.Matrix {
	execFenced := in.executor != nil && in.executor.HasFencingValidator()
	rollbackFenced := in.rollback != nil && in.rollback.HasFencingValidator()
	return wiring.Matrix{
		Profile:            in.profile,
		Fencing:            execFenced && rollbackFenced,
		Lease:              in.leaseManager != nil && in.leaseManager.HasPersistentLeaseStore(),
		LeaderCoordination: in.leaseManager != nil && in.leaseManager.HasPersistentLeaseStore(),
		Audit:              in.auditJournal != nil,
		Telemetry:          in.executor != nil && in.executor.HasTelemetrySink(),
		Ownership:          in.ownership != nil,
		PolicyEngine:       in.policyEngine != nil,
		Governor:           in.governor != nil,
		OPA:                in.opaEngine != nil,
		OutboxWorker:       in.outboxWorker != nil,
		OutboxLeaseGuard:   in.outboxLeaseGuard != nil,
	}
}

func validateStartupWiring(cfg *config.Config, in startupWiringInputs) error {
	in.profile = cfg.Runtime.Profile
	matrix := buildStartupWiringMatrix(in)
	matrix.AbuseIPDBReportingConfigured = cfg.AbuseIPDB.ReportingEnabled != nil
	matrix.AbuseIPDBReportingEnabled = cfg.AbuseIPDB.ReportingEnabled != nil && *cfg.AbuseIPDB.ReportingEnabled
	return matrix.ValidateStartup()
}
