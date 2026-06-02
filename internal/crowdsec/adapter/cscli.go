package adapter

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec"
	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// durationPattern matches cscli-style ban durations (e.g. "4h", "30m",
// "168h", "1h30m"). It deliberately rejects anything else so malformed or
// hostile durations never reach the delegated CrowdSec write boundary.
var durationPattern = regexp.MustCompile(`^[0-9]+[smhd]([0-9]+[smhd])*$`)

// allowedScopes is the strict allowlist of CrowdSec decision scopes this batch
// adapter may delegate. Anything else fails closed before reaching the writer.
var allowedScopes = map[string]bool{"ip": true, "range": true}

// validateExecOperation enforces fail-closed input validation before this batch
// adapter delegates to the single CrowdSec write boundary. Returns an empty
// string when the operation is safe to delegate.
func validateExecOperation(a models.ExecutableOperation) string {
	switch a.Type {
	case models.ActionAddDecision, models.ActionDeleteDecision:
	default:
		return "unsupported action type"
	}
	if !allowedScopes[a.Scope] {
		return "invalid scope (allowed: ip, range)"
	}
	if a.Value == "" {
		return "missing target value"
	}
	// Reject flag-injection on every field that becomes a positional cscli arg.
	for _, field := range []string{a.Scope, a.Value, a.Duration, a.Reason} {
		if strings.HasPrefix(field, "-") {
			return "argument must not start with '-'"
		}
	}
	switch a.Scope {
	case "ip":
		if net.ParseIP(a.Value) == nil {
			return "value is not a valid IP address"
		}
	case "range":
		if _, _, err := net.ParseCIDR(a.Value); err != nil {
			return "value is not a valid CIDR range"
		}
	}
	if a.Type == models.ActionAddDecision {
		if a.Duration == "" {
			return "missing duration for add decision"
		}
		if !durationPattern.MatchString(a.Duration) {
			return "invalid duration format (expected e.g. 4h, 30m)"
		}
	}
	return ""
}

// CSCLIExecutor preserves the batch execution contract for orchestrator code,
// but it is not a CrowdSec write boundary. It delegates all mutations to the
// injected CrowdSec writer, which in production must be crowdsec.Client.
type CSCLIExecutor struct {
	writer  crowdsec.DecisionManager
	timeout time.Duration
}

func NewCSCLIExecutor(binPath string, timeout time.Duration) *CSCLIExecutor {
	if binPath == "" {
		binPath = "cscli"
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return NewCSCLIExecutorWithWriter(crowdsec.NewClientFromConfig(binPath, "", timeout), timeout)
}

func NewCSCLIExecutorWithWriter(writer crowdsec.DecisionManager, timeout time.Duration) *CSCLIExecutor {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &CSCLIExecutor{
		writer:  writer,
		timeout: timeout,
	}
}

func (e *CSCLIExecutor) Execute(ctx context.Context, batch models.Batch) (models.BatchResult, error) {
	const op = "crowdsec.adapter.CSCLIExecutor.Execute"

	result := models.BatchResult{
		BatchID:   batch.ID,
		StartTime: time.Now().UTC(),
		Success:   true,
	}

	for _, action := range batch.Actions {
		// Enforce timeout per mutation
		opCtx, cancel := context.WithTimeout(ctx, e.timeout)

		execRes := e.executeSingle(opCtx, action)
		cancel()

		result.Results = append(result.Results, execRes)
		if execRes.Status == "failed" {
			result.Success = false
		}
	}

	result.EndTime = time.Now().UTC()
	return result, nil
}

func (e *CSCLIExecutor) executeSingle(ctx context.Context, a models.ExecutableOperation) models.ExecutionResult {
	start := time.Now()
	res := models.ExecutionResult{
		OperationID: a.OriginatingOpID,
		Audit: models.AuditTrail{
			Action:     a.Type,
			Target:     a.Value,
			ExecutedAt: start.UTC(),
			ExecutedBy: "crowdsec-client-delegating-executor",
		},
	}

	// Fail closed before delegating to the CrowdSec write boundary.
	if reason := validateExecOperation(a); reason != "" {
		res.Status = "failed"
		res.Error = reason
		return res
	}

	if e.writer == nil {
		res.Status = "failed"
		res.Error = "missing CrowdSec decision writer"
		return res
	}

	var err error
	switch a.Type {
	case models.ActionAddDecision:
		if a.Scope == "ip" {
			err = e.writer.AddIPDecision(ctx, a.Value, a.Duration, a.Reason)
		} else {
			err = e.writer.AddRangeDecision(ctx, a.Value, a.Duration, a.Reason)
		}
	case models.ActionDeleteDecision:
		if a.Scope == "ip" {
			err = e.writer.DeleteIPDecision(ctx, a.Value)
		} else {
			err = e.writer.DeleteRangeDecision(ctx, a.Value)
		}
	default:
		res.Status = "failed"
		res.Error = "unsupported action type"
		return res
	}

	res.Duration = time.Since(start)

	if err != nil {
		if e.isIdempotentSuccess(a.Type, err.Error()) {
			res.Status = "success"
			res.Audit.RawCommand = "(delegated crowdsec.Client idempotent)"
		} else {
			res.Status = "failed"
			res.Error = err.Error()
		}
	} else {
		res.Status = "success"
		res.Audit.RawCommand = "(delegated crowdsec.Client)"
	}

	return res
}

func (e *CSCLIExecutor) isIdempotentSuccess(t models.ActionType, output string) bool {
	lowerOut := strings.ToLower(output)
	if t == models.ActionAddDecision {
		// "decision already exists" or similar
		return strings.Contains(lowerOut, "already exists")
	}
	if t == models.ActionDeleteDecision {
		// "0 decisions deleted" or similar
		return strings.Contains(lowerOut, "0 decisions deleted") || strings.Contains(lowerOut, "no matching")
	}
	return false
}
