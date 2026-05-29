package adapter

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// CSCLIExecutor implements real CrowdSec mutations using the cscli binary.
type CSCLIExecutor struct {
	binPath string
	timeout time.Duration
}

func NewCSCLIExecutor(binPath string, timeout time.Duration) *CSCLIExecutor {
	if binPath == "" {
		binPath = "cscli"
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &CSCLIExecutor{
		binPath: binPath,
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
			ExecutedBy: "cscli-executor",
		},
	}

	var args []string
	switch a.Type {
	case models.ActionAddDecision:
		args = []string{"decisions", "add", "--" + a.Scope, a.Value, "--duration", a.Duration, "--reason", a.Reason, "--type", "ban"}
	case models.ActionDeleteDecision:
		args = []string{"decisions", "delete", "--" + a.Scope, a.Value}
	default:
		res.Status = "failed"
		res.Error = "unsupported action type"
		return res
	}

	res.Audit.RawCommand = e.binPath + " " + strings.Join(args, " ")

	// Execute command safely
	cmd := exec.CommandContext(ctx, e.binPath, args...)
	output, err := cmd.CombinedOutput()

	res.Duration = time.Since(start)

	if err != nil {
		// Handle idempotence: if it already exists or was already deleted, we might count as success
		// or specific status.
		outStr := string(output)
		if e.isIdempotentSuccess(a.Type, outStr) {
			res.Status = "success"
			res.Audit.RawCommand += " (idempotent)"
		} else {
			res.Status = "failed"
			res.Error = fmt.Sprintf("%v: %s", err, outStr)
		}
	} else {
		res.Status = "success"
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
