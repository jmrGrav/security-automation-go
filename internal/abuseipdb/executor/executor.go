package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/quota"
)

// Executor defines the contract for sending reports.
type Executor interface {
	Execute(ctx context.Context, reports []models.ExecutableReport) error
}

type RealExecutor struct {
	transport *transport.Transport
}

func New(t *transport.Transport) *RealExecutor {
	return &RealExecutor{transport: t}
}

func (e *RealExecutor) Execute(ctx context.Context, reports []models.ExecutableReport) error {
	for _, r := range reports {
		if state, ok := quota.DefaultRegistry().State("abuseipdb"); ok && state == quota.Exhausted {
			metrics.AbuseIPDBFailuresTotal.Inc()
			metrics.AbuseIPDBRateLimitTotal.Inc()
			return fmt.Errorf("abuseipdb quota exhausted; reporting suspended")
		}

		// 1. Send report
		req := models.ReportRequest{
			IP:         r.IP,
			Categories: r.Categories,
			Comment:    r.Comment,
		}

		start := time.Now()
		_, err := e.transport.Report(ctx, req)
		duration := time.Since(start)

		// 2. Metrics
		metrics.AbuseIPDBExecutionDurationSeconds.Observe(duration.Seconds())
		if err != nil {
			metrics.AbuseIPDBFailuresTotal.Inc()
			// Check for rate limit
			if isRateLimit(err) {
				metrics.AbuseIPDBRateLimitTotal.Inc()
			}
			return err
		} else {
			metrics.AbuseIPDBReportsTotal.Inc()
		}
	}
	return nil
}

func isRateLimit(err error) bool {
	// Simple check based on error string for now
	return err != nil && (contains(err.Error(), "429") || contains(err.Error(), "rate limit"))
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr)))
}

type DryRunExecutor struct{}

func NewDryRunExecutor() *DryRunExecutor {
	return &DryRunExecutor{}
}

func (e *DryRunExecutor) Execute(ctx context.Context, reports []models.ExecutableReport) error {
	// Dry-run rendering is usually handled by a separate layer or logged here
	return nil
}
