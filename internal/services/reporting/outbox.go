package reporting

import (
	"context"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
)

type ReportReservation struct {
	IP             string
	Source         string
	IdempotencyKey string
	EvidenceID     string
	Status         string
	ExpiresAt      time.Time
	Report         abmodels.ExecutableReport
}

type ReportOutboxItem struct {
	Reservation   ReportReservation
	AttemptCount  int
	LastError     string
	NextAttemptAt time.Time
}

type ReportReservationStore interface {
	Reserve(ctx context.Context, reservation ReportReservation) error
	MarkStatus(ctx context.Context, evidenceID string, status string) error
	ListRetryable(ctx context.Context, now time.Time, limit int) ([]ReportOutboxItem, error)
	RecordAttempt(ctx context.Context, evidenceID string, status string, lastError string, nextAttemptAt time.Time) error
}

const (
	ReportStatusPending             = "pending"
	ReportStatusReported            = "reported"
	ReportStatusFailed              = "failed"
	ReportStatusReportedDedupFailed = "reported_dedup_failed"
)
