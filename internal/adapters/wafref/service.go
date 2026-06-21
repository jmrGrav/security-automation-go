package wafref

import (
	"context"

	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type Service struct {
	reporting *reporting.Service
}

func NewService(reportingService *reporting.Service) *Service {
	return &Service{reporting: reportingService}
}

// Process records a block-page reference as Evidence/Timeline only. A ref by
// itself is never a ban decision — the CrowdSec/OpenResty alert it
// corresponds to already went through its own reporting path with its own
// classification. This call exists purely so the ref is searchable and
// correlates to that alert by IP/timestamp/URI; it must never reach
// AbuseIPDB/Spamhaus or feed auto-ban.
func (s *Service) Process(ctx context.Context, raw RawEvent) (reporting.Result, error) {
	normalized, err := Normalize(raw)
	if err != nil {
		return reporting.Result{}, err
	}
	if s == nil || s.reporting == nil {
		return reporting.Result{}, nil
	}
	return s.reporting.Process(ctx, reporting.Request{
		Source:       abuseformat.SourceCrowdSecWAF,
		Event:        normalized,
		EvidenceOnly: true,
	})
}
