package crowdsecevent

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

func (s *Service) Process(ctx context.Context, raw RawEvent) (reporting.Result, error) {
	normalized, err := Normalize(raw)
	if err != nil {
		return reporting.Result{}, err
	}
	if s == nil || s.reporting == nil {
		return reporting.Result{}, nil
	}
	return s.reporting.Process(ctx, reporting.Request{
		Source: abuseformat.SourceCrowdSecWAF,
		Event:  normalized,
	})
}
