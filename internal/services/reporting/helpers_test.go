package reporting_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type fakeReporter struct {
	reports []abmodels.ExecutableReport
	err     error
	mu      sync.Mutex
}

func (f *fakeReporter) Execute(_ context.Context, reports []abmodels.ExecutableReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.reports = append(f.reports, reports...)
	return nil
}

func (f *fakeReporter) Reports() []abmodels.ExecutableReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]abmodels.ExecutableReport(nil), f.reports...)
}

type fakeDedupStore struct {
	mu         sync.Mutex
	last       map[string]time.Time
	err        error
	markErr    error
	markCount  int
	lastMarked string
}

func newFakeDedupStore() *fakeDedupStore {
	return &fakeDedupStore{last: make(map[string]time.Time)}
}

func (s *fakeDedupStore) LastReportedAt(_ context.Context, ip netip.Addr) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return time.Time{}, false, s.err
	}
	ts, ok := s.last[ip.String()]
	return ts, ok, nil
}

func (s *fakeDedupStore) MarkReported(_ context.Context, ip netip.Addr, reportedAt time.Time, evidenceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.markErr != nil {
		return s.markErr
	}
	s.last[ip.String()] = reportedAt
	s.markCount++
	s.lastMarked = evidenceID
	return nil
}

type fakeEvidenceStore struct {
	mu       sync.Mutex
	evidence []reporting.DecisionEvidence
	err      error
}

type fakeReservationStore struct {
	mu       sync.Mutex
	reserve  []reporting.ReportReservation
	statuses map[string]string
	items    []reporting.ReportOutboxItem
	err      error
}

func (s *fakeReservationStore) Reserve(_ context.Context, reservation reporting.ReportReservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	for _, existing := range s.reserve {
		if existing.IP == reservation.IP && existing.Status == reporting.ReportStatusPending {
			return errors.New("reservation exists")
		}
	}
	s.reserve = append(s.reserve, reservation)
	if s.statuses == nil {
		s.statuses = make(map[string]string)
	}
	s.statuses[reservation.EvidenceID] = reservation.Status
	return nil
}

func (s *fakeReservationStore) FindPendingByIPAndIdempotencyKey(_ context.Context, ip string, idempotencyKey string) (reporting.ReportReservation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, reservation := range s.reserve {
		if reservation.IP == ip && reservation.IdempotencyKey == idempotencyKey && reservation.Status == reporting.ReportStatusPending {
			return reservation, true, nil
		}
	}
	return reporting.ReportReservation{}, false, nil
}

func (s *fakeReservationStore) MarkStatus(_ context.Context, evidenceID string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.statuses == nil {
		s.statuses = make(map[string]string)
	}
	s.statuses[evidenceID] = status
	for i := range s.reserve {
		if s.reserve[i].EvidenceID == evidenceID {
			s.reserve[i].Status = status
		}
	}
	return nil
}

func (s *fakeReservationStore) ClaimRetryable(_ context.Context, now time.Time, limit int, claimUntil time.Time) ([]reporting.ReportOutboxItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if len(s.items) > 0 {
		out := append([]reporting.ReportOutboxItem(nil), s.items...)
		for i := range out {
			out[i].NextAttemptAt = claimUntil
		}
		return out, nil
	}
	var out []reporting.ReportOutboxItem
	for _, reservation := range s.reserve {
		if reservation.Status == reporting.ReportStatusPending || reservation.Status == reporting.ReportStatusFailed {
			out = append(out, reporting.ReportOutboxItem{Reservation: reservation, NextAttemptAt: claimUntil})
		}
	}
	return out, nil
}

func (s *fakeReservationStore) RecordAttempt(_ context.Context, evidenceID string, status string, lastError string, nextAttemptAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.statuses == nil {
		s.statuses = make(map[string]string)
	}
	s.statuses[evidenceID] = status
	for i := range s.reserve {
		if s.reserve[i].EvidenceID == evidenceID {
			s.reserve[i].Status = status
		}
	}
	for i := range s.items {
		if s.items[i].Reservation.EvidenceID == evidenceID {
			s.items[i].Reservation.Status = status
			s.items[i].AttemptCount++
			s.items[i].LastError = lastError
			s.items[i].NextAttemptAt = nextAttemptAt
		}
	}
	return nil
}

func (s *fakeEvidenceStore) Append(_ context.Context, evidence reporting.DecisionEvidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.evidence = append(s.evidence, evidence)
	return nil
}

func (s *fakeEvidenceStore) Evidence() []reporting.DecisionEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]reporting.DecisionEvidence(nil), s.evidence...)
}

func (s *fakeEvidenceStore) List(_ context.Context, limit int) ([]reporting.DecisionEvidence, error) {
	return s.Search(context.Background(), reporting.EvidenceSearchOptions{Limit: limit})
}

func (s *fakeEvidenceStore) Get(_ context.Context, evidenceID string) (reporting.DecisionEvidence, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, evidence := range s.evidence {
		if evidence.EvidenceID == evidenceID {
			return evidence, true, nil
		}
	}
	return reporting.DecisionEvidence{}, false, nil
}

func (s *fakeEvidenceStore) Search(_ context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]reporting.DecisionEvidence(nil), s.evidence...)
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

func (s *fakeEvidenceStore) Count(_ context.Context, opts reporting.EvidenceSearchOptions) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.evidence)
	if opts.Limit > 0 && n > opts.Limit {
		n = opts.Limit
	}
	return n, nil
}

func withURIs(event classifier.Event, uris []string) classifier.Event {
	event.URIs = uris
	event.URI = uris[0]
	return event
}
