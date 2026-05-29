package sqlite

import "github.com/jm/security-automation-go/internal/services/reporting"

// ReportingStores groups the SQLite-backed persistence used by the reporting/security slice.
type ReportingStores struct {
	Dedup    *AbuseReportDedupStore
	Evidence *ReportingEvidenceStore
	Cursors  *CursorStore
	Outbox   *ReportReservationStore
}

func NewReportingStores(db *DB) *ReportingStores {
	if db == nil {
		return nil
	}
	return &ReportingStores{
		Dedup:    NewAbuseReportDedupStore(db),
		Evidence: NewReportingEvidenceStore(db),
		Cursors:  NewCursorStore(db),
		Outbox:   NewReportReservationStore(db),
	}
}

func (s *ReportingStores) Configure(service *reporting.Service) {
	if s == nil || service == nil {
		return
	}
	service.SetReportDedupStore(s.Dedup)
	service.SetEvidenceStore(s.Evidence)
	service.SetReportReservationStore(s.Outbox)
}
