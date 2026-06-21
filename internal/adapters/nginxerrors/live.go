package nginxerrors

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/nginxaccess"
)

// LiveSource reads error entries (status >= 400) from nginx access logs in
// LogDir, using nginxaccess.ReadDir's rotation-aware glob (access.log,
// access.log.1, *.gz). Unlike wafref's byte-offset tailer, access logs
// rotate and get truncated, so callers must track progress by event
// timestamp (via ListErrorsSince's since/high-watermark contract), not by
// file offset.
type LiveSource struct {
	LogDir string
}

func NewLiveSource(logDir string) *LiveSource {
	return &LiveSource{LogDir: logDir}
}

// ListErrorsSince returns all error-status (>=400) entries strictly after
// since, sorted oldest-first. Fail-open: missing/unreadable files yield an
// empty result rather than an error.
func (s *LiveSource) ListErrorsSince(_ context.Context, since time.Time) ([]RawEvent, error) {
	if s == nil {
		return nil, nil
	}
	entries := nginxaccess.Filter4xx5xx(nginxaccess.ReadDir(s.LogDir))

	events := make([]RawEvent, 0, len(entries))
	for _, e := range entries {
		if !e.Time.After(since) {
			continue
		}
		events = append(events, RawEvent{
			IP:        e.IP,
			Timestamp: e.Time,
			Method:    e.Method,
			URI:       e.URI,
			Status:    e.Status,
			UserAgent: e.UserAgent,
		})
	}
	return events, nil
}
