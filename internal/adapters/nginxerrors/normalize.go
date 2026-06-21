// Package nginxerrors ingests nginx access-log entries with status >= 400
// (the same parsing nginxaccess already provides) and feeds them into the
// evidence-only reporting path for HTTP error intelligence. It never blocks,
// scores, or bans on its own — see Service.ProcessSince.
package nginxerrors

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
)

// RawEvent is one nginx access-log line with an error status (>=400),
// already parsed by nginxaccess.ParseLine/ReadFile/ReadDir.
type RawEvent struct {
	IP        netip.Addr
	Timestamp time.Time
	Method    string
	URI       string
	Status    int
	UserAgent string
}

func Normalize(raw RawEvent) (classifier.Event, error) {
	if !raw.IP.IsValid() {
		return classifier.Event{}, fmt.Errorf("nginxerrors normalize: ip is required")
	}
	if raw.Status < 400 || raw.Status >= 600 {
		return classifier.Event{}, fmt.Errorf("nginxerrors normalize: status %d is not an error status", raw.Status)
	}
	uri := strings.TrimSpace(raw.URI)
	if uri == "" {
		uri = "unknown"
	}
	return classifier.Event{
		IP:                 raw.IP.String(),
		URI:                uri,
		URIs:               []string{uri},
		HTTPMethod:         raw.Method,
		UserAgent:          raw.UserAgent,
		Action:             "http_error",
		RuleName:           fmt.Sprintf("http_%d", raw.Status),
		Source:             "nginx_http_error",
		Timestamp:          raw.Timestamp.UTC(),
		EdgeResponseStatus: raw.Status,
		Hits:               1,
	}, nil
}
