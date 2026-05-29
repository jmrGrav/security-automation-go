package openrestyevent

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
)

type RawEvent struct {
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	URIs      []string  `json:"uris"`
	UserAgent string    `json:"user_agent"`
	Action    string    `json:"action"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Timestamp time.Time `json:"timestamp"`
	Hits      int       `json:"hits"`
	WindowSec int       `json:"window_seconds"`
}

func Normalize(raw RawEvent) (classifier.Event, error) {
	if strings.TrimSpace(raw.IP) == "" {
		return classifier.Event{}, fmt.Errorf("openrestyevent normalize: ip is required")
	}
	uris := normalizeURIs(raw.URIs)
	if len(uris) == 0 {
		return classifier.Event{}, fmt.Errorf("openrestyevent normalize: at least one uri is required")
	}
	return classifier.Event{
		IP:        raw.IP,
		URI:       uris[0],
		URIs:      uris,
		Hostname:  raw.Hostname,
		UserAgent: raw.UserAgent,
		Action:    firstNonEmpty(raw.Action, "block"),
		RuleID:    raw.RuleID,
		RuleName:  raw.RuleName,
		Source:    "openresty_waf",
		Timestamp: raw.Timestamp.UTC(),
		Hits:      raw.Hits,
		WindowSec: raw.WindowSec,
	}, nil
}

func normalizeURIs(uris []string) []string {
	out := make([]string, 0, len(uris))
	seen := make(map[string]struct{}, len(uris))
	for _, uri := range uris {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		if _, ok := seen[uri]; ok {
			continue
		}
		seen[uri] = struct{}{}
		out = append(out, uri)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
