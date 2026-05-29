// Package cloudflareevent normalizes Cloudflare WAF events into the local
// classifier input shape. It keeps Cloudflare transport schemas out of the
// security classifier and ensures replay remains deterministic and auditable.
package cloudflareevent

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
)

type RawEvent struct {
	IP        string    `json:"ip"`
	URI       string    `json:"uri"`
	Hostname  string    `json:"hostname"`
	UserAgent string    `json:"user_agent"`
	Action    string    `json:"action"`
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
	RayID     string    `json:"ray_id,omitempty"`
	Hits      int       `json:"hits"`
	WindowSec int       `json:"window_seconds"`
}

func Normalize(raw RawEvent) (classifier.Event, error) {
	if strings.TrimSpace(raw.IP) == "" {
		return classifier.Event{}, fmt.Errorf("cloudflareevent normalize: ip is required")
	}
	if strings.TrimSpace(raw.URI) == "" {
		return classifier.Event{}, fmt.Errorf("cloudflareevent normalize: uri is required")
	}
	return classifier.Event{
		IP:        raw.IP,
		URI:       raw.URI,
		Hostname:  raw.Hostname,
		UserAgent: raw.UserAgent,
		Action:    raw.Action,
		RuleID:    raw.RuleID,
		RuleName:  raw.RuleName,
		Source:    firstNonEmpty(raw.Source, "cloudflare_waf"),
		Timestamp: raw.Timestamp.UTC(),
		RayID:     raw.RayID,
		Hits:      raw.Hits,
		WindowSec: raw.WindowSec,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
