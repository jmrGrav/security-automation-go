package wafref

import (
	"fmt"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
)

// RawEvent mirrors one line written by the OpenResty/Lua waf_refs.lua bundle
// to waf_refs.jsonl: the block-page reference a human saw, plus the request
// details already computed by the ban-page renderer. It carries no score or
// detection signal of its own — it only exists for correlation.
type RawEvent struct {
	Ref       string    `json:"ref"`
	Timestamp time.Time `json:"ts"`
	IP        string    `json:"client_ip"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	URI       string    `json:"uri"`
	Reason    string    `json:"reason"`
}

func Normalize(raw RawEvent) (classifier.Event, error) {
	if strings.TrimSpace(raw.IP) == "" {
		return classifier.Event{}, fmt.Errorf("wafref normalize: ip is required")
	}
	if strings.TrimSpace(raw.Ref) == "" {
		return classifier.Event{}, fmt.Errorf("wafref normalize: ref is required")
	}
	uri := strings.TrimSpace(raw.URI)
	if uri == "" {
		uri = "unknown"
	}
	return classifier.Event{
		IP:         raw.IP,
		URI:        uri,
		URIs:       []string{uri},
		Hostname:   raw.Host,
		HTTPMethod: raw.Method,
		Action:     "block",
		RuleName:   firstNonEmpty(raw.Reason, "waf_block"),
		Source:     "waf_ref",
		Timestamp:  raw.Timestamp.UTC(),
		Hits:       1,
		Ref:        raw.Ref,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
