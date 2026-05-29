// Package source provides backends for reading active CrowdSec decisions.
// It mirrors Python's _fetch_all_cscli_decisions + get_active_bans() logic.
package source

import (
	"context"
	"strings"
)

// localOrigins mirrors Python's LOCAL_ORIGINS = {"crowdsec", "cscli"}.
// Only decisions from these origins are synced to Cloudflare.
var localOrigins = map[string]bool{
	"crowdsec": true,
	"cscli":    true,
}

// DecisionSource is the backend-agnostic contract for fetching active CrowdSec decisions.
type DecisionSource interface {
	// ListAlerts returns the raw list of alerts from cscli or LAPI.
	// Returns (nil, nil) when the source is empty (no active bans).
	// Returns (nil, err) on communication failure.
	ListAlerts(ctx context.Context) ([]RawAlert, error)
}

// RawAlert mirrors the top-level element in `cscli decisions list -o json` output.
// Each alert may contain one or more decisions.
type RawAlert struct {
	Decisions []RawDecision `json:"decisions"`
}

// RawDecision is one entry in the decisions array.
type RawDecision struct {
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Scenario string `json:"scenario"`
	Duration string `json:"duration"`
	ID       int64  `json:"id"`
}

// FilterActiveBanIPs applies the same filter as Python's get_active_bans():
//   - origin in LOCAL_ORIGINS ("crowdsec" or "cscli")
//   - type == "ban"
//   - scope.lower() == "ip"
//
// Deduplication is applied; order is not guaranteed.
func FilterActiveBanIPs(alerts []RawAlert) []string {
	seen := make(map[string]bool)
	var ips []string
	for _, alert := range alerts {
		for _, dec := range alert.Decisions {
			if !localOrigins[dec.Origin] {
				continue
			}
			if dec.Type != "ban" {
				continue
			}
			if strings.ToLower(dec.Scope) != "ip" {
				continue
			}
			if dec.Value == "" || seen[dec.Value] {
				continue
			}
			seen[dec.Value] = true
			ips = append(ips, dec.Value)
		}
	}
	return ips
}
