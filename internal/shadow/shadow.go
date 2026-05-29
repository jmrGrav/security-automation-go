// Package shadow provides infrastructure for Go shadow-mode validation:
// Go computes sync plans without mutating Cloudflare, then compares
// each plan against Python's authoritative CF state.
//
// Success criterion: ≥ 99.9% plan equivalence over 7 consecutive days.
package shadow

import (
	"time"
)

// Cycle captures one complete shadow evaluation pass.
// Written to the cycle log as a JSONL record.
type Cycle struct {
	CycleAt time.Time `json:"cycle_at"`

	// Input state read from authoritative sources
	ActiveBanCount int `json:"active_ban_count"` // IPs from cscli
	CFRuleCount    int `json:"cf_rule_count"`    // CF rules with crowdsec-local-ban tag

	// Go's computed plan (what Go would do if authoritative)
	PlannedAdds    []string `json:"planned_adds"`    // in active_bans, not in CF
	PlannedDeletes []string `json:"planned_deletes"` // in CF, not in active_bans

	// Recidivist escalations Go would trigger
	RecidiveEscalations []RecidiveEscalation `json:"recidive_escalations,omitempty"`

	// CIDR /24 escalations Go would trigger
	CIDREscalations []CIDREscalation `json:"cidr_escalations,omitempty"`

	// Comparison metrics
	AgreementPct   float64  `json:"agreement_pct"`   // Jaccard similarity × 100
	FalsePositives []string `json:"false_positives"` // Go would add, Python hasn't
	FalseNegatives []string `json:"false_negatives"` // Python has, Go would remove
	InSync         bool     `json:"in_sync"`         // PlannedAdds and PlannedDeletes both empty

	// Drift explanation (populated when not InSync)
	DriftExplanation string `json:"drift_explanation,omitempty"`
}

// RecidiveEscalation describes one recidivist escalation Go would apply.
type RecidiveEscalation struct {
	IP       string `json:"ip"`
	Count    int    `json:"count"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// CIDREscalation describes one /24 CIDR ban Go would apply.
type CIDREscalation struct {
	CIDR    string   `json:"cidr"`
	IPCount int      `json:"ip_count"`
	IPs     []string `json:"ips"`
}

// Metrics aggregates multiple cycles for reporting.
type Metrics struct {
	TotalCycles      int
	InSyncCycles     int
	AgreementPctAvg  float64
	AgreementPctMin  float64
	TotalFalsePos    int
	TotalFalseNeg    int
	ConsecutiveSync  int // longest consecutive fully-in-sync run
	SevenDayPct      float64
	SevenDayEligible bool // true when ≥ 7 days of data exist
}

// SyncPlan is the output of a dry-run enforcement computation.
type SyncPlan struct {
	ActiveBans map[string]bool // normalized IPs from CrowdSec
	CFRules    map[string]bool // normalized IPs currently in CF with the watched tag
	ToAdd      []string        // ActiveBans - CFRules
	ToDelete   []string        // CFRules - ActiveBans (ip → ruleID not needed here)
}

// Compare builds a Cycle record from the Go plan and current CF state.
// falsePosExplanation lists known reasons Go's plan may diverge from Python's
// (used to annotate drift).
func Compare(plan SyncPlan, cycleAt time.Time) Cycle {
	c := Cycle{
		CycleAt:        cycleAt,
		ActiveBanCount: len(plan.ActiveBans),
		CFRuleCount:    len(plan.CFRules),
		PlannedAdds:    plan.ToAdd,
		PlannedDeletes: plan.ToDelete,
		FalsePositives: plan.ToAdd,    // Go would add, Python hasn't
		FalseNegatives: plan.ToDelete, // Python has, Go would remove
		InSync:         len(plan.ToAdd) == 0 && len(plan.ToDelete) == 0,
	}

	// Jaccard similarity: |A ∩ B| / |A ∪ B|
	intersection := 0
	for ip := range plan.ActiveBans {
		if plan.CFRules[ip] {
			intersection++
		}
	}
	unionSize := len(plan.ActiveBans) + len(plan.CFRules) - intersection
	if unionSize == 0 {
		c.AgreementPct = 100.0
	} else {
		c.AgreementPct = float64(intersection) / float64(unionSize) * 100.0
	}

	if !c.InSync {
		c.DriftExplanation = buildDriftExplanation(plan)
	}
	return c
}

// buildDriftExplanation produces a human-readable drift summary.
// Mirrors Python's categorization of drift causes.
func buildDriftExplanation(plan SyncPlan) string {
	if len(plan.ToAdd) > 0 && len(plan.ToDelete) == 0 {
		return "Go has more active bans than CF (likely anti-self-ban filter missing in Go, or timing)"
	}
	if len(plan.ToDelete) > 0 && len(plan.ToAdd) == 0 {
		return "CF has rules Go wouldn't add (ModSec/CIDR rules, or Python added before last CS cycle)"
	}
	return "bidirectional drift: check protected-IP filter and timing"
}

// ComputeMetrics computes aggregate statistics from a slice of cycles.
func ComputeMetrics(cycles []Cycle) Metrics {
	if len(cycles) == 0 {
		return Metrics{}
	}
	m := Metrics{
		TotalCycles:     len(cycles),
		AgreementPctMin: 100.0,
	}

	sum := 0.0
	currentRun := 0
	maxRun := 0

	// 7-day window: cycles within the last 7 days
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	sevenDaySum := 0.0
	sevenDayCount := 0

	for i, c := range cycles {
		_ = i
		sum += c.AgreementPct
		if c.AgreementPct < m.AgreementPctMin {
			m.AgreementPctMin = c.AgreementPct
		}
		m.TotalFalsePos += len(c.FalsePositives)
		m.TotalFalseNeg += len(c.FalseNegatives)
		if c.InSync {
			m.InSyncCycles++
			currentRun++
			if currentRun > maxRun {
				maxRun = currentRun
			}
		} else {
			currentRun = 0
		}
		if !c.CycleAt.Before(cutoff) {
			sevenDaySum += c.AgreementPct
			sevenDayCount++
		}
	}

	m.AgreementPctAvg = sum / float64(len(cycles))
	m.ConsecutiveSync = maxRun

	if sevenDayCount > 0 {
		m.SevenDayPct = sevenDaySum / float64(sevenDayCount)
	}
	// Eligible when data spans at least 7 days (order-independent).
	if len(cycles) > 1 {
		var oldest, newest time.Time
		for _, c := range cycles {
			if oldest.IsZero() || c.CycleAt.Before(oldest) {
				oldest = c.CycleAt
			}
			if newest.IsZero() || c.CycleAt.After(newest) {
				newest = c.CycleAt
			}
		}
		m.SevenDayEligible = newest.Sub(oldest) >= 7*24*time.Hour
	}

	return m
}
