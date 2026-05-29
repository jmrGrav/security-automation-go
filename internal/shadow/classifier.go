package shadow

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// DriftClass categorizes why Go's plan diverges from Python's actual CF state.
type DriftClass string

const (
	// DriftProtectedIP: IP is in a protected range (RFC1918, CF, host own IP).
	// Should be zero after anti-self-ban wiring. Any occurrence = Go bug.
	DriftProtectedIP DriftClass = "protected_ip"

	// DriftAllowlist: IP is in CrowdSec allowlist.
	// Python filters allowlisted IPs before CF sync; Go's enforcement loop
	// currently does not check the allowlist. False positives expected until fixed.
	DriftAllowlist DriftClass = "allowlist_filter"

	// DriftConfidenceGate: IP's scenario falls below CF_MIN_CONFIDENCE threshold.
	// Python applies adaptive mitigation; Go does not. False positives expected.
	DriftConfidenceGate DriftClass = "confidence_gate"

	// DriftModSecRule: IP is in CF under "modsec-ban" tag — added by Python's
	// ModSec path, not the crowdsec-local-ban enforcement loop Go watches.
	// False negatives expected (Python has it, Go wouldn't add it under this tag).
	DriftModSecRule DriftClass = "modsec_rule"

	// DriftCIDRRule: IP falls inside a /24 CIDR block in CF under "crowdsec-cidr-ban".
	// Python bans the /24; Go's CIDR service is built but not yet wired to the sync daemon.
	DriftCIDRRule DriftClass = "cidr_rule"

	// DriftTiming: transient difference — CS decision changed between Python's last
	// cycle and Go's current read, or CF state hasn't converged yet.
	// Characterized by low recurrence (1-2 cycles).
	DriftTiming DriftClass = "timing"

	// DriftRuleCollapsing: Python collapses adjacent /32s into a /24 or smaller prefix;
	// Go would add individual IPs. Explains false negatives for collapsed ranges.
	DriftRuleCollapsing DriftClass = "rule_collapsing"

	// DriftUnknown: not classifiable from available data.
	DriftUnknown DriftClass = "unknown"
)

// DriftRisk is the operational severity of a drift class.
type DriftRisk string

const (
	DriftRiskHigh   DriftRisk = "HIGH"
	DriftRiskMedium DriftRisk = "MEDIUM"
	DriftRiskLow    DriftRisk = "LOW"
	DriftRiskInfo   DriftRisk = "INFO"
)

// IPDrift describes one IP's divergence history across multiple cycles.
type IPDrift struct {
	IP              string
	Direction       string // "false_positive" (Go would add) or "false_negative" (Go would remove)
	OccurrenceCount int    // how many cycles it appeared in
	FirstSeen       time.Time
	LastSeen        time.Time
	Classification  DriftClass
	Risk            DriftRisk
	Explanation     string
	// PythonBug is true when the drift is attributable to a Python deficiency
	// rather than a Go gap. Currently no known cases.
	PythonBug bool
}

// ClassificationReport is the full drift analysis output.
type ClassificationReport struct {
	GeneratedAt      time.Time
	CyclesAnalyzed   int
	TotalDriftEvents int

	// Per-class counts
	ClassCounts map[DriftClass]int

	// Per-IP analysis, sorted by risk then occurrence count
	IPDrifts []IPDrift

	// Known Go gaps that explain the observed drift
	ExplainedByGoGaps []string

	// Timing differences (low risk, expected)
	TimingDriftCount int

	// Unexplained drift (requires investigation)
	UnexplainedCount int
}

// Classify analyses cycle history and classifies each divergent IP.
// shield is used to detect protected-IP drift; allowlist is optional
// (pass nil to skip allowlist classification).
func Classify(
	cycles []Cycle,
	isProtected func(ip string) bool,
	allowlistIPs map[string]bool,
) ClassificationReport {
	report := ClassificationReport{
		GeneratedAt:    time.Now().UTC(),
		CyclesAnalyzed: len(cycles),
		ClassCounts:    make(map[DriftClass]int),
	}
	if len(cycles) == 0 {
		return report
	}

	type ipKey struct{ ip, dir string }
	tracker := make(map[ipKey]*IPDrift)

	for _, c := range cycles {
		for _, ip := range c.FalsePositives {
			k := ipKey{ip, "false_positive"}
			if tracker[k] == nil {
				tracker[k] = &IPDrift{
					IP: ip, Direction: "false_positive", FirstSeen: c.CycleAt,
				}
			}
			d := tracker[k]
			d.OccurrenceCount++
			d.LastSeen = c.CycleAt
		}
		for _, ip := range c.FalseNegatives {
			k := ipKey{ip, "false_negative"}
			if tracker[k] == nil {
				tracker[k] = &IPDrift{
					IP: ip, Direction: "false_negative", FirstSeen: c.CycleAt,
				}
			}
			d := tracker[k]
			d.OccurrenceCount++
			d.LastSeen = c.CycleAt
		}
	}

	report.TotalDriftEvents = len(tracker)

	for _, d := range tracker {
		classifyOne(d, isProtected, allowlistIPs)
		report.ClassCounts[d.Classification]++
		report.IPDrifts = append(report.IPDrifts, *d)
	}

	sort.Slice(report.IPDrifts, func(i, j int) bool {
		ri := riskOrder(report.IPDrifts[i].Risk)
		rj := riskOrder(report.IPDrifts[j].Risk)
		if ri != rj {
			return ri < rj
		}
		return report.IPDrifts[i].OccurrenceCount > report.IPDrifts[j].OccurrenceCount
	})

	report.TimingDriftCount = report.ClassCounts[DriftTiming]
	report.UnexplainedCount = report.ClassCounts[DriftUnknown]
	report.ExplainedByGoGaps = explainedByGoGaps(report.ClassCounts)

	return report
}

func classifyOne(d *IPDrift, isProtected func(string) bool, allowlistIPs map[string]bool) {
	ip := d.IP

	// 1. Protected IP (RFC1918, CF, host own IP) — should be zero since wiring
	if isProtected != nil && isProtected(ip) {
		d.Classification = DriftProtectedIP
		d.Risk = DriftRiskHigh
		d.Explanation = "IP is in a protected range (RFC1918/CF/host). " +
			"Anti-self-ban is wired in Go; if this appears it is a Go bug."
		return
	}

	// 2. Allowlist filter (false positive only — Go doesn't check CS allowlist yet)
	if d.Direction == "false_positive" && allowlistIPs != nil {
		if allowlistIPs[ip] {
			d.Classification = DriftAllowlist
			d.Risk = DriftRiskMedium
			d.Explanation = "IP is in CrowdSec allowlist. Python filters allowlisted IPs " +
				"before CF sync; Go enforcement loop missing allowlist check (known gap)."
			return
		}
	}

	// 3. CIDR range — IP falls inside a /24 in CF (false negative)
	if d.Direction == "false_negative" && isInsideCIDR(ip) {
		d.Classification = DriftCIDRRule
		d.Risk = DriftRiskLow
		d.Explanation = "IP is covered by a /24 CIDR rule in CF. Python bans /24 directly; " +
			"Go would ban the individual IP. cidrban.RealService not yet wired to daemon."
		return
	}

	// 4. Timing: low recurrence (≤ 2 cycles) — transient CS/CF state difference
	if d.OccurrenceCount <= 2 {
		d.Classification = DriftTiming
		d.Risk = DriftRiskLow
		d.Explanation = fmt.Sprintf(
			"Appeared in only %d cycle(s). Likely timing: CS decision changed between "+
				"Python's last sync and Go's current read.", d.OccurrenceCount)
		return
	}

	// 5. Persistent false positive (> 2 cycles) — likely confidence gate or unknown
	if d.Direction == "false_positive" {
		d.Classification = DriftConfidenceGate
		d.Risk = DriftRiskMedium
		d.Explanation = fmt.Sprintf(
			"Persistent false positive over %d cycles. Likely CF_MIN_CONFIDENCE gate "+
				"(Python filters low-confidence scenarios; Go does not).", d.OccurrenceCount)
		return
	}

	// 6. Persistent false negative — likely ModSec or rule collapsing
	if d.Direction == "false_negative" {
		d.Classification = DriftModSecRule
		d.Risk = DriftRiskLow
		d.Explanation = fmt.Sprintf(
			"Persistent false negative over %d cycles. Likely Python added this IP "+
				"via ModSec (modsec-ban tag) or CIDR path, not crowdsec-local-ban.", d.OccurrenceCount)
		return
	}

	d.Classification = DriftUnknown
	d.Risk = DriftRiskMedium
	d.Explanation = "Not classifiable from available cycle data. Manual investigation required."
}

// isInsideCIDR heuristic: checks whether ip is likely covered by a /24 ban by
// seeing if it has a private or repeated prefix pattern. Production version would
// check the CF API for CIDR rules — here we flag IPv4s that end in non-.1 octets
// as candidates. This is a heuristic, not authoritative.
func isInsideCIDR(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	return ip4 != nil && ip4[3] != 1 // rough heuristic: non-.1 host in a /24
}

func riskOrder(r DriftRisk) int {
	switch r {
	case DriftRiskHigh:
		return 0
	case DriftRiskMedium:
		return 1
	case DriftRiskLow:
		return 2
	default:
		return 3
	}
}

func explainedByGoGaps(counts map[DriftClass]int) []string {
	var gaps []string
	explanations := map[DriftClass]string{
		DriftProtectedIP:    "Anti-self-ban filter (now wired — should be zero)",
		DriftAllowlist:      "Allowlist filter missing in enforcement loop",
		DriftConfidenceGate: "CF_MIN_CONFIDENCE adaptive mitigation not ported",
		DriftModSecRule:     "ModSec AbuseIPDB reporting path uses different CF tag",
		DriftCIDRRule:       "cidrban.RealService not wired to sync daemon",
		DriftRuleCollapsing: "Rule collapsing (collapse_ips) not ported",
	}
	// Emit in risk order
	for _, cls := range []DriftClass{
		DriftProtectedIP, DriftAllowlist, DriftConfidenceGate,
		DriftCIDRRule, DriftRuleCollapsing, DriftModSecRule,
	} {
		if counts[cls] > 0 {
			gaps = append(gaps, fmt.Sprintf("%s — %d IPs: %s",
				cls, counts[cls], explanations[cls]))
		}
	}
	return gaps
}

// RemediationItem describes one remediation action ranked by risk.
type RemediationItem struct {
	Rank        int
	DriftClass  DriftClass
	Risk        DriftRisk
	Count       int
	Action      string
	DoNotFix    bool // true when this is a "collect evidence only" phase
	Explanation string
}

// BuildRemediationList returns remediation items ranked by operational risk.
// All items are marked DoNotFix=true per the "evidence only" mission constraint.
func BuildRemediationList(report ClassificationReport) []RemediationItem {
	type entry struct {
		cls     DriftClass
		risk    DriftRisk
		action  string
		explain string
	}
	candidates := []entry{
		{
			DriftProtectedIP, DriftRiskHigh,
			"Verify Shield.IsProtected() covers all management IPs/VPNs/bastions",
			"Any protected-IP drift is a P0 lockout risk. Verify coverage matches production topology.",
		},
		{
			DriftAllowlist, DriftRiskMedium,
			"Wire cs.ListAllowlist() filter into CrowdSecSyncApp.buildSyncPlan()",
			"IPs in CS allowlist should never be banned in CF. Currently Go skips this check.",
		},
		{
			DriftConfidenceGate, DriftRiskMedium,
			"Port Python's _should_sync_to_cf() / CF_MIN_CONFIDENCE gate",
			"Python excludes low-confidence scenarios. Go bans all active bans regardless of confidence.",
		},
		{
			DriftCIDRRule, DriftRiskLow,
			"Wire cidrban.RealService into CrowdSecSyncApp scheduler loop",
			"CIDR /24 escalation service is built but not called in the sync cycle.",
		},
		{
			DriftRuleCollapsing, DriftRiskLow,
			"Port Python's collapse_ips() to reduce individual /32 rules",
			"Python collapses adjacent IPs into prefix ranges. Go adds each IP individually.",
		},
		{
			DriftModSecRule, DriftRiskLow,
			"Add ModSec AbuseIPDB reporting (already built; verify tag match)",
			"Python's modsec-ban rules appear as false negatives. Verify tag routing.",
		},
	}

	var items []RemediationItem
	rank := 1
	for _, c := range candidates {
		count := report.ClassCounts[c.cls]
		if count == 0 {
			continue
		}
		items = append(items, RemediationItem{
			Rank:        rank,
			DriftClass:  c.cls,
			Risk:        c.risk,
			Count:       count,
			Action:      c.action,
			Explanation: c.explain,
			DoNotFix:    true, // evidence-only phase
		})
		rank++
	}
	// Unknown items always last
	if report.UnexplainedCount > 0 {
		items = append(items, RemediationItem{
			Rank:        rank,
			DriftClass:  DriftUnknown,
			Risk:        DriftRiskMedium,
			Count:       report.UnexplainedCount,
			Action:      "Investigate manually: check CS scenario, CF tag, and Python WAL",
			Explanation: "Cannot classify without runtime checks (allowlist, CF tag inspection).",
			DoNotFix:    true,
		})
	}
	return items
}

// DriftClassLabel returns a human-readable label for a drift class.
func DriftClassLabel(c DriftClass) string {
	labels := map[DriftClass]string{
		DriftProtectedIP:    "Protected IP",
		DriftAllowlist:      "Allowlist filter",
		DriftConfidenceGate: "Confidence gate",
		DriftModSecRule:     "ModSec rule",
		DriftCIDRRule:       "CIDR /24 rule",
		DriftTiming:         "Timing difference",
		DriftRuleCollapsing: "Rule collapsing",
		DriftUnknown:        "Unknown",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return string(c)
}

// DriftOwner maps a drift class to "Python bug", "Go gap", "Expected", or "Timing".
func DriftOwner(c DriftClass) string {
	owners := map[DriftClass]string{
		DriftProtectedIP:    "Go bug (should be zero after wiring)",
		DriftAllowlist:      "Go gap (known missing feature)",
		DriftConfidenceGate: "Go gap (known missing feature)",
		DriftModSecRule:     "Expected behavior difference",
		DriftCIDRRule:       "Go gap (service built, not wired)",
		DriftTiming:         "Timing difference (expected)",
		DriftRuleCollapsing: "Go gap (known missing feature)",
		DriftUnknown:        "Unknown — investigate",
	}
	if o, ok := owners[c]; ok {
		return o
	}
	return "Unknown"
}

// FormatDriftTable returns a markdown table row for one IPDrift.
func FormatDriftTable(d IPDrift) string {
	return fmt.Sprintf("| `%s` | %s | %d | %s | %s | %s |",
		d.IP, directionLabel(d.Direction), d.OccurrenceCount,
		DriftClassLabel(d.Classification), d.Risk, DriftOwner(d.Classification))
}

func directionLabel(dir string) string {
	if dir == "false_positive" {
		return "FP (Go extra)"
	}
	return "FN (Python extra)"
}

// PerClassSummary returns a compact summary of drift counts per class and owner.
func PerClassSummary(report ClassificationReport) string {
	var sb strings.Builder
	sb.WriteString("| Class | Count | Direction | Owner |\n")
	sb.WriteString("|---|---|---|---|\n")
	for _, cls := range []DriftClass{
		DriftProtectedIP, DriftAllowlist, DriftConfidenceGate,
		DriftCIDRRule, DriftRuleCollapsing, DriftModSecRule,
		DriftTiming, DriftUnknown,
	} {
		n := report.ClassCounts[cls]
		if n == 0 {
			continue
		}
		dir := "FP"
		if cls == DriftModSecRule || cls == DriftCIDRRule || cls == DriftRuleCollapsing {
			dir = "FN"
		} else if cls == DriftTiming || cls == DriftUnknown {
			dir = "mixed"
		}
		fmt.Fprintf(&sb, "| %s | %d | %s | %s |\n",
			DriftClassLabel(cls), n, dir, DriftOwner(cls))
	}
	return sb.String()
}
