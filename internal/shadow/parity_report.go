package shadow

import (
	"fmt"
	"strings"
	"time"
)

// ParityFeature describes one Python feature and its Go implementation status,
// cross-referenced with observed shadow drift.
type ParityFeature struct {
	Name          string
	PythonFunc    string
	GoLocation    string
	Status        string // "implemented", "partial", "missing"
	DriftClass    DriftClass
	DriftCount    int // IPs observed drifting due to this gap
	RiskIfMissing string
}

// WriteParityReport generates PYTHON_GO_PARITY_REPORT.md from cycle history.
// It cross-references observed drift with known feature gaps.
func WriteParityReport(outputPath string, cycles []Cycle, isProtected func(string) bool, allowlistIPs map[string]bool) error {
	driftReport := Classify(cycles, isProtected, allowlistIPs)
	m := ComputeMetrics(cycles)
	content := buildParityMarkdown(driftReport, m, cycles)
	return atomicWrite(outputPath, content)
}

func buildParityMarkdown(drift ClassificationReport, m Metrics, cycles []Cycle) string {
	var b strings.Builder

	b.WriteString("# Python ↔ Go Parity Report\n\n")
	fmt.Fprintf(&b, "**Generated:** %s  \n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "**Shadow cycles analyzed:** %d  \n", drift.CyclesAnalyzed)
	fmt.Fprintf(&b, "**Average agreement:** %.2f%%  \n", m.AgreementPctAvg)
	fmt.Fprintf(&b, "**7-day agreement:** ")
	if m.SevenDayEligible {
		fmt.Fprintf(&b, "%.2f%%  \n", m.SevenDayPct)
	} else {
		b.WriteString("collecting...  \n")
	}
	b.WriteString("\n---\n\n")

	b.WriteString("## Purpose\n\n")
	b.WriteString("This report maps each Python production feature to its Go equivalent,\n")
	b.WriteString("then cross-references observed shadow drift to quantify the real-world\n")
	b.WriteString("impact of each known gap. **Evidence only — no fixes during this phase.**\n\n")

	// Feature matrix with drift impact
	features := buildFeatureMatrix(drift.ClassCounts)

	b.WriteString("## Feature Parity with Observed Drift Impact\n\n")
	b.WriteString("| Feature | Python | Go | Status | Drift IPs | Risk |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, f := range features {
		statusIcon := statusIcon(f.Status)
		driftCol := "—"
		if f.DriftCount > 0 {
			driftCol = fmt.Sprintf("%d", f.DriftCount)
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s %s | %s | %s |\n",
			f.Name, f.PythonFunc, f.GoLocation, statusIcon, f.Status,
			driftCol, f.RiskIfMissing)
	}
	b.WriteString("\n")

	// Agreement breakdown by feature gap
	b.WriteString("## Drift Attribution by Feature Gap\n\n")
	b.WriteString("How much of the observed drift is explained by each Go gap:\n\n")
	totalDrift := drift.TotalDriftEvents
	if totalDrift == 0 {
		b.WriteString("**No drift observed. Full agreement detected.**\n\n")
	} else {
		b.WriteString("| Gap | Drift IPs | % of Total Drift | Classification |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, cls := range []DriftClass{
			DriftProtectedIP, DriftAllowlist, DriftConfidenceGate,
			DriftCIDRRule, DriftRuleCollapsing, DriftModSecRule,
			DriftTiming, DriftUnknown,
		} {
			n := drift.ClassCounts[cls]
			if n == 0 {
				continue
			}
			pct := float64(n) / float64(totalDrift) * 100
			fmt.Fprintf(&b, "| %s | %d | %.1f%% | %s |\n",
				DriftClassLabel(cls), n, pct, DriftOwner(cls))
		}
		b.WriteString("\n")
	}

	// False positive analysis
	fpTotal := drift.ClassCounts[DriftAllowlist] + drift.ClassCounts[DriftConfidenceGate] +
		drift.ClassCounts[DriftProtectedIP] + drift.ClassCounts[DriftUnknown]
	b.WriteString("## False Positive Analysis\n\n")
	b.WriteString("False positives = IPs Go would ban that Python correctly excludes.\n\n")
	fmt.Fprintf(&b, "- **Total false positive IPs:** %d\n", fpTotal)
	if drift.ClassCounts[DriftProtectedIP] > 0 {
		fmt.Fprintf(&b, "- Protected IP (P0 bug): %d — **INVESTIGATE IMMEDIATELY**\n",
			drift.ClassCounts[DriftProtectedIP])
	}
	fmt.Fprintf(&b, "- Allowlist filter gap: %d\n", drift.ClassCounts[DriftAllowlist])
	fmt.Fprintf(&b, "- Confidence gate gap: %d\n", drift.ClassCounts[DriftConfidenceGate])
	fmt.Fprintf(&b, "- Unknown: %d\n", drift.ClassCounts[DriftUnknown])
	b.WriteString("\n")

	// False negative analysis
	fnTotal := drift.ClassCounts[DriftModSecRule] + drift.ClassCounts[DriftCIDRRule] + drift.ClassCounts[DriftRuleCollapsing]
	b.WriteString("## False Negative Analysis\n\n")
	b.WriteString("False negatives = IPs Python has in CF that Go would remove.\n\n")
	fmt.Fprintf(&b, "- **Total false negative IPs:** %d\n", fnTotal)
	fmt.Fprintf(&b, "- ModSec rules (different CF tag): %d\n", drift.ClassCounts[DriftModSecRule])
	fmt.Fprintf(&b, "- CIDR /24 rules (not wired): %d\n", drift.ClassCounts[DriftCIDRRule])
	fmt.Fprintf(&b, "- Rule collapsing (Go would add /32s, Python collapses): %d\n",
		drift.ClassCounts[DriftRuleCollapsing])
	b.WriteString("\n")

	// Timing
	b.WriteString("## Timing Differences\n\n")
	fmt.Fprintf(&b, "- **Timing drift IPs:** %d (appear ≤ 2 cycles — not algorithmic)\n\n",
		drift.ClassCounts[DriftTiming])
	b.WriteString("Timing differences are expected and acceptable. They reflect the 60-second\n")
	b.WriteString("interval between Python and Go cycles, not algorithmic divergence.\n\n")

	// Migration readiness based on evidence
	b.WriteString("## Migration Readiness Assessment\n\n")
	b.WriteString("Based on observed evidence (not projections):\n\n")

	if !m.SevenDayEligible {
		b.WriteString("**STATUS: PENDING** — 7-day baseline not yet collected.\n\n")
	} else if m.SevenDayPct >= 99.9 {
		b.WriteString("**STATUS: CONDITIONAL GO** — 7-day agreement ≥ 99.9%.\n\n")
		b.WriteString("Before granting mutation authority:\n")
		b.WriteString("1. Confirm protected-IP drift = 0\n")
		b.WriteString("2. Wire allowlist filter (prevents banning allowlisted IPs)\n")
		b.WriteString("3. Confirm ModSec/CIDR false negatives are handled by their own tags\n\n")
	} else {
		fmt.Fprintf(&b, "**STATUS: NO-GO** — 7-day agreement %.2f%% below 99.9%% threshold.\n\n",
			m.SevenDayPct)
		b.WriteString("Remediation required before migration.\n\n")
	}

	// Defect table
	b.WriteString("## Defect Classification Table\n\n")
	b.WriteString("| Defect | Class | Python Bug? | Go Bug? | Expected? | Evidence Count |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	defects := []struct {
		name    string
		cls     DriftClass
		isPyBug bool
		isGoBug bool
		isExp   bool
	}{
		{"Protected IP in ban set", DriftProtectedIP, false, true, false},
		{"Allowlist IP banned", DriftAllowlist, false, true, false},
		{"Low-confidence scenario banned", DriftConfidenceGate, false, true, false},
		{"ModSec rule counted as FN", DriftModSecRule, false, false, true},
		{"/24 CIDR IP counted as FN", DriftCIDRRule, false, false, true},
		{"Timing transient", DriftTiming, false, false, true},
		{"Unknown divergence", DriftUnknown, false, false, false},
	}
	for _, d := range defects {
		count := drift.ClassCounts[d.cls]
		if count == 0 {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %d |\n",
			d.name, DriftClassLabel(d.cls),
			yesNo(d.isPyBug), yesNo(d.isGoBug), yesNo(d.isExp), count)
	}
	b.WriteString("\n")

	return b.String()
}

func buildFeatureMatrix(classCounts map[DriftClass]int) []ParityFeature {
	return []ParityFeature{
		{
			Name: "Active ban fetch", PythonFunc: "get_active_bans()", GoLocation: "crowdsec.Client.ListActiveBans()",
			Status: "implemented", DriftClass: DriftUnknown, DriftCount: 0, RiskIfMissing: "CRITICAL",
		},
		{
			Name: "Anti-self-ban", PythonFunc: "is_protected()", GoLocation: "security/protected.Shield",
			Status: "implemented", DriftClass: DriftProtectedIP, DriftCount: classCounts[DriftProtectedIP], RiskIfMissing: "P0 lockout",
		},
		{
			Name: "Allowlist filter", PythonFunc: "is_allowlisted()", GoLocation: "not wired in enforcement",
			Status: "partial", DriftClass: DriftAllowlist, DriftCount: classCounts[DriftAllowlist], RiskIfMissing: "HIGH",
		},
		{
			Name: "Confidence gate", PythonFunc: "_should_sync_to_cf()", GoLocation: "not ported",
			Status: "missing", DriftClass: DriftConfidenceGate, DriftCount: classCounts[DriftConfidenceGate], RiskIfMissing: "MEDIUM",
		},
		{
			Name: "Recidivist escalation", PythonFunc: "sync_recidivists()", GoLocation: "recidive.RealService",
			Status: "implemented", DriftClass: DriftUnknown, DriftCount: 0, RiskIfMissing: "MEDIUM",
		},
		{
			Name: "CIDR /24 auto-ban", PythonFunc: "sync_cidr_bans()", GoLocation: "cidrban.RealService (not wired)",
			Status: "partial", DriftClass: DriftCIDRRule, DriftCount: classCounts[DriftCIDRRule], RiskIfMissing: "MEDIUM",
		},
		{
			Name: "ModSecurity ban", PythonFunc: "sync_modsec()", GoLocation: "modsecurity.RealService",
			Status: "partial", DriftClass: DriftModSecRule, DriftCount: classCounts[DriftModSecRule], RiskIfMissing: "LOW",
		},
		{
			Name: "Rule collapsing", PythonFunc: "collapse_ips()", GoLocation: "not ported",
			Status: "missing", DriftClass: DriftRuleCollapsing, DriftCount: classCounts[DriftRuleCollapsing], RiskIfMissing: "LOW",
		},
		{
			Name: "CF rule cleanup", PythonFunc: "sync_cloudflare() to_delete", GoLocation: "app.CleanupApp.Run()",
			Status: "implemented", DriftClass: DriftUnknown, DriftCount: 0, RiskIfMissing: "MEDIUM",
		},
		{
			Name: "AbuseIPDB reporting", PythonFunc: "sync_abuseipdb()", GoLocation: "adapters/crowdsecevent + reporting",
			Status: "implemented", DriftClass: DriftUnknown, DriftCount: 0, RiskIfMissing: "LOW",
		},
		{
			Name: "WAF replay", PythonFunc: "poll_cloudflare_waf()", GoLocation: "adapters/cloudflareevent",
			Status: "implemented", DriftClass: DriftUnknown, DriftCount: 0, RiskIfMissing: "LOW",
		},
	}
}

func statusIcon(s string) string {
	switch s {
	case "implemented":
		return "✅"
	case "partial":
		return "⚠️"
	case "missing":
		return "❌"
	default:
		return "?"
	}
}

func yesNo(b bool) string {
	if b {
		return "✅"
	}
	return "—"
}
