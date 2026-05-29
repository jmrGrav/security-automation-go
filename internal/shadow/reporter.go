package shadow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const successThreshold = 99.9 // %

// WriteReport generates SHADOW_MODE_REPORT.md from cycle history.
// The report is written atomically to avoid partial reads.
func WriteReport(outputPath string, cycles []Cycle) error {
	if len(cycles) == 0 {
		return nil
	}
	m := ComputeMetrics(cycles)
	content := buildMarkdown(cycles, m)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("shadow.WriteReport: mkdir: %w", err)
	}
	tmp := outputPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return fmt.Errorf("shadow.WriteReport: write: %w", err)
	}
	return os.Rename(tmp, outputPath)
}

func buildMarkdown(cycles []Cycle, m Metrics) string {
	var b strings.Builder
	now := time.Now().UTC()
	last := cycles[len(cycles)-1]

	// Header
	b.WriteString("# Shadow Mode Validation Report\n\n")
	fmt.Fprintf(&b, "**Generated:** %s  \n", now.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Cycles recorded:** %d  \n", m.TotalCycles)
	if len(cycles) > 1 {
		span := cycles[len(cycles)-1].CycleAt.Sub(cycles[0].CycleAt)
		fmt.Fprintf(&b, "**Data span:** %s  \n", span.Round(time.Minute))
	}
	b.WriteString("\n---\n\n")

	// Current status
	b.WriteString("## Current Status\n\n")
	statusLine := "✅ IN SYNC"
	if !last.InSync {
		statusLine = "⚠️ DRIFT DETECTED"
	}
	fmt.Fprintf(&b, "**Status:** %s  \n", statusLine)
	fmt.Fprintf(&b, "**Last cycle:** %s  \n", last.CycleAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Active bans:** %d  \n", last.ActiveBanCount)
	fmt.Fprintf(&b, "**CF rules:** %d  \n", last.CFRuleCount)
	fmt.Fprintf(&b, "**Agreement:** %.2f%%  \n", last.AgreementPct)
	if !last.InSync && last.DriftExplanation != "" {
		fmt.Fprintf(&b, "**Drift cause:** %s  \n", last.DriftExplanation)
	}
	b.WriteString("\n")

	// Success criterion
	b.WriteString("## Success Criterion\n\n")
	b.WriteString("| Criterion | Target | Current | Status |\n")
	b.WriteString("|---|---|---|---|\n")
	sevenDayStatus := "⏳ Collecting data"
	if m.SevenDayEligible {
		if m.SevenDayPct >= successThreshold {
			sevenDayStatus = "✅ PASS"
		} else {
			sevenDayStatus = "❌ FAIL"
		}
	}
	fmt.Fprintf(&b, "| 7-day agreement | ≥%.1f%% | %.2f%% | %s |\n",
		successThreshold, m.SevenDayPct, sevenDayStatus)
	fmt.Fprintf(&b, "| All-time average | ≥%.1f%% | %.2f%% | %s |\n",
		successThreshold, m.AgreementPctAvg, passOrFail(m.AgreementPctAvg >= successThreshold))
	fmt.Fprintf(&b, "| Consecutive in-sync | max streak | %d cycles | — |\n", m.ConsecutiveSync)
	b.WriteString("\n")

	// Aggregate metrics
	b.WriteString("## Aggregate Metrics\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|---|---|\n")
	fmt.Fprintf(&b, "| Total cycles | %d |\n", m.TotalCycles)
	fmt.Fprintf(&b, "| In-sync cycles | %d (%.1f%%) |\n", m.InSyncCycles,
		pct(m.InSyncCycles, m.TotalCycles))
	fmt.Fprintf(&b, "| Average agreement | %.2f%% |\n", m.AgreementPctAvg)
	fmt.Fprintf(&b, "| Minimum agreement | %.2f%% |\n", m.AgreementPctMin)
	fmt.Fprintf(&b, "| Total false positives | %d |\n", m.TotalFalsePos)
	fmt.Fprintf(&b, "| Total false negatives | %d |\n", m.TotalFalseNeg)
	b.WriteString("\n")

	// Last 20 cycles table
	b.WriteString("## Recent Cycles\n\n")
	b.WriteString("| Timestamp | Active Bans | CF Rules | Agreement | To Add | To Delete | In Sync |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	start := 0
	if len(cycles) > 20 {
		start = len(cycles) - 20
	}
	for _, c := range cycles[start:] {
		syncCol := "✅"
		if !c.InSync {
			syncCol = "⚠️"
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %.1f%% | %d | %d | %s |\n",
			c.CycleAt.Format("2006-01-02 15:04:05"),
			c.ActiveBanCount, c.CFRuleCount,
			c.AgreementPct,
			len(c.PlannedAdds), len(c.PlannedDeletes),
			syncCol,
		)
	}
	b.WriteString("\n")

	// Drift details from last cycle
	if !last.InSync {
		b.WriteString("## Current Drift Details\n\n")
		if len(last.FalsePositives) > 0 {
			b.WriteString("### False Positives (Go would ban, Python hasn't)\n\n")
			b.WriteString("These IPs are in CrowdSec active bans but not in Cloudflare rules.\n")
			b.WriteString("Likely causes: anti-self-ban filter, allowlist filter, confidence gate.\n\n")
			for _, ip := range last.FalsePositives {
				fmt.Fprintf(&b, "- `%s`\n", ip)
			}
			b.WriteString("\n")
		}
		if len(last.FalseNegatives) > 0 {
			b.WriteString("### False Negatives (Python has in CF, Go would remove)\n\n")
			b.WriteString("These IPs are in Cloudflare rules but not in CrowdSec active bans.\n")
			b.WriteString("Likely causes: ModSec bans, CIDR bans, Python already acted before CS cleared the decision.\n\n")
			for _, ip := range last.FalseNegatives {
				fmt.Fprintf(&b, "- `%s`\n", ip)
			}
			b.WriteString("\n")
		}
	}

	// Recidive escalations
	if len(last.RecidiveEscalations) > 0 {
		b.WriteString("## Recidivist Escalations (Last Cycle)\n\n")
		b.WriteString("| IP | Count | Duration | Scenario |\n")
		b.WriteString("|---|---|---|---|\n")
		for _, r := range last.RecidiveEscalations {
			fmt.Fprintf(&b, "| `%s` | %d | %s | %s |\n", r.IP, r.Count, r.Duration, r.Scenario)
		}
		b.WriteString("\n")
	}

	// CIDR escalations
	if len(last.CIDREscalations) > 0 {
		b.WriteString("## CIDR /24 Escalations (Last Cycle)\n\n")
		b.WriteString("| CIDR | IP Count |\n")
		b.WriteString("|---|---|\n")
		for _, c := range last.CIDREscalations {
			fmt.Fprintf(&b, "| `%s` | %d |\n", c.CIDR, c.IPCount)
		}
		b.WriteString("\n")
	}

	// Migration readiness
	b.WriteString("## Migration Readiness\n\n")
	if m.SevenDayEligible && m.SevenDayPct >= successThreshold {
		b.WriteString("**GO — Ready for controlled authority.**  \n")
		b.WriteString("7-day agreement ≥ 99.9%. Go can be granted mutation authority for `crowdsec-local-ban` rules.\n")
	} else if m.SevenDayEligible {
		fmt.Fprintf(&b, "**NO-GO — Agreement %.2f%% below 99.9%% threshold.**  \n", m.SevenDayPct)
		b.WriteString("Investigate drift causes before granting mutation authority.\n")
	} else {
		b.WriteString("**PENDING — Collecting 7-day baseline.**  \n")
		if len(cycles) > 0 {
			elapsed := now.Sub(cycles[0].CycleAt)
			remaining := 7*24*time.Hour - elapsed
			if remaining > 0 {
				fmt.Fprintf(&b, "Approximately %s remaining before eligibility.\n", remaining.Round(time.Hour))
			}
		}
	}
	b.WriteString("\n")

	return b.String()
}

func passOrFail(ok bool) string {
	if ok {
		return "✅ PASS"
	}
	return "❌ FAIL"
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
