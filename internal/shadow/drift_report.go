package shadow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteDriftAnalysis generates SHADOW_DRIFT_ANALYSIS.md from cycle history.
// isProtected and allowlistIPs are used by the classifier; pass nil to skip.
func WriteDriftAnalysis(
	outputPath string,
	cycles []Cycle,
	isProtected func(string) bool,
	allowlistIPs map[string]bool,
) error {
	report := Classify(cycles, isProtected, allowlistIPs)
	content := buildDriftMarkdown(report, cycles)
	return atomicWrite(outputPath, content)
}

func buildDriftMarkdown(report ClassificationReport, cycles []Cycle) string {
	var b strings.Builder
	m := ComputeMetrics(cycles)

	b.WriteString("# Shadow Drift Analysis\n\n")
	fmt.Fprintf(&b, "**Generated:** %s  \n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Cycles analyzed:** %d  \n", report.CyclesAnalyzed)
	fmt.Fprintf(&b, "**Total divergent IPs:** %d  \n", report.TotalDriftEvents)
	fmt.Fprintf(&b, "**Average agreement:** %.2f%%  \n", m.AgreementPctAvg)
	b.WriteString("\n---\n\n")

	// Executive summary
	b.WriteString("## Executive Summary\n\n")
	b.WriteString("This report classifies every IP that appeared in Go's false-positive or\n")
	b.WriteString("false-negative sets during shadow execution. Classifications map to either\n")
	b.WriteString("a known Go gap, a timing difference, or unknown (requiring investigation).\n\n")
	b.WriteString("**Phase constraint:** Do NOT implement fixes during this evidence phase.\n\n")

	// Class breakdown table
	b.WriteString("## Drift by Classification\n\n")
	b.WriteString(PerClassSummary(report))
	b.WriteString("\n")

	// Explained by Go gaps
	if len(report.ExplainedByGoGaps) > 0 {
		b.WriteString("## Explained by Known Go Gaps\n\n")
		for _, gap := range report.ExplainedByGoGaps {
			fmt.Fprintf(&b, "- %s\n", gap)
		}
		b.WriteString("\n")
	}

	// Timing drift
	if report.TimingDriftCount > 0 {
		b.WriteString("## Timing Differences (Expected)\n\n")
		fmt.Fprintf(&b, "%d IP(s) appeared in only 1-2 cycles. These are transient and do not\n",
			report.TimingDriftCount)
		b.WriteString("indicate algorithmic divergence. Frequency naturally decreases as the\n")
		b.WriteString("shadow run accumulates more cycles.\n\n")
	}

	// Unexplained
	if report.UnexplainedCount > 0 {
		b.WriteString("## Unexplained Drift (Requires Investigation)\n\n")
		fmt.Fprintf(&b, "**%d IP(s)** could not be classified from cycle data alone.  \n", report.UnexplainedCount)
		b.WriteString("Manual steps for each:\n")
		b.WriteString("1. Check if IP is in CS allowlist: `cscli allowlists inspect my_allowlist | grep <ip>`\n")
		b.WriteString("2. Check CF rule tag: look up rule in Cloudflare dashboard for exact `notes` field\n")
		b.WriteString("3. Check Python WAL for last mutation: `grep <ip> /var/log/crowdsec/cf-sync.wal.jsonl`\n\n")
	}

	// Full IP table
	b.WriteString("## All Divergent IPs\n\n")
	if len(report.IPDrifts) == 0 {
		b.WriteString("_No divergent IPs detected. Go and Python are in full agreement._\n\n")
	} else {
		b.WriteString("| IP | Direction | Occurrences | Class | Risk | Owner |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, d := range report.IPDrifts {
			b.WriteString(FormatDriftTable(d) + "\n")
		}
		b.WriteString("\n")
		b.WriteString("**Direction:** FP = false positive (Go would add, Python hasn't); ")
		b.WriteString("FN = false negative (Python has in CF, Go would remove)\n\n")
	}

	// Remediation list
	items := BuildRemediationList(report)
	b.WriteString("## Remediation List (Evidence Phase — Do Not Fix)\n\n")
	b.WriteString("Items ranked by operational risk. All marked as **evidence only**.\n\n")
	if len(items) == 0 {
		b.WriteString("_No remediation items. No unexplained drift detected._\n\n")
	} else {
		b.WriteString("| Rank | Risk | Class | IP Count | Action |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, item := range items {
			fmt.Fprintf(&b, "| %d | %s | %s | %d | %s |\n",
				item.Rank, item.Risk, DriftClassLabel(item.DriftClass),
				item.Count, item.Action)
		}
		b.WriteString("\n")
		for _, item := range items {
			fmt.Fprintf(&b, "**%d. %s** (%s)\n\n", item.Rank,
				DriftClassLabel(item.DriftClass), item.Risk)
			fmt.Fprintf(&b, "%s\n\n", item.Explanation)
		}
	}

	return b.String()
}

func atomicWrite(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("atomicWrite mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return fmt.Errorf("atomicWrite write: %w", err)
	}
	return os.Rename(tmp, path)
}
