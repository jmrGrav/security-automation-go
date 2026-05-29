package main

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

func TestExplainEvidence(t *testing.T) {
	ev := reporting.DecisionEvidence{
		EvidenceID:        "ev-1",
		Timestamp:         time.Date(2026, 5, 27, 16, 0, 0, 0, time.UTC),
		Source:            "cloudflare_waf",
		IP:                "198.51.100.10",
		URIs:              []string{"/wp-login.php", "/xmlrpc.php"},
		AbuseType:         "wordpress_probe",
		RiskScore:         12,
		Confidence:        0.95,
		Categories:        []string{"Bad Web Bot", "Web App Attack"},
		Decision:          "suppressed",
		SuppressionReason: "abuseipdb_recently_reported",
		Comment:           "Cloudflare WAF: ...",
		InputHash:         "input-hash",
		DecisionHash:      "decision-hash",
	}

	got := reporting.ExplainEvidence(ev)
	if got.Reason != "suppressed: abuseipdb_recently_reported" {
		t.Fatalf("unexpected reason: %+v", got)
	}
	if got.Decision != "suppressed" || got.EvidenceID != "ev-1" {
		t.Fatalf("unexpected explanation: %+v", got)
	}
}
