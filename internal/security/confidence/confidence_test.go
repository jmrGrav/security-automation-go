package confidence

import "testing"

func TestScoreLowConfidenceRequiresReview(t *testing.T) {
	res := Score([]Evidence{
		{Source: "appsec", Category: "timeout", Weight: 0.30, Penalty: 0.15, ReplayToken: "evt-1"},
	}, "appsec", DefaultPolicy())

	if !res.RequiresHumanReview {
		t.Fatal("expected low-confidence decision to require review")
	}
	if res.AllowHardDeny {
		t.Fatal("expected low-confidence decision to block hard deny")
	}
	if res.AllowGlobalAction {
		t.Fatal("expected low-confidence decision to block global action")
	}
}

func TestScoreHighConfidenceAllowsEscalation(t *testing.T) {
	res := Score([]Evidence{
		{Source: "crowdsec", Category: "correlated", Weight: 0.95, ReplayToken: "evt-1"},
		{Source: "lua", Category: "honeypot", Weight: 0.96, ReplayToken: "evt-2"},
	}, "bot", DefaultPolicy())

	if res.RequiresHumanReview {
		t.Fatal("expected high-confidence decision to avoid human review")
	}
	if !res.AllowHardDeny {
		t.Fatal("expected high-confidence decision to allow hard deny")
	}
}
