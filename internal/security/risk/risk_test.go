package risk

import (
	"testing"
	"time"
)

func TestFaviconOnlyObserve(t *testing.T) {
	a := Assess(Event{URIs: []string{"/favicon.ico"}, Hits: 1, Timestamp: time.Now().UTC()})
	if a.Decision != DecisionObserveOnly || a.AbuseType != CategoryBenignBootstrap {
		t.Fatalf("expected observe-only benign probe, got %+v", a)
	}
}

func TestBaselineAssetsOnlyObserve(t *testing.T) {
	a := Assess(Event{URIs: []string{"/", "/assets/site.css", "/favicon.ico"}, Hits: 3, Timestamp: time.Now().UTC()})
	if a.Decision != DecisionObserveOnly || a.AbuseType != CategoryBenignBootstrap {
		t.Fatalf("expected benign bootstrap observe-only, got %+v", a)
	}
}

func TestWordPressRepeatedSuspicious(t *testing.T) {
	a := Assess(Event{URIs: []string{"/wp-login.php", "/wp-login.php"}, Hits: 5, Timestamp: time.Now().UTC()})
	if a.AbuseType != CategoryWordPressProbe {
		t.Fatalf("unexpected abuse type: %+v", a)
	}
	if a.Score < 5 {
		t.Fatalf("expected elevated score, got %+v", a)
	}
}

func TestEnvAttemptHighRisk(t *testing.T) {
	a := Assess(Event{URIs: []string{"/.env"}, Hits: 1, Timestamp: time.Now().UTC()})
	if a.Score < 10 {
		t.Fatalf("expected high risk score, got %+v", a)
	}
}

// Scanner UAs (sqlmap, nikto, python-requests, curl) must not be suppressed as
// low_confidence even when score is in the 5–9 range: they receive a confidence
// floor of 0.75, above the 0.70 reporting threshold.
func TestKnownScannerUAConfidenceFloor(t *testing.T) {
	scannerUAs := []string{
		"sqlmap/1.7 (https://sqlmap.org)",
		"nikto/2.1.6",
		"python-requests/2.31.0",
		"curl/7.88.1",
	}
	for _, ua := range scannerUAs {
		a := Assess(Event{UserAgent: ua, Hits: 1, Timestamp: time.Now().UTC()})
		if a.AbuseType != CategoryScanner {
			t.Errorf("UA=%q: expected abuse_type=scanner, got %q", ua, a.AbuseType)
		}
		if a.Confidence < 0.70 {
			t.Errorf("UA=%q: confidence %.2f is below 0.70 threshold (score=%d)", ua, a.Confidence, a.Score)
		}
		if a.SuppressedLowSignal {
			t.Errorf("UA=%q: SuppressedLowSignal must be false for score>=5", ua)
		}
	}
}

// benign_probe events with score 5–9 and no scanner UA must remain suppressed.
func TestBenignProbeScoreFiveToNineRemainsLowConf(t *testing.T) {
	a := Assess(Event{URIs: []string{"/wp-login.php"}, Hits: 1, Timestamp: time.Now().UTC()})
	if a.Confidence >= 0.70 {
		t.Errorf("wordpress_probe without scanner UA should remain below 0.70 threshold, got %.2f", a.Confidence)
	}
}

func TestMixedBenignAndExploitExploitWins(t *testing.T) {
	a := Assess(Event{URIs: []string{"/favicon.ico", "/../../etc/passwd"}, Hits: 2, Timestamp: time.Now().UTC()})
	if a.AbuseType != CategoryExploitAttempt && a.AbuseType != CategoryConfirmedAbuse {
		t.Fatalf("expected exploit to win, got %+v", a)
	}
}

// CF Custom Rule block with a clean URI (no attack pattern) must not be
// suppressed as benign_signal: the operator explicitly blocked this traffic.
func TestCFCustomRuleBlockCleanURIReportable(t *testing.T) {
	a := Assess(Event{
		URIs:      []string{"/blog"},
		Action:    "block",
		Source:    "firewallCustom",
		Hits:      1,
		Timestamp: time.Now().UTC(),
	})
	if a.AbuseType == CategoryBenignProbe || a.AbuseType == CategoryBenignBootstrap {
		t.Errorf("CF custom rule block must not be benign, got %q", a.AbuseType)
	}
	if a.Confidence < 0.70 {
		t.Errorf("CF custom rule block confidence %.2f must be >= 0.70 (score=%d)", a.Confidence, a.Score)
	}
	if a.SuppressedLowSignal {
		t.Error("CF custom rule block must not be marked SuppressedLowSignal")
	}
}

// CF Custom Rule block on a bootstrap URI must NOT early-return as benign_bootstrap.
func TestCFCustomRuleBlockBootstrapURIReportable(t *testing.T) {
	a := Assess(Event{
		URIs:      []string{"/favicon.ico"},
		Action:    "block",
		Source:    "firewallCustom",
		Hits:      1,
		Timestamp: time.Now().UTC(),
	})
	if a.AbuseType == CategoryBenignBootstrap {
		t.Errorf("CF custom rule block must not be benign_bootstrap, got %q", a.AbuseType)
	}
	if a.Confidence < 0.70 {
		t.Errorf("expected confidence >= 0.70 for CF custom rule block, got %.2f", a.Confidence)
	}
}

// CF Managed Rule block must also be boosted.
func TestCFManagedRuleBlockReportable(t *testing.T) {
	a := Assess(Event{
		URIs:      []string{"/search?q=test"},
		Action:    "block",
		Source:    "firewallManaged",
		Hits:      1,
		Timestamp: time.Now().UTC(),
	})
	if a.Confidence < 0.70 {
		t.Errorf("CF managed rule block confidence %.2f must be >= 0.70", a.Confidence)
	}
}

// Non-block CF events (skip/allow) must NOT be boosted.
func TestCFSkipActionNotBoosted(t *testing.T) {
	a := Assess(Event{
		URIs:      []string{"/blog"},
		Action:    "skip",
		Source:    "firewallCustom",
		Hits:      1,
		Timestamp: time.Now().UTC(),
	})
	if a.Score >= 10 {
		t.Errorf("skip action must not receive CF block boost, got score=%d", a.Score)
	}
}
