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

func TestMixedBenignAndExploitExploitWins(t *testing.T) {
	a := Assess(Event{URIs: []string{"/favicon.ico", "/../../etc/passwd"}, Hits: 2, Timestamp: time.Now().UTC()})
	if a.AbuseType != CategoryExploitAttempt && a.AbuseType != CategoryConfirmedAbuse {
		t.Fatalf("expected exploit to win, got %+v", a)
	}
}
