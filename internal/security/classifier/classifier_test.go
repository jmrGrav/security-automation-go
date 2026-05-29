package classifier

import (
	"testing"
	"time"
)

func TestClassifyWordpressProbe(t *testing.T) {
	cls := Classify(Event{
		URI:       "/wp-login.php",
		UserAgent: "Mozilla/5.0",
		Hits:      9,
		Timestamp: time.Now().UTC(),
	})
	if cls.AbuseType != "wordpress_probe" {
		t.Fatalf("unexpected abuse type: %s", cls.AbuseType)
	}
	if cls.Confidence < 0.65 {
		t.Fatalf("expected high confidence, got %f", cls.Confidence)
	}
	if cls.EnforcementStage == "" {
		t.Fatal("expected enforcement stage")
	}
	if cls.RiskScore < 5 {
		t.Fatalf("expected elevated risk score, got %d", cls.RiskScore)
	}
	if len(cls.Categories) == 0 {
		t.Fatal("expected mapped categories")
	}
}

func TestClassifyBenignBootstrap(t *testing.T) {
	cls := Classify(Event{
		URI:       "/favicon.ico",
		UserAgent: "",
		Hits:      1,
		Timestamp: time.Now().UTC(),
	})
	if cls.AbuseType != "benign_bootstrap" {
		t.Fatalf("unexpected abuse type: %s", cls.AbuseType)
	}
	if cls.EnforcementStage != "observe_only" {
		t.Fatalf("unexpected enforcement stage: %s", cls.EnforcementStage)
	}
	if len(cls.Categories) != 0 {
		t.Fatalf("expected no AbuseIPDB categories, got %v", cls.Categories)
	}
	if !cls.SuspectedLowConf {
		t.Fatal("expected benign bootstrap to be low confidence")
	}
}
