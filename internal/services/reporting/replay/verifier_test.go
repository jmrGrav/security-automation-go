package replay_test

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/services/reporting/replay"
)

func TestVerifyReplayOK(t *testing.T) {
	now := time.Date(2026, 5, 27, 16, 0, 0, 0, time.UTC)
	event := classifier.Event{
		IP:        "198.51.100.10",
		Hostname:  "example.com",
		URI:       "/wp-login.php",
		URIs:      []string{"/wp-login.php", "/xmlrpc.php"},
		Action:    "block",
		RuleID:    "cf-rule-1",
		Hits:      9,
		WindowSec: 300,
		Timestamp: now,
	}
	source := abuseformat.SourceCloudflareWAF
	req := reporting.Request{Source: source, Event: event}
	cls := classifier.Classify(event)
	comment := abuseformat.Build(abuseformat.Input{
		Source:     source,
		Hits:       event.Hits,
		WindowSec:  event.WindowSec,
		Action:     event.Action,
		AbuseType:  cls.AbuseType,
		Categories: cls.Categories,
		RuleID:     event.RuleID,
		URIs:       event.URIs,
		Confidence: cls.Confidence,
	})

	ev := reporting.DecisionEvidence{
		EvidenceID:        "ev-1",
		Timestamp:         now,
		Source:            "cloudflare_waf",
		IP:                event.IP,
		Comment:           comment,
		Decision:          "reported",
		Reported:          true,
		ClassifierVersion: reporting.ClassifierVersion,
		FormatterVersion:  reporting.FormatterVersion,
		PolicyVersion:     reporting.PolicyVersion,
		InputHash:         reporting.ReplayInputHash(req),
		DecisionHash:      reporting.ReplayDecisionHash(comment, cls, "reported", ""),
		NormalizedEvent:   event,
	}

	result := replay.Verify(ev)
	if !result.ReplayOK {
		t.Fatalf("expected replay ok, got %+v", result)
	}
}

func TestVerifyReplayMismatchAndMissingContext(t *testing.T) {
	ev := reporting.DecisionEvidence{
		EvidenceID:      "ev-2",
		Source:          "cloudflare_waf",
		Comment:         "bad",
		Decision:        "suppressed",
		InputHash:       "x",
		DecisionHash:    "y",
		NormalizedEvent: classifier.Event{},
	}
	result := replay.Verify(ev)
	if !result.MissingContext {
		t.Fatalf("expected missing context, got %+v", result)
	}
}

func TestVerifyReplayVersionDrift(t *testing.T) {
	ev := reporting.DecisionEvidence{
		EvidenceID:        "ev-3",
		Source:            "cloudflare_waf",
		Comment:           "x",
		Decision:          "reported",
		InputHash:         "x",
		DecisionHash:      "y",
		ClassifierVersion: "classifier/old",
		FormatterVersion:  reporting.FormatterVersion,
		PolicyVersion:     reporting.PolicyVersion,
		NormalizedEvent: classifier.Event{
			IP: "198.51.100.10", URI: "/wp-login.php", Timestamp: time.Now().UTC(),
		},
	}
	result := replay.Verify(ev)
	if !result.VersionDrift {
		t.Fatalf("expected version drift, got %+v", result)
	}
}
