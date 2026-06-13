package crowdsecevent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveSourceReadsRecentBansAndCorrelatesURIs(t *testing.T) {
	dir := t.TempDir()
	decisionsLog := filepath.Join(dir, "decisions.log")
	nginxDir := filepath.Join(dir, "nginx")
	if err := os.MkdirAll(nginxDir, 0755); err != nil {
		t.Fatalf("mkdir nginx dir: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	decisionLine := `{"dt":"` + now + `","cs":{"event_type":"decision","origin":"crowdsec","type":"ban","scenario":"crowdsecurity/http-sensitive-files","ip":"8.8.8.8","id":"abc"}}` + "\n"
	if err := os.WriteFile(decisionsLog, []byte(decisionLine), 0644); err != nil {
		t.Fatalf("write decisions log: %v", err)
	}
	accessLine := `8.8.8.8 - - [27/May/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 403 0 "-" "curl/8.0"` + "\n"
	if err := os.WriteFile(filepath.Join(nginxDir, "access.log"), []byte(accessLine), 0644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	source := NewLiveSource(decisionsLog, nginxDir, 24*time.Hour)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if len(events[0].URIs) != 1 || events[0].URIs[0] != "/.env" {
		t.Fatalf("unexpected URIs: %+v", events[0])
	}
}

func TestLiveSourceSkipsMalformedEntries(t *testing.T) {
	dir := t.TempDir()
	decisionsLog := filepath.Join(dir, "decisions.log")
	nginxDir := filepath.Join(dir, "nginx")
	if err := os.MkdirAll(nginxDir, 0755); err != nil {
		t.Fatalf("mkdir nginx dir: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	content := strings.Join([]string{
		`{"dt":"` + now + `","cs":{"event_type":"decision","origin":"crowdsec","type":"ban","scenario":"crowdsecurity/http-sensitive-files","ip":"8.8.8.8","id":"abc"}}`,
		`{"dt":"bad-time","cs":{"event_type":"decision","origin":"crowdsec","type":"ban","scenario":"crowdsecurity/http-sensitive-files","ip":"8.8.4.4","id":"def"}}`,
		`{"dt":"` + now + `","cs":{"event_type":"decision","origin":"crowdsec","type":"ban","scenario":"crowdsecurity/ssh-bf","ip":"8.8.4.4","id":"ghi"}}`,
	}, "\n") + "\n"
	if err := os.WriteFile(decisionsLog, []byte(content), 0644); err != nil {
		t.Fatalf("write decisions log: %v", err)
	}
	accessLine := `8.8.8.8 - - [27/May/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 403 0 "-" "curl/8.0"` + "\n"
	if err := os.WriteFile(filepath.Join(nginxDir, "access.log"), []byte(accessLine), 0644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	source := NewLiveSource(decisionsLog, nginxDir, 24*time.Hour)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// 8.8.8.8 has nginx URI; 8.8.4.4 (ssh-bf) has no nginx URI but must not
	// be silently dropped — Normalize() will use "unknown" as URI placeholder.
	if len(events) != 2 {
		t.Fatalf("expected 2 events (http + no-uri non-http ban), got %d", len(events))
	}
	var httpEvent, noURIEvent RawEvent
	for _, ev := range events {
		if ev.IP == "8.8.8.8" {
			httpEvent = ev
		} else {
			noURIEvent = ev
		}
	}
	if httpEvent.IP == "" || len(httpEvent.URIs) != 1 || httpEvent.URIs[0] != "/wp-login.php" {
		t.Fatalf("unexpected http event: %+v", httpEvent)
	}
	if noURIEvent.IP != "8.8.4.4" || len(noURIEvent.URIs) != 0 {
		t.Fatalf("unexpected no-uri event: %+v", noURIEvent)
	}
	if noURIEvent.RuleName != "crowdsecurity/ssh-bf" {
		t.Fatalf("expected rule_name to carry scenario as explicit ban reason, got %q", noURIEvent.RuleName)
	}
}

func TestAcceptDecision_CAPIOrigin(t *testing.T) {
	s := NewLiveSource("", "", 24*time.Hour)
	// CAPI (Community API) decisions must be accepted — they represent the majority
	// of real-world bans from the CrowdSec threat-intel community blocklist.
	if !s.acceptDecision("decision", "capi", "", "ban", "crowdsecurity/http-scan") {
		t.Error("CAPI origin must be accepted")
	}
	if !s.acceptDecision("decision", "crowdsec", "", "ban", "crowdsecurity/http-scan") {
		t.Error("crowdsec origin must still be accepted")
	}
	if !s.acceptDecision("decision", "cscli", "", "ban", "crowdsecurity/http-scan") {
		t.Error("cscli origin must still be accepted")
	}
	if s.acceptDecision("decision", "unknown", "", "ban", "crowdsecurity/http-scan") {
		t.Error("unknown origin must be rejected")
	}
	if s.acceptDecision("decision", "capi", "", "allow", "crowdsecurity/http-scan") {
		t.Error("non-ban type must be rejected")
	}
}

func TestLiveSourceAcceptsCAPIDecisions(t *testing.T) {
	dir := t.TempDir()
	decisionsLog := filepath.Join(dir, "decisions.log")
	now := time.Now().UTC().Format(time.RFC3339)
	// CAPI (Community API) bans — the majority of real-world CrowdSec decisions.
	content := `{"dt":"` + now + `","cs":{"event_type":"decision","origin":"CAPI","type":"ban","scenario":"http:scan","ip":"92.119.36.158","id":"14590968"}}` + "\n"
	if err := os.WriteFile(decisionsLog, []byte(content), 0644); err != nil {
		t.Fatalf("write decisions log: %v", err)
	}
	source := NewLiveSource(decisionsLog, "", 24*time.Hour)
	events, err := source.Read(context.Background())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 CAPI event, got %d — CAPI origin must not be rejected", len(events))
	}
	if events[0].IP != "92.119.36.158" {
		t.Errorf("unexpected IP: %s", events[0].IP)
	}
}

// Non-HTTP bans (SSH brute-force, raw TCP) have no nginx URI. Normalize must
// substitute "unknown" so the event passes through the pipeline.
func TestNormalizeEmptyURIsFallsBackToUnknown(t *testing.T) {
	ev, err := Normalize(RawEvent{
		IP:        "1.2.3.4",
		URIs:      nil,
		RuleID:    "ssh-1",
		RuleName:  "crowdsecurity/ssh-bf",
		Timestamp: time.Now().UTC(),
		Hits:      1,
		WindowSec: 3600,
	})
	if err != nil {
		t.Fatalf("Normalize with empty URIs must not error: %v", err)
	}
	if ev.URI != "unknown" || len(ev.URIs) != 1 || ev.URIs[0] != "unknown" {
		t.Fatalf("expected URI=unknown, got %+v", ev)
	}
}
