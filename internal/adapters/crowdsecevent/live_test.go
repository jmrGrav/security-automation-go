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

func TestLiveSourceSkipsMalformedAndUncorrelatedEntries(t *testing.T) {
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
		`{"dt":"` + now + `","cs":{"event_type":"decision","origin":"crowdsec","type":"ban","scenario":"crowdsecurity/http-sensitive-files","ip":"8.8.4.4","id":"ghi"}}`,
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
	if len(events) != 1 {
		t.Fatalf("expected only one correlated valid event, got %d", len(events))
	}
	if events[0].IP != "8.8.8.8" || events[0].URIs[0] != "/wp-login.php" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}
