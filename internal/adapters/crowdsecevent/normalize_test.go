package crowdsecevent

import (
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	ev, err := Normalize(RawEvent{
		IP:        "1.2.3.4",
		Hostname:  "arleo.eu",
		URIs:      []string{"/wp-login.php", "/xmlrpc.php"},
		Action:    "block",
		RuleID:    "crowdsec-1",
		RuleName:  "wordpress",
		Timestamp: time.Now().UTC(),
		Hits:      9,
		WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(ev.URIs) != 2 || ev.URI != "/wp-login.php" {
		t.Fatalf("unexpected normalized event: %+v", ev)
	}
}
