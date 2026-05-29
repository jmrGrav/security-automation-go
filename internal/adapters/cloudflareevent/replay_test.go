package cloudflareevent

import (
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	event, err := Normalize(RawEvent{
		IP:        "1.2.3.4",
		URI:       "/wp-login.php",
		Action:    "block",
		RuleID:    "r1",
		RuleName:  "wordpress",
		Source:    "cloudflare",
		Timestamp: time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC),
		Hits:      9,
		WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.Source != "cloudflare" {
		t.Fatalf("unexpected source: %s", event.Source)
	}
}
