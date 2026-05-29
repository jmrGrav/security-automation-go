package abuseformat

import (
	"strings"
	"testing"
)

func TestBuildGoldenCloudflare(t *testing.T) {
	comment := Build(Input{
		Source:     SourceCloudflareWAF,
		Hits:       9,
		WindowSec:  300,
		Action:     "block",
		AbuseType:  "wordpress_probe",
		Categories: []string{"Web App Attack", "Bad Web Bot"},
		RuleID:     "xxx",
		URIs:       []string{"/wp-login.php", "/xmlrpc.php"},
		Confidence: 0.88,
	})
	want := "Cloudflare WAF: 9 hits in 300s | action=block | abuse=wordpress_probe | categories=Bad Web Bot,Web App Attack | rule_id=xxx | URIs=/wp-login.php,/xmlrpc.php | confidence=0.88"
	if comment != want {
		t.Fatalf("unexpected comment:\nwant: %s\ngot:  %s", want, comment)
	}
}

func TestBuildGoldenCrowdSec(t *testing.T) {
	comment := Build(Input{
		Source:     SourceCrowdSecWAF,
		Hits:       4,
		WindowSec:  120,
		Action:     "block",
		AbuseType:  "scanner",
		Categories: []string{"Bad Web Bot"},
		RuleID:     "crowdsec-1",
		URIs:       []string{"/login", "/login"},
		Confidence: 0.91,
	})
	want := "CrowdSec WAF: 4 hits in 120s | action=block | abuse=scanner | categories=Bad Web Bot | rule_id=crowdsec-1 | URIs=/login | confidence=0.91"
	if comment != want {
		t.Fatalf("unexpected comment:\nwant: %s\ngot:  %s", want, comment)
	}
}

func TestBuildGoldenOpenRestyMissingRuleID(t *testing.T) {
	comment := Build(Input{
		Source:     SourceOpenRestyWAF,
		Hits:       1,
		WindowSec:  30,
		Action:     "challenge",
		AbuseType:  "benign_probe",
		Categories: []string{"Bad Web Bot"},
		URIs:       []string{"/robots.txt"},
		Confidence: 0.12,
	})
	want := "OpenResty WAF: 1 hits in 30s | action=challenge | abuse=benign_probe | categories=Bad Web Bot | rule_id=unknown | URIs=/robots.txt | confidence=0.12"
	if comment != want {
		t.Fatalf("unexpected comment:\nwant: %s\ngot:  %s", want, comment)
	}
}

func TestBuildDedupsAndOrdersFields(t *testing.T) {
	comment := Build(Input{
		Source:     SourceCrowdSecWAF,
		Hits:       2,
		WindowSec:  30,
		Action:     "block",
		AbuseType:  "scanner",
		Categories: []string{"Web App Attack", "Bad Web Bot", "Bad Web Bot"},
		RuleID:     "r1",
		URIs:       []string{"/b", "/a", "/b"},
		Confidence: 0.90,
	})
	want := "CrowdSec WAF: 2 hits in 30s | action=block | abuse=scanner | categories=Bad Web Bot,Web App Attack | rule_id=r1 | URIs=/a,/b | confidence=0.90"
	if comment != want {
		t.Fatalf("unexpected comment:\nwant: %s\ngot:  %s", want, comment)
	}
}

func TestBuildPreservesSpecialURICharacters(t *testing.T) {
	comment := Build(Input{
		Source:     SourceCloudflareWAF,
		Hits:       1,
		WindowSec:  60,
		Action:     "block",
		AbuseType:  "exploit_attempt",
		Categories: []string{"Web App Attack"},
		RuleID:     "cf-special",
		URIs:       []string{"/search?q=%3Cscript%3E", "/search?q=%3Cscript%3E"},
		Confidence: 0.99,
	})
	want := "Cloudflare WAF: 1 hits in 60s | action=block | abuse=exploit_attempt | categories=Web App Attack | rule_id=cf-special | URIs=/search?q=%3Cscript%3E | confidence=0.99"
	if comment != want {
		t.Fatalf("unexpected comment:\nwant: %s\ngot:  %s", want, comment)
	}
}

func TestBuildTruncatesLongComment(t *testing.T) {
	comment := Build(Input{
		Source:     SourceOpenRestyWAF,
		Hits:       99,
		WindowSec:  300,
		Action:     "block",
		AbuseType:  "scanner",
		Categories: []string{"Bad Web Bot"},
		RuleID:     strings.Repeat("rule", 80),
		URIs:       []string{"/a", "/b", "/c", "/d", "/e", "/f", strings.Repeat("/x", 100)},
		Confidence: 0.80,
	})
	if !strings.HasSuffix(comment, "…") {
		t.Fatalf("expected ellipsis truncation, got %s", comment)
	}
	wantLen := maxCommentLength + len("…") - 1
	if len(comment) != wantLen {
		t.Fatalf("expected exact truncation byte length %d, got %d", wantLen, len(comment))
	}
}
