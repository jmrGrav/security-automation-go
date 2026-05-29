package reporting_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/adapters/crowdsecevent"
	"github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

func TestCanonicalCommentExactAcrossSources(t *testing.T) {
	now := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

	makeService := func() (*reporting.Service, *fakeReporter, *sinks.RecorderSink) {
		reporter := &fakeReporter{}
		recorder := &sinks.RecorderSink{}
		return reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute), reporter, recorder
	}

	type sourceCase struct {
		name       string
		source     abuseformat.Source
		event      classifier.Event
		want       string
		wantReport bool
	}

	crowdsecEvent, err := crowdsecevent.Normalize(crowdsecevent.RawEvent{
		IP: "8.8.8.8", Hostname: "arleo.eu", URIs: []string{"/wp-login.php", "/xmlrpc.php"},
		Action: "block", RuleID: "xxx", RuleName: "wordpress", Timestamp: now, Hits: 9, WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("normalize crowdsec: %v", err)
	}
	openrestyEvent, err := openrestyevent.Normalize(openrestyevent.RawEvent{
		IP: "8.8.8.8", Hostname: "arleo.eu", URIs: []string{"/wp-login.php", "/xmlrpc.php"},
		Action: "block", RuleID: "xxx", RuleName: "wordpress", Timestamp: now, Hits: 9, WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("normalize openresty: %v", err)
	}
	cloudflareEvent, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", Hostname: "arleo.eu", URI: "/wp-login.php", Action: "block", RuleID: "xxx", RuleName: "wordpress", Timestamp: now, Hits: 9, WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("normalize cloudflare: %v", err)
	}

	cases := []sourceCase{
		{
			name:       "crowdsec",
			source:     abuseformat.SourceCrowdSecWAF,
			event:      withURIs(crowdsecEvent, []string{"/wp-login.php", "/xmlrpc.php"}),
			want:       "CrowdSec WAF: 9 hits in 300s | action=block | abuse=wordpress_probe | categories=Bad Web Bot,Web App Attack | rule_id=xxx | URIs=/wp-login.php,/xmlrpc.php | confidence=0.82",
			wantReport: true,
		},
		{
			name:       "openresty",
			source:     abuseformat.SourceOpenRestyWAF,
			event:      withURIs(openrestyEvent, []string{"/wp-login.php", "/xmlrpc.php"}),
			want:       "OpenResty WAF: 9 hits in 300s | action=block | abuse=wordpress_probe | categories=Bad Web Bot,Web App Attack | rule_id=xxx | URIs=/wp-login.php,/xmlrpc.php | confidence=0.82",
			wantReport: true,
		},
		{
			name:       "cloudflare",
			source:     abuseformat.SourceCloudflareWAF,
			event:      cloudflareEvent,
			want:       "Cloudflare WAF: 9 hits in 300s | action=block | abuse=wordpress_probe | categories=Bad Web Bot,Web App Attack | rule_id=xxx | URIs=/wp-login.php | confidence=0.65",
			wantReport: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, _, _ := makeService()
			result, err := service.Process(context.Background(), reporting.Request{Source: tc.source, Event: tc.event})
			if err != nil {
				t.Fatalf("process: %v", err)
			}
			if result.Comment != tc.want {
				t.Fatalf("unexpected comment:\nwant: %s\ngot:  %s", tc.want, result.Comment)
			}
			if result.Reported != tc.wantReport {
				t.Fatalf("unexpected report decision: %+v", result)
			}
		})
	}
}

func TestSameURIFamilySameAbuseTypeAcrossSources(t *testing.T) {
	now := time.Now().UTC()
	crowdsecEvent, _ := crowdsecevent.Normalize(crowdsecevent.RawEvent{IP: "8.8.8.8", URIs: []string{"/wp-login.php"}, Timestamp: now, Hits: 9, WindowSec: 300})
	openrestyEvent, _ := openrestyevent.Normalize(openrestyevent.RawEvent{IP: "8.8.8.8", URIs: []string{"/wp-login.php"}, Timestamp: now, Hits: 9, WindowSec: 300})
	cloudflareEvent, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{IP: "8.8.8.8", URI: "/wp-login.php", Timestamp: now, Hits: 9, WindowSec: 300})

	cls1 := classifier.Classify(crowdsecEvent)
	cls2 := classifier.Classify(openrestyEvent)
	cls3 := classifier.Classify(cloudflareEvent)

	if cls1.AbuseType != cls2.AbuseType || cls2.AbuseType != cls3.AbuseType {
		t.Fatalf("abuse type drift: %s %s %s", cls1.AbuseType, cls2.AbuseType, cls3.AbuseType)
	}
}

func TestBenignBootstrapTelemetryOnly(t *testing.T) {
	service := reporting.New(&fakeReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/favicon.ico", Timestamp: time.Now().UTC(), Hits: 1, WindowSec: 300,
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.Reported {
		t.Fatalf("expected telemetry-only suppression, got %+v", result)
	}
}

func TestExploitAttemptReported(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	evidence := &fakeEvidenceStore{}
	service := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	service.SetEvidenceStore(evidence)
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: time.Now().UTC(), Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported || len(reporter.reports) != 1 {
		t.Fatalf("expected report, got %+v reports=%d", result, len(reporter.reports))
	}
	if !result.TelemetryEvent.AbuseIPDBReported || len(recorder.Events) != 1 {
		t.Fatalf("expected telemetry for report, got %+v %+v", result.TelemetryEvent, recorder.Events)
	}
	reportedEvidence := 0
	pendingEvidence := 0
	for _, ev := range evidence.evidence {
		if ev.Decision == "report_pending" {
			pendingEvidence++
		}
		if ev.Reported {
			reportedEvidence++
		}
	}
	if pendingEvidence != 1 || reportedEvidence != 1 {
		t.Fatalf("expected persisted report evidence, got %+v", evidence.evidence)
	}
}
