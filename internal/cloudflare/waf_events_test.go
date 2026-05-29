package cloudflare_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/fixtures"
	"github.com/jm/security-automation-go/internal/httpclient"
)

func TestDiscovery_WAFEvents_GraphQLReplay(t *testing.T) {
	fixture := fixtures.SanitizedFixture{
		SourceFixtureID: "waf-events",
		ResponseStatus:  http.StatusOK,
		ResponseBody: []byte(`{
			"data": {
				"viewer": {
					"zones": [{
						"firewallEventsAdaptive": [{
							"action": "block",
							"clientIP": "8.8.8.8",
							"clientRequestPath": "/wp-login.php",
							"clientRequestQuery": "",
							"host": "arleo.eu",
							"datetime": "2026-05-27T10:00:00Z",
							"source": "waf",
							"userAgent": "Mozilla/5.0",
							"ruleId": "cf-rule-1",
							"description": "WordPress probe"
						}]
					}]
				}
			}
		}`),
	}
	fixture.IntegrityHash = fixtures.IntegrityHashSanitized(fixture)
	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{fixture}, fixtures.ReplayMetadata{
		Ordering: []string{"waf-events"},
	})
	doer := fixtures.NewReplayDoer(engine)

	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	cf := client.New("fake-token", hc)

	events, err := cf.ListWAFEventsSince(context.Background(), "zone-id", time.Date(2026, 5, 27, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("list waf events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].RuleID != "cf-rule-1" || events[0].Host != "arleo.eu" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestDiscovery_WAFEvents_GraphQLReplayHandlesSparseFields(t *testing.T) {
	fixture := fixtures.SanitizedFixture{
		SourceFixtureID: "waf-events-sparse",
		ResponseStatus:  http.StatusOK,
		ResponseBody: []byte(`{
			"data": {
				"viewer": {
					"zones": [{
						"firewallEventsAdaptive": [{
							"action": "managed_challenge",
							"clientIP": "8.8.4.4",
							"clientRequestPath": "/xmlrpc.php",
							"clientRequestQuery": "",
							"host": "arleo.eu",
							"datetime": "2026-05-27T10:05:00Z",
							"source": "waf"
						}]
					}]
				}
			}
		}`),
	}
	fixture.IntegrityHash = fixtures.IntegrityHashSanitized(fixture)
	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{fixture}, fixtures.ReplayMetadata{
		Ordering: []string{"waf-events-sparse"},
	})
	doer := fixtures.NewReplayDoer(engine)

	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	cf := client.New("fake-token", hc)

	events, err := cf.ListWAFEventsSince(context.Background(), "zone-id", time.Date(2026, 5, 27, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("list waf events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one sparse event, got %d", len(events))
	}
	if events[0].UserAgent != "" || events[0].RuleID != "" {
		t.Fatalf("expected sparse fields to stay empty, got %+v", events[0])
	}
}
