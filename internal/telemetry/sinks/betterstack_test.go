package sinks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

func TestBetterStackSinkPublishesStableJSON(t *testing.T) {
	var (
		authHeader string
		payload    map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	sink := NewBetterStack(betterstack.NewClient(httpclient.New(config.HTTPConfig{}), "super-secret", srv.URL))
	err := sink.Publish(context.Background(), tmevents.SecurityEvent{
		Timestamp:         time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Source:            "cloudflare_waf",
		IP:                "8.8.8.8",
		URI:               "/xmlrpc.php",
		Hostname:          "arleo.eu",
		RuleID:            "cf-1",
		AbuseType:         "wordpress_probe",
		RiskScore:         8,
		Confidence:        0.82,
		EnforcementStage:  "soft_mitigation",
		AbuseIPDBReported: true,
		Severity:          "warning",
		Metadata:          map[string]any{"canonical_comment": "Cloudflare WAF: ..."},
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if authHeader != "Bearer super-secret" {
		t.Fatalf("unexpected auth header: %s", authHeader)
	}
	if payload["source"] != "cloudflare_waf" || payload["abuse_type"] != "wordpress_probe" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), "super-secret") {
		t.Fatal("token leaked into payload")
	}
}

func TestBetterStackSinkTimeoutErrorReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := betterstack.NewClient(httpclient.New(config.HTTPConfig{Timeout: 10 * time.Millisecond, RetryMax: 1}), "secret", srv.URL)
	sink := NewBetterStack(client)
	err := sink.Publish(context.Background(), tmevents.SecurityEvent{Source: "cloudflare_waf", Severity: "warning"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
