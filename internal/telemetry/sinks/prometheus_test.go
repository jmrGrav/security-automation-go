package sinks

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestPrometheusSinkSuppressedAndReportedMetrics(t *testing.T) {
	sink := NewPrometheus()

	if err := sink.Publish(context.Background(), tmevents.SecurityEvent{
		Source:            "cloudflare_waf",
		AbuseType:         "benign_bootstrap",
		RiskScore:         1,
		EnforcementStage:  "observe_only",
		SuppressionReason: "benign_signal",
		Severity:          "info",
	}); err != nil {
		t.Fatalf("publish suppressed: %v", err)
	}
	if err := sink.Publish(context.Background(), tmevents.SecurityEvent{
		Source:            "cloudflare_waf",
		AbuseType:         "confirmed_abuse",
		RiskScore:         24,
		EnforcementStage:  "propagable_ban",
		AbuseIPDBReported: true,
		Severity:          "critical",
	}); err != nil {
		t.Fatalf("publish reported: %v", err)
	}

	handler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	out := string(body)

	if !strings.Contains(out, "security_false_positive_suppressed_total") {
		t.Fatal("expected suppression metric exposed")
	}
	if !strings.Contains(out, "security_hard_ban_allowed_total") {
		t.Fatal("expected hard ban metric exposed")
	}
}
