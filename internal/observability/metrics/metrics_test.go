package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestMetricsExposition(t *testing.T) {
	// 1. Reset metrics if possible or just increment to test
	ReconciliationRunsTotal.Inc()
	BreakerState.Set(1)

	// 2. Setup promhttp handler with our registry
	handler := promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// 3. Scrape metrics
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to scrape metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	out := string(body)

	// 4. Verify presence of our metrics
	if !strings.Contains(out, "reconciliation_runs_total") {
		t.Error("expected reconciliation_runs_total in output")
	}
	if !strings.Contains(out, "breaker_state") {
		t.Error("expected breaker_state in output")
	}
}

func TestLabelStability(t *testing.T) {
	// Verify that CounterVec works with predefined labels
	MutationOperationsTotal.WithLabelValues("create").Inc()
	MutationOperationsTotal.WithLabelValues("delete").Inc()

	handler := promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to scrape metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	out := string(body)

	if !strings.Contains(out, `mutation_operations_total{type="create"}`) {
		t.Error("expected create label in output")
	}
	if !strings.Contains(out, `mutation_operations_total{type="delete"}`) {
		t.Error("expected delete label in output")
	}
}
