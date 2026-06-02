package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/security/quota"
)

func TestTransport_RequestRecordsQuotaObservation(t *testing.T) {
	quota.ResetDefaultRegistry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Ratelimit", `"default";r=50;t=30`)
		w.Header().Set("Ratelimit-Policy", `"burst";q=100;w=60`)
		w.Header().Set("Retry-After", "12")
		w.Header().Set("ETag", `"abc123"`)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{}})
	}))
	defer srv.Close()

	tr := transport.New(&redirectingClient{base: srv.URL, inner: srv.Client()}, "tok")
	_, _, err := tr.Request(context.Background(), http.MethodGet, "/zones", nil, nil, "")
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}

	obs, ok := quota.DefaultRegistry().Get("cloudflare")
	if !ok {
		t.Fatal("expected cloudflare observation")
	}
	if obs.State != quota.Normal || obs.Remaining != 50 {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestTransport_RequestSuspendsMutationWhenQuotaExhausted(t *testing.T) {
	quota.ResetDefaultRegistry()
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:         "cloudflare",
		Plan:             "test",
		QuotaSource:      "test",
		LimitKnown:       true,
		Limit:            10,
		RemainingKnown:   true,
		Remaining:        0,
		UsedKnown:        true,
		Used:             10,
		PercentKnown:     true,
		RemainingPercent: 0,
		State:            quota.Exhausted,
	})

	tr := transport.New(&panicDoer{}, "tok")
	if _, _, err := tr.Request(context.Background(), http.MethodPost, "/zones", nil, nil, ""); err == nil {
		t.Fatal("expected exhausted quota to suspend mutation")
	}
}

type panicDoer struct{}

func (panicDoer) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	panic("quota guard should have short-circuited before HTTP call")
}
