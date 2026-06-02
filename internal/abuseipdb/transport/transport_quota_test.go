package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type redirectingClient struct {
	base  string
	inner *http.Client
}

func (c *redirectingClient) Do(req *http.Request) (*http.Response, error) {
	parsed, _ := url.Parse(c.base)
	req.URL.Scheme = parsed.Scheme
	req.URL.Host = parsed.Host
	return c.inner.Do(req)
}

func TestTransport_ReportRecordsQuotaObservation(t *testing.T) {
	quota.ResetDefaultRegistry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "11")
		w.Header().Set("X-RateLimit-Reset", "1545973200")
		_ = json.NewEncoder(w).Encode(models.ReportResponse{Data: models.ReportData{IPAddress: "1.2.3.4", AbuseScore: 100}})
	}))
	defer srv.Close()

	tr := New(httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(&redirectingClient{base: srv.URL, inner: srv.Client()})), "token")
	if _, err := tr.Report(context.Background(), models.ReportRequest{IP: "1.2.3.4", Categories: "21", Comment: "test"}); err != nil {
		t.Fatalf("Report returned error: %v", err)
	}

	obs, ok := quota.DefaultRegistry().Get("abuseipdb")
	if !ok {
		t.Fatal("expected abuseipdb observation")
	}
	if obs.State != quota.Throttled || obs.Remaining != 11 {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}
