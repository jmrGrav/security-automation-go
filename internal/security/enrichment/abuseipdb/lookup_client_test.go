package abuseipdb_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment/abuseipdb"
)

// redirectDoer rewrites every request host to the mock server URL.
type redirectDoer struct {
	base string
}

func (d *redirectDoer) Do(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(d.base, "http://")
	return http.DefaultTransport.RoundTrip(clone)
}

func newTestClient(t *testing.T, status int, body string) *abuseipdb.LookupClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(&redirectDoer{base: srv.URL}))
	return abuseipdb.NewLookupClient(hc, "testkey")
}

func TestAbuseIPDBLookup_Success(t *testing.T) {
	const body = `{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":85,"countryCode":"CN","isp":"Example ISP","domain":"example.com","usageType":"Data Center/Web Hosting/Transit","totalReports":12}}`
	client := newTestClient(t, http.StatusOK, body)

	verdict, err := client.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Score != 85 {
		t.Errorf("expected Score=85, got %d", verdict.Score)
	}
	if verdict.Provider != "abuseipdb" {
		t.Errorf("expected Provider=abuseipdb, got %s", verdict.Provider)
	}
	if !verdict.Manual {
		t.Error("expected Manual=true")
	}
	if !strings.Contains(verdict.Note, "confidence=85") {
		t.Errorf("expected confidence in note, got %q", verdict.Note)
	}
	if !strings.Contains(verdict.Note, "reports=12") {
		t.Errorf("expected reports in note, got %q", verdict.Note)
	}
}

func TestAbuseIPDBLookup_CleanIP(t *testing.T) {
	const body = `{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":0,"countryCode":"US","isp":"Google LLC","totalReports":0}}`
	client := newTestClient(t, http.StatusOK, body)

	verdict, err := client.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Score != 0 {
		t.Errorf("expected Score=0 for clean IP, got %d", verdict.Score)
	}
}

func TestAbuseIPDBLookup_429FailOpen(t *testing.T) {
	const body = `{"errors":[{"detail":"Daily rate limit exceeded.","status":429}]}`
	client := newTestClient(t, http.StatusTooManyRequests, body)

	verdict, err := client.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err == nil {
		t.Fatalf("expected error on 429, got verdict Score=%d", verdict.Score)
	}
	// Score must be zero on error so callers can fail-open.
	if verdict.Score != 0 {
		t.Errorf("expected Score=0 on error, got %d", verdict.Score)
	}
}

func TestAbuseIPDBLookup_TimeoutFailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // block until client times out
	}))
	defer srv.Close()
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(&redirectDoer{base: srv.URL}))
	client := abuseipdb.NewLookupClient(hc, "testkey")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	verdict, err := client.Lookup(ctx, netip.MustParseAddr("1.2.3.4"))
	if err == nil {
		t.Fatalf("expected error on timeout, got verdict Score=%d", verdict.Score)
	}
	if verdict.Score != 0 {
		t.Errorf("expected Score=0 on timeout, got %d", verdict.Score)
	}
}
