package abuseipdb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type abuseQuotaRedirectDoer struct {
	base  *url.URL
	inner *http.Client
}

func (d abuseQuotaRedirectDoer) Do(req *http.Request) (*http.Response, error) {
	u := *d.base
	u.Path = req.URL.Path
	u.RawQuery = req.URL.RawQuery
	r := req.Clone(req.Context())
	r.URL = &u
	r.Host = d.base.Host
	return d.inner.Do(r)
}

func TestClientRefreshQuotaCapturesHeaders(t *testing.T) {
	t.Parallel()

	quota.ResetDefaultRegistry()
	t.Cleanup(quota.ResetDefaultRegistry)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Key"); got != "abuse-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/check") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "12")
		w.Header().Set("X-RateLimit-Reset-After", "30")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"ipAddress":            "1.1.1.1",
				"abuseConfidenceScore": 0,
			},
		})
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	client := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(abuseQuotaRedirectDoer{base: base, inner: srv.Client()}))
	api := NewClient("abuse-token", client)

	obs, err := api.RefreshQuota(context.Background())
	if err != nil {
		t.Fatalf("RefreshQuota returned error: %v", err)
	}
	if obs.Provider != "abuseipdb" || obs.State != quota.Throttled {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if obs.Limit != 1000 || obs.Remaining != 12 {
		t.Fatalf("expected quota headers to be captured, got %+v", obs)
	}
}
