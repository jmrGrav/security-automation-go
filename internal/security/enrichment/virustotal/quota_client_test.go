package virustotal

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/quota"
)

type vtRedirectDoer struct {
	base  *url.URL
	inner *http.Client
}

func (d vtRedirectDoer) Do(req *http.Request) (*http.Response, error) {
	u := *d.base
	u.Path = req.URL.Path
	u.RawQuery = req.URL.RawQuery
	r := req.Clone(req.Context())
	r.URL = &u
	r.Host = d.base.Host
	return d.inner.Do(r)
}

func TestVirusTotalQuotaClientFetchesQuota(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-apikey"); got != "vt-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/users/vt-key") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"id":"vt-key","attributes":{"quotas":{"api_requests_daily":{"allowed":1000,"used":13},"api_requests_hourly":{"allowed":60000,"used":1},"api_requests_monthly":{"allowed":30000,"used":104}}}}}`)
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	client := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(vtRedirectDoer{base: base, inner: srv.Client()}))
	quotaClient := NewQuotaClient(client, "vt-key")

	obs, err := quotaClient.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if obs.Provider != "virustotal" || obs.State != quota.Normal {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if obs.Plan != "api_requests_daily" {
		t.Fatalf("expected daily quota to be selected, got %+v", obs)
	}
}
