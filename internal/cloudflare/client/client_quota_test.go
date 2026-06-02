package client

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

type quotaRedirectDoer struct {
	base  *url.URL
	inner *http.Client
}

func (d quotaRedirectDoer) Do(req *http.Request) (*http.Response, error) {
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
		if got := r.Header.Get("Authorization"); got != "Bearer cf-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/user/tokens/verify") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Ratelimit", `"default";r=40;t=20`)
		w.Header().Set("Ratelimit-Policy", `"burst";q=100;w=60`)
		_, _ = io.WriteString(w, `{"success":true,"result":{"id":"tok","status":"active"},"errors":[],"messages":[]}`)
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	client := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(quotaRedirectDoer{base: base, inner: srv.Client()}))
	api := New("cf-token", client)

	obs, err := api.RefreshQuota(context.Background())
	if err != nil {
		t.Fatalf("RefreshQuota returned error: %v", err)
	}
	if obs.Provider != "cloudflare" || obs.State != quota.Normal {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if obs.Limit != 100 || obs.Remaining != 40 {
		t.Fatalf("expected quota headers to be captured, got %+v", obs)
	}
}
