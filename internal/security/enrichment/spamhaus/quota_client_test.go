package spamhaus

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
)

type spamhausRedirectDoer struct {
	base  *url.URL
	inner *http.Client
}

func (d spamhausRedirectDoer) Do(req *http.Request) (*http.Response, error) {
	u := *d.base
	u.Path = req.URL.Path
	u.RawQuery = req.URL.RawQuery
	r := req.Clone(req.Context())
	r.URL = &u
	r.Host = d.base.Host
	return d.inner.Do(r)
}

func TestSpamhausQuotaClientFetchesSubmitCount(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer spamhaus-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/submissions/count") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"total":42,"approved":30,"pending":10,"rejected":2}`)
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	client := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(spamhausRedirectDoer{base: base, inner: srv.Client()}))
	quotaClient := NewQuotaClient(client, "spamhaus-token")

	obs, err := quotaClient.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if obs.Provider != "spamhaus" {
		t.Fatalf("unexpected provider: %+v", obs)
	}
	if obs.Plan != "submit" {
		t.Fatalf("expected plan=submit, got %q", obs.Plan)
	}
	if !obs.UsedKnown || obs.Used != 42 {
		t.Fatalf("expected Used=42, got %+v", obs)
	}
}
