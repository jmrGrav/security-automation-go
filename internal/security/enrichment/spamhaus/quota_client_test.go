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
	"github.com/jm/security-automation-go/internal/security/quota"
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

func TestSpamhausQuotaClientFetchesLimits(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer spamhaus-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/limits") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, `{"status":200,"limits":{"qms":1000,"qmh":1500,"rl_qph":3600,"rl_qpm":60,"rl_qps":1},"current":{"qpm":890,"qpd":890,"rl_qph":5,"rl_qpm":0,"rl_qps":0}}`)
	}))
	defer srv.Close()

	base, _ := url.Parse(srv.URL)
	client := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(spamhausRedirectDoer{base: base, inner: srv.Client()}))
	quotaClient := NewQuotaClient(client, "spamhaus-token")

	obs, err := quotaClient.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}
	if obs.Provider != "spamhaus" || obs.State != quota.Warning {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if obs.Plan != "rl_qps" && obs.Plan != "rl_qpm" && obs.Plan != "rl_qph" && obs.Plan != "qms" && obs.Plan != "qmh" {
		t.Fatalf("unexpected plan: %+v", obs)
	}
}
