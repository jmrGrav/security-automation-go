package spamhaus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
)

// submitRedirectDoer routes all SubmitClient requests to a test server by
// replacing the host while preserving the path/query.
type submitRedirectDoer struct {
	base  *url.URL
	inner *http.Client
}

func (d submitRedirectDoer) Do(req *http.Request) (*http.Response, error) {
	u := *d.base
	u.Path = req.URL.Path
	u.RawQuery = req.URL.RawQuery
	r := req.Clone(req.Context())
	r.URL = &u
	r.Host = d.base.Host
	return d.inner.Do(r)
}

func newSubmitTestClient(srv *httptest.Server, token string) *SubmitClient {
	base, _ := url.Parse(srv.URL)
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(submitRedirectDoer{base: base, inner: srv.Client()}))
	return NewSubmitClient(hc, token)
}

func TestSubmitClient_NoToken_IsNoOp(t *testing.T) {
	t.Parallel()
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "")
	err := c.Report(context.Background(), netip.MustParseAddr("1.2.3.4"), "test")
	if err != nil {
		t.Fatalf("expected nil error for empty token, got %v", err)
	}
	if called {
		t.Fatal("HTTP handler should not be called when token is empty")
	}
}

func TestSubmitClient_Success_200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer token: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "real-token")
	if err := c.Report(context.Background(), netip.MustParseAddr("1.2.3.4"), "exploit_attempt"); err != nil {
		t.Fatalf("expected nil error for 200, got %v", err)
	}
}

func TestSubmitClient_AuthFailure_401(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "bad-token")
	err := c.Report(context.Background(), netip.MustParseAddr("1.2.3.4"), "test")
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error should mention auth failure: %v", err)
	}
}

func TestSubmitClient_AuthFailure_403(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "bad-token")
	err := c.Report(context.Background(), netip.MustParseAddr("1.2.3.4"), "test")
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("error should mention auth failure: %v", err)
	}
}

func TestSubmitClient_RateLimit_429(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "good-token")
	err := c.Report(context.Background(), netip.MustParseAddr("1.2.3.4"), "test")
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error should mention rate limit: %v", err)
	}
}

func TestSubmitClient_ServerError_500(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "good-token")
	err := c.Report(context.Background(), netip.MustParseAddr("1.2.3.4"), "test")
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "retryable") {
		t.Errorf("error should mention retryable: %v", err)
	}
}

func TestSubmitClient_PayloadContainsIPAndNote(t *testing.T) {
	t.Parallel()
	var capturedBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newSubmitTestClient(srv, "good-token")
	ip := netip.MustParseAddr("203.0.113.42")
	reason := "confirmed_abuse"
	if err := c.Report(context.Background(), ip, reason); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedBody["value"] != ip.String() {
		t.Errorf("expected value=%q, got %q", ip.String(), capturedBody["value"])
	}
	if capturedBody["note"] != reason {
		t.Errorf("expected note=%q, got %q", reason, capturedBody["note"])
	}
}
