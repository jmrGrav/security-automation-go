package spamhaus

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/security/enrichment"
)

func TestSpamhausLookupNotListed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// A proper API 404 (IP not in any list) includes JSON content-type.
		// This distinguishes it from a routing 404 ("404 page not found", no JSON).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := newSpamhausTestClient(t, srv)
	lc := NewLookupClient(client, "sh-token")

	verdict, err := lc.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("unexpected error for JSON 404 (not listed): %v", err)
	}
	if verdict.Score != 0 {
		t.Errorf("expected score 0 for not-listed IP, got %d", verdict.Score)
	}
	if verdict.Note != "not listed" {
		t.Errorf("expected note 'not listed', got %q", verdict.Note)
	}
	if verdict.Mode != enrichment.LookupModeManual {
		t.Errorf("expected manual mode, got %q", verdict.Mode)
	}
}

// A plain-text 404 (routing error, wrong API path) must return an error,
// not a false "not listed" verdict.
func TestSpamhausLookupPlainText404IsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "404 page not found")
	}))
	defer srv.Close()

	client := newSpamhausTestClient(t, srv)
	lc := NewLookupClient(client, "sh-token")

	_, err := lc.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err == nil {
		t.Fatal("expected error for plain-text 404 (routing 404 / wrong API path), got nil")
	}
}

func TestSpamhausLookupListed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"dataset":"CSS","listed":true},{"dataset":"XBL","listed":false}]}`)
	}))
	defer srv.Close()

	client := newSpamhausTestClient(t, srv)
	lc := NewLookupClient(client, "sh-token")

	verdict, err := lc.Lookup(context.Background(), netip.MustParseAddr("5.6.7.8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Score != 1 {
		t.Errorf("expected score 1 for listed IP, got %d", verdict.Score)
	}
	if verdict.Note != "listed: CSS" {
		t.Errorf("expected note 'listed: CSS', got %q", verdict.Note)
	}
}

func TestSpamhausLookupHTTP401(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := newSpamhausTestClient(t, srv)
	lc := NewLookupClient(client, "bad-token")

	_, err := lc.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
}

// TestSpamhausAuthFailDoesNotCrashEnrichment verifies the fail-open guarantee:
// a Spamhaus 401 propagates as an error but the enrichment service skips it
// and still returns DNS/ASN data.
func TestSpamhausAuthFailDoesNotCrashEnrichment(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := newSpamhausTestClient(t, srv)
	lc := NewLookupClient(client, "bad-token")

	svc := enrichment.NewService(enrichment.Config{
		Enabled: true,
	}, nil, nil, []enrichment.LookupProvider{lc}, nil)

	summary, err := svc.Enrich(context.Background(), netip.MustParseAddr("1.2.3.4"), enrichment.LookupOptions{ManualForensics: true})
	if err != nil {
		t.Fatalf("enrichment service must not return error on provider failure, got: %v", err)
	}
	// Spamhaus errored → Providers slice must be empty (provider skipped)
	if len(summary.Providers) != 0 {
		t.Errorf("expected 0 provider verdicts (spamhaus skipped), got %d", len(summary.Providers))
	}
}

type shRedirectDoer struct {
	base  *url.URL
	inner *http.Client
}

func (d shRedirectDoer) Do(req *http.Request) (*http.Response, error) {
	u := *d.base
	u.Path = req.URL.Path
	u.RawQuery = req.URL.RawQuery
	r := req.Clone(req.Context())
	r.URL = &u
	r.Host = d.base.Host
	return d.inner.Do(r)
}

func newSpamhausTestClient(t *testing.T, srv *httptest.Server) httpclient.Client {
	t.Helper()
	base, _ := url.Parse(srv.URL)
	return httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(shRedirectDoer{base: base, inner: srv.Client()}))
}
