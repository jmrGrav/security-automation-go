package virustotal

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

func TestVirusTotalLookupClean(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "vt-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"data":{"attributes":{"reputation":0,"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":80,"undetected":10}}}}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	lc := NewLookupClient(client, "vt-key")

	verdict, err := lc.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Score != 0 {
		t.Errorf("expected score 0 for clean IP, got %d", verdict.Score)
	}
	if verdict.Provider != "virustotal" {
		t.Errorf("expected provider virustotal, got %q", verdict.Provider)
	}
	if verdict.Mode != enrichment.LookupModeManual {
		t.Errorf("expected manual mode, got %q", verdict.Mode)
	}
}

func TestVirusTotalLookupMalicious(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"attributes":{"reputation":-3,"last_analysis_stats":{"malicious":5,"suspicious":1,"harmless":60,"undetected":10}}}}`)
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	lc := NewLookupClient(client, "vt-key")

	verdict, err := lc.Lookup(context.Background(), netip.MustParseAddr("5.6.7.8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.Score != 5 {
		t.Errorf("expected score 5 (malicious count), got %d", verdict.Score)
	}
	if !verdict.Manual {
		t.Error("expected Manual=true")
	}
}

func TestVirusTotalLookupHTTP401(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := newTestClient(t, srv)
	lc := NewLookupClient(client, "bad-key")

	_, err := lc.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
}

func TestVirusTotalLookupEmptyKey(t *testing.T) {
	t.Parallel()
	lc := NewLookupClient(nil, "")
	_, err := lc.Lookup(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func newTestClient(t *testing.T, srv *httptest.Server) httpclient.Client {
	t.Helper()
	base, _ := url.Parse(srv.URL)
	return httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(vtRedirectDoer{base: base, inner: srv.Client()}))
}
