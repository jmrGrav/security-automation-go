package transport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/transport"
)

func TestCloudflareRetryAfter(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Retry-After", "12")
	if got := transport.CloudflareRetryAfter(resp); got != 12*time.Second {
		t.Fatalf("unexpected retry-after: %s", got)
	}
	resp.Header.Set("Retry-After", "bad")
	if got := transport.CloudflareRetryAfter(resp); got != 0 {
		t.Fatalf("expected zero on invalid retry-after, got %s", got)
	}
	if got := transport.CloudflareRetryAfter(nil); got != 0 {
		t.Fatalf("expected zero on nil response, got %s", got)
	}
}

func TestTransport_Request_429_ReturnsExplicitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`error code: 1015`))
	}))
	defer srv.Close()

	redirectClient := &redirectingClient{base: srv.URL, inner: srv.Client()}
	tr := transport.New(redirectClient, "tok")
	_, _, err := tr.Request(context.Background(), http.MethodGet, "/test", nil, nil, "")
	if err == nil {
		t.Fatal("HTTP 429 must return an error, not nil")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should mention 429, got: %v", err)
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error should mention rate limited, got: %v", err)
	}
}

func TestTransport_Request_429_WithoutRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`error code: 1015`))
	}))
	defer srv.Close()

	redirectClient := &redirectingClient{base: srv.URL, inner: srv.Client()}
	tr := transport.New(redirectClient, "tok")
	_, _, err := tr.Request(context.Background(), http.MethodGet, "/test", nil, nil, "")
	if err == nil {
		t.Fatal("HTTP 429 without Retry-After must still return an error")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error should mention rate limited, got: %v", err)
	}
}

func TestExecuteGraphQLSuccessAndError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()

	redirectClient := &redirectingClient{base: srv.URL, inner: srv.Client()}
	tr := transport.New(redirectClient, "tok")
	type payload struct {
		OK bool `json:"ok"`
	}
	got, err := transport.ExecuteGraphQL[payload](context.Background(), tr, "query { ok }", nil)
	if err != nil {
		t.Fatalf("execute graphql: %v", err)
	}
	if !got.OK {
		t.Fatal("expected graphQL success payload")
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ok":false},"errors":[{"message":"boom"}]}`))
	}))
	defer errSrv.Close()

	errClient := &redirectingClient{base: errSrv.URL, inner: errSrv.Client()}
	errTransport := transport.New(errClient, "tok")
	if _, err := transport.ExecuteGraphQL[payload](context.Background(), errTransport, "query { ok }", nil); err == nil {
		t.Fatal("expected graphql error")
	}
}
