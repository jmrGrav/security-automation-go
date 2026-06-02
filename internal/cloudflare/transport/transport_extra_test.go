package transport_test

import (
	"context"
	"net/http"
	"net/http/httptest"
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
