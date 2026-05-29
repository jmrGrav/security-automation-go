package betterstack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
)

func TestClientSendPostsStableJSON(t *testing.T) {
	var (
		authHeader string
		body       map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := NewClient(httpclient.New(config.HTTPConfig{}), "secret-token", srv.URL)
	err := client.Send(context.Background(), Event{
		Message:   "cloudflare replay",
		Source:    "cloudflare_waf",
		Level:     "warning",
		Timestamp: time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Payload: map[string]any{
			"ip":         "8.8.8.8",
			"abuse_type": "wordpress_probe",
		},
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if authHeader != "Bearer secret-token" {
		t.Fatalf("unexpected auth header: %s", authHeader)
	}
	if body["message"] != "cloudflare replay" || body["source"] != "cloudflare_waf" {
		t.Fatalf("unexpected body: %+v", body)
	}
	if body["dt"] != "2026-05-27T12:00:00Z" {
		t.Fatalf("unexpected timestamp: %+v", body)
	}
}

func TestClientSendHandlesTimeoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	hc := httpclient.New(config.HTTPConfig{Timeout: 10 * time.Millisecond, RetryMax: 1})
	client := NewClient(hc, "secret-token", srv.URL)
	err := client.Send(context.Background(), Event{Message: "timeout", Source: "cloudflare_waf", Level: "warning"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
