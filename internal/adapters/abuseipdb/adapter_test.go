package abuseipdb

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestCheckReturnsScore(t *testing.T) {
	client := httpclient.New(config.HTTPConfig{
		Timeout:      time.Second,
		RetryMax:     1,
		RetryBackoff: time.Millisecond,
	}, httpclient.WithDoer(doerFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":12}}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})))

	checker := NewChecker(abtransport.New(client, "secret"), Config{
		TTL:     time.Minute,
		Timeout: time.Second,
	})

	result, err := checker.Check(context.Background(), netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if result.Score != 12 {
		t.Fatalf("unexpected score: %d", result.Score)
	}
	if result.Provider != "abuseipdb" {
		t.Fatalf("unexpected provider: %s", result.Provider)
	}
	if result.CacheHit {
		t.Fatal("expected first lookup to miss cache")
	}
}

func TestCheckUsesTTLCache(t *testing.T) {
	var calls int
	client := httpclient.New(config.HTTPConfig{
		Timeout:      time.Second,
		RetryMax:     1,
		RetryBackoff: time.Millisecond,
	}, httpclient.WithDoer(doerFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		body := `{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":91}}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})))

	checker := NewChecker(abtransport.New(client, "secret"), Config{
		TTL:     time.Minute,
		Timeout: time.Second,
	})
	ip := netip.MustParseAddr("1.2.3.4")

	first, err := checker.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("first check: %v", err)
	}
	second, err := checker.Check(context.Background(), ip)
	if err != nil {
		t.Fatalf("second check: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected one transport call, got %d", calls)
	}
	if first.CacheHit {
		t.Fatal("expected first result not to be cached")
	}
	if !second.CacheHit {
		t.Fatal("expected second result to use cache")
	}
	if second.Score != 91 {
		t.Fatalf("unexpected cached score: %d", second.Score)
	}
}
