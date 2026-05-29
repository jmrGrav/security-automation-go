package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/logging"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

type testRateHook struct {
	beforeCalls atomic.Int32
	afterCalls  atomic.Int32
}

func (h *testRateHook) Before(context.Context, *http.Request) error {
	h.beforeCalls.Add(1)
	return nil
}

func (h *testRateHook) After(context.Context, *http.Request, *http.Response, error) error {
	h.afterCalls.Add(1)
	return nil
}

func TestHTTPClientRetriesAndSucceeds(t *testing.T) {
	var calls atomic.Int32
	client := New(config.HTTPConfig{Timeout: time.Second, RetryMax: 3, RetryBackoff: time.Millisecond},
		WithDoer(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			_ = req
			if calls.Add(1) < 2 {
				return nil, errors.New("temporary failure")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		})),
	)

	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}

	ctx := logging.WithTraceLogger(context.Background(), logging.New(config.GlobalConfig{
		AppEnv:      "test",
		ServiceName: "httpclient-test",
		Log:         config.LogConfig{Level: "debug", Format: "json"},
	}))
	resp, err := client.Do(ctx, req)
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	_ = resp.Body.Close()

	if calls.Load() != 2 {
		t.Fatalf("unexpected call count: %d", calls.Load())
	}
}

func TestHTTPClientCallsRateHooks(t *testing.T) {
	hook := &testRateHook{}
	client := New(config.HTTPConfig{Timeout: time.Second, RetryMax: 1, RetryBackoff: time.Millisecond},
		WithRateLimitHook(hook),
		WithDoer(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			_ = req
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		})),
	)

	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	_ = resp.Body.Close()

	if hook.beforeCalls.Load() != 1 || hook.afterCalls.Load() != 1 {
		t.Fatalf("unexpected hook calls: before=%d after=%d", hook.beforeCalls.Load(), hook.afterCalls.Load())
	}
}
