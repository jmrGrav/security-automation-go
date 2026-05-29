package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/logging"
)

type RateLimitHook interface {
	Before(ctx context.Context, req *http.Request) error
	After(ctx context.Context, req *http.Request, resp *http.Response, err error) error
}

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

type RetryPolicy struct {
	MaxAttempts int
	Backoff     Backoff
	ShouldRetry func(resp *http.Response, err error) bool
}

type HTTPClient struct {
	client      Doer
	retryPolicy RetryPolicy
	rateHook    RateLimitHook
}

func New(cfg config.HTTPConfig, opts ...Option) *HTTPClient {
	options := options{
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   cfg.Timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       50,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   cfg.Timeout,
				ExpectContinueTimeout: time.Second,
			},
		},
		retryPolicy: RetryPolicy{
			MaxAttempts: cfg.RetryMax,
			Backoff:     NewExponentialBackoff(cfg.RetryBackoff, 30*time.Second),
			ShouldRetry: defaultShouldRetry,
		},
	}

	for _, opt := range opts {
		opt(&options)
	}

	if options.retryPolicy.MaxAttempts <= 0 {
		options.retryPolicy.MaxAttempts = 1
	}
	if options.retryPolicy.Backoff == nil {
		options.retryPolicy.Backoff = NewExponentialBackoff(time.Second, 30*time.Second)
	}
	if options.retryPolicy.ShouldRetry == nil {
		options.retryPolicy.ShouldRetry = defaultShouldRetry
	}

	return &HTTPClient{
		client:      options.client,
		retryPolicy: options.retryPolicy,
		rateHook:    options.rateHook,
	}
}

func (c *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	const op = "httpclient.Do"

	if req == nil {
		return nil, apperr.New(op, "request is required")
	}
	if ctx == nil {
		return nil, apperr.New(op, "context is required")
	}

	logger := logging.FromContext(ctx, nil)
	traceID := logging.TraceIDFromContext(ctx)

	var lastResp *http.Response
	var lastErr error

	for attempt := 1; attempt <= c.retryPolicy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, apperr.Wrap(op, err)
		}

		clonedReq := req.Clone(ctx)

		if c.rateHook != nil {
			if err := c.rateHook.Before(ctx, clonedReq); err != nil {
				return nil, apperr.Wrapf(op, err, "rate limiter before hook failed")
			}
		}

		resp, err := c.client.Do(clonedReq)
		if c.rateHook != nil {
			if hookErr := c.rateHook.After(ctx, clonedReq, resp, err); hookErr != nil {
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				return nil, apperr.Wrapf(op, hookErr, "rate limiter after hook failed")
			}
		}

		lastResp = resp
		lastErr = err

		if !c.retryPolicy.ShouldRetry(resp, err) || attempt == c.retryPolicy.MaxAttempts {
			if err != nil {
				return nil, apperr.Wrapf(op, err, "request failed after %d attempt(s)", attempt)
			}
			return resp, nil
		}

		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}

		delay := c.retryPolicy.Backoff.Duration(attempt)
		if logger != nil {
			logger.WarnContext(ctx, "retrying HTTP request",
				"attempt", attempt,
				"max_attempts", c.retryPolicy.MaxAttempts,
				"backoff", delay.String(),
				"method", clonedReq.Method,
				"url", clonedReq.URL.String(),
				"trace_id", traceID,
			)
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, apperr.Wrap(op, ctx.Err())
		case <-timer.C:
		}
	}

	if lastErr != nil {
		return nil, apperr.Wrap(op, lastErr)
	}
	if lastResp == nil {
		return nil, apperr.New(op, "request failed without response or error")
	}
	return lastResp, nil
}

func defaultShouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return true
	}
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
}

type options struct {
	client      Doer
	retryPolicy RetryPolicy
	rateHook    RateLimitHook
}

type Option func(*options)

func WithDoer(doer Doer) Option {
	return func(o *options) {
		if doer != nil {
			o.client = doer
		}
	}
}

func WithRetryPolicy(policy RetryPolicy) Option {
	return func(o *options) {
		o.retryPolicy = policy
	}
}

func WithRateLimitHook(hook RateLimitHook) Option {
	return func(o *options) {
		o.rateHook = hook
	}
}

func StatusError(resp *http.Response) error {
	if resp == nil {
		return errors.New("nil response")
	}
	return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
}
