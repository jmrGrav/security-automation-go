package fixtures

import (
	"bytes"
	"io"
	"net/http"
)

// ReplayDoer adapts the ReplayEngine to the http.RoundTripper or a custom Doer interface.
type ReplayDoer struct {
	Engine *ReplayEngine
}

func NewReplayDoer(e *ReplayEngine) *ReplayDoer {
	return &ReplayDoer{Engine: e}
}

func (d *ReplayDoer) Do(req *http.Request) (*http.Response, error) {
	res, err := d.Engine.Next(req.Context())
	if err != nil {
		if err.Error() == "EOF" {
			return nil, io.EOF
		}
		return nil, err
	}

	if res.Error != nil {
		// Simulation of network-level errors or specific HTTP statuses
		if res.Error == ErrInjectedRateLimit {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"success":false,"errors":[{"message":"rate limit"}]}`))),
				Request:    req,
			}, nil
		}
		// For timeout or connection reset, we return the error directly
		return nil, res.Error
	}

	resp := &http.Response{
		StatusCode: res.Response.ResponseStatus,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(res.Response.ResponseBody)),
		Request:    req,
	}

	for k, v := range res.Response.ResponseHeaders {
		resp.Header.Set(k, v)
	}

	return resp, nil
}
