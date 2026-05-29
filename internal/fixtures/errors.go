package fixtures

import "errors"

var (
	ErrFixtureNotFound   = errors.New("fixture not found")
	ErrFixtureCorrupted  = errors.New("fixture integrity check failed")
	ErrInvalidSchema     = errors.New("invalid fixture schema version")
	ErrInjectedTimeout   = errors.New("injected timeout failure")
	ErrInjectedRateLimit = errors.New("injected rate limit failure (429)")
	ErrInjectedTransient = errors.New("injected transient failure")
	ErrInconsistentOrder = errors.New("replay sequence ordering inconsistency")
	ErrMalformedResponse = errors.New("malformed response payload")
	ErrConnectionReset   = errors.New("connection reset by peer")
	ErrPartialPayload    = errors.New("partial response payload received")
)
