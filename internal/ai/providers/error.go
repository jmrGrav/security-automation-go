package providers

import "fmt"

// Error is a typed provider failure that preserves retryability without exposing secrets.
type Error struct {
	Provider   Name
	StatusCode int
	Retryable  bool
	Reason     string
	Err        error
}

func (e *Error) Error() string {
	if e == nil {
		return "provider error"
	}
	if e.Reason != "" {
		return fmt.Sprintf("%s provider error: %s", e.Provider, e.Reason)
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s provider error: status %d", e.Provider, e.StatusCode)
	}
	if e.Err != nil {
		return fmt.Sprintf("%s provider error: %v", e.Provider, e.Err)
	}
	return fmt.Sprintf("%s provider error", e.Provider)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
