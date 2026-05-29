package models

import "time"

// APIResponse is the standard wrapper for all API responses.
type APIResponse struct {
	Success   bool      `json:"success"`
	Data      any       `json:"data,omitempty"`
	Error     *APIError `json:"error,omitempty"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ConfirmationPayload is required for mutation endpoints.
type ConfirmationPayload struct {
	Confirmed bool   `json:"confirmed"`
	Reason    string `json:"reason"`
	PlanID    string `json:"plan_id,omitempty"`
}
