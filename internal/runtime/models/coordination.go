package models

import (
	"time"
)

// Lease represents an exclusive right to perform an action.
type Lease struct {
	ID        string    `json:"lease_id"`
	Owner     string    `json:"owner"`
	Action    string    `json:"action"` // "reconcile", "rollback"
	EpochID   string    `json:"epoch_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`

	// HA protection
	FencingToken int64 `json:"fencing_token,omitempty"`
}

// Epoch represents a logical execution generation.
type Epoch struct {
	ID             string    `json:"epoch_id"`
	ParentID       string    `json:"parent_id,omitempty"`
	Generation     int64     `json:"generation"`
	SchedulerRunID string    `json:"scheduler_run_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

func (l Lease) IsExpired() bool {
	return !l.ExpiresAt.IsZero() && time.Now().After(l.ExpiresAt)
}
