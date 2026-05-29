package governor

import (
	"time"
)

type ResourceType string

const (
	ResourceRequest     ResourceType = "request"     // Total API requests (GET, etc.)
	ResourceMutation    ResourceType = "mutation"    // POST, PATCH, PUT
	ResourceDestructive ResourceType = "destructive" // DELETE, Rollback-delete
)

// Limit defines the capacity and refill rate for a resource.
type Limit struct {
	MaxBurst int           `json:"max_burst"`
	Rate     int           `json:"rate"` // units per Interval
	Interval time.Duration `json:"interval"`
}

// ProviderConfig defines limits for an external service.
type ProviderConfig struct {
	Name   string           `json:"name"`
	Limits map[string]Limit `json:"limits"`
}

// TenantConfig defines overrides and weights for a tenant.
type TenantConfig struct {
	ID     string  `json:"tenant_id"`
	Weight float64 `json:"weight"` // Relative priority
	Class  string  `json:"class"`  // e.g., "prod", "staging"
}

// PressureScore represents the systemic health of a provider/tenant link.
type PressureScore struct {
	ProviderID string    `json:"provider_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Score      float64   `json:"score"` // 0.0 (idle) to 1.0 (saturated)
	UpdatedAt  time.Time `json:"updated_at"`
}
