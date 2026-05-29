package models

import "time"

// Ruleset represents a Cloudflare Ruleset (Phase-based firewall rules).
type Ruleset struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Kind        string        `json:"kind"`  // "managed", "custom", "root", "zone"
	Phase       string        `json:"phase"` // e.g., "http_request_firewall_custom"
	Rules       []RulesetRule `json:"rules,omitempty"`
	LastUpdated time.Time     `json:"last_updated,omitempty"`
}

// RulesetRule represents an individual rule within a ruleset.
type RulesetRule struct {
	ID               string    `json:"id,omitempty"`
	Version          string    `json:"version,omitempty"`
	Action           string    `json:"action"`
	ActionParameters any       `json:"action_parameters,omitempty"`
	Expression       string    `json:"expression"`
	Description      string    `json:"description"`
	Enabled          bool      `json:"enabled"`
	LastUpdated      time.Time `json:"last_updated,omitempty"`
	Ref              string    `json:"ref,omitempty"`
	Categories       []string  `json:"categories,omitempty"`
}

// PhaseDescriptor defines a logical evaluation point in the Cloudflare edge.
type PhaseDescriptor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Precedence  int    `json:"precedence"`
	Description string `json:"description"`
}
