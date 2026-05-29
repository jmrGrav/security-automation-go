package models

import "time"

// ResponseEnvelope is the standard Cloudflare API response wrapper.
type ResponseEnvelope struct {
	Result     any             `json:"result"`
	Success    bool            `json:"success"`
	Errors     []ResponseError `json:"errors"`
	Messages   []string        `json:"messages"`
	ResultInfo *ResultInfo     `json:"result_info,omitempty"`
}

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type ResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

// TokenVerification is returned by /user/tokens/verify
type TokenVerification struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	NotBefore time.Time `json:"not_before,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Zone represents a Cloudflare Zone.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Paused bool   `json:"paused"`
	Type   string `json:"type"`
}

// IPAccessRule represents an IP Access Rule (Firewall -> Tools).
// All fields present in CF API responses are included to satisfy DecodeStrict.
type IPAccessRule struct {
	ID            string            `json:"id"`
	Mode          string            `json:"mode"`
	Notes         string            `json:"notes"`
	AllowedModes  []string          `json:"allowed_modes"`
	Configuration RuleConfiguration `json:"configuration"`
	Paused        bool              `json:"paused"`
	CreatedOn     time.Time         `json:"created_on"`
	ModifiedOn    time.Time         `json:"modified_on"`
	Scope         *RuleScope        `json:"scope,omitempty"`
}

// RuleScope describes which CF entity (zone or account) a rule belongs to.
type RuleScope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type RuleConfiguration struct {
	Target string `json:"target"`
	Value  string `json:"value"`
}

// FirewallList represents an IP list (Account -> Configurations -> Lists).
type FirewallList struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Kind        string    `json:"kind"`
	NumItems    int       `json:"num_items"`
	CreatedOn   time.Time `json:"created_on"`
	ModifiedOn  time.Time `json:"modified_on"`
}

// FirewallListItem represents an item in an IP list.
type FirewallListItem struct {
	ID         string    `json:"id"`
	IP         string    `json:"ip"`
	Comment    string    `json:"comment"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
}

// WAFEvent represents a WAF event (GraphQL).
type WAFEvent struct {
	Action             string    `json:"action"`
	ClientIP           string    `json:"clientIP"`
	Datetime           time.Time `json:"datetime"`
	ClientRequestPath  string    `json:"clientRequestPath"`
	ClientRequestQuery string    `json:"clientRequestQuery"`
	Host               string    `json:"host,omitempty"`
	Source             string    `json:"source,omitempty"`
	UserAgent          string    `json:"userAgent,omitempty"`
	RuleID             string    `json:"ruleId,omitempty"`
	Description        string    `json:"description,omitempty"`
}
