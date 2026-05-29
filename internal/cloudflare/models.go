package cloudflare

import "time"

type AccessRule struct {
	ID            string `json:"id,omitempty"`
	Mode          string `json:"mode"`
	Notes         string `json:"notes"`
	Configuration struct {
		Target string `json:"target"`
		Value  string `json:"value"`
	} `json:"configuration"`
}

type ListItem struct {
	ID      string `json:"id,omitempty"`
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

type WAFEvent struct {
	Action             string    `json:"action"`
	ClientIP           string    `json:"clientIP"`
	Datetime           time.Time `json:"datetime"`
	ClientRequestPath  string    `json:"clientRequestPath"`
	ClientRequestQuery string    `json:"clientRequestQuery"`
}

// TODO: Add GraphQL request/response models for WAF polling
// TODO: Add List Items request/response models for pagination and batching
// TODO: Add Access Rules request/response models for pagination
