package models

import "time"

// ReportRequest represents the AbuseIPDB API payload for reporting an IP.
type ReportRequest struct {
	IP         string `json:"ip"`
	Categories string `json:"categories"` // Comma-separated category IDs
	Comment    string `json:"comment"`
}

// ReportResponse represents the successful response from AbuseIPDB.
type ReportResponse struct {
	Data ReportData `json:"data"`
}

type ReportData struct {
	IPAddress  string `json:"ipAddress"`
	AbuseScore int    `json:"abuseConfidenceScore"`
	ReportID   int    `json:"id,omitempty"`
}

// CheckResponse represents the successful response from AbuseIPDB /check.
type CheckResponse struct {
	Data CheckData `json:"data"`
}

type CheckData struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode,omitempty"`
	ISP                  string `json:"isp,omitempty"`
	Domain               string `json:"domain,omitempty"`
	UsageType            string `json:"usageType,omitempty"`
	TotalReports         int    `json:"totalReports,omitempty"`
}

// ExecutableReport represents a translated AbuseIPDB action.
type ExecutableReport struct {
	ExecutionID       string `json:"execution_id"`
	StableIdentityKey string `json:"stable_identity_key"`

	IP         string `json:"ip"`
	Categories string `json:"categories"`
	Comment    string `json:"comment"`

	OriginatingOpID string    `json:"originating_op_id"`
	CreatedAt       time.Time `json:"created_at"`
}
