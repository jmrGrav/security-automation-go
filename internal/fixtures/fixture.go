package fixtures

import (
	"time"
)

// RawFixture represents an exact, unsanitized capture from a live API.
// It is used as the source of truth for generating sanitized replay artifacts.
type RawFixture struct {
	FixtureID          string            `json:"fixture_id"`
	CapturedAt         time.Time         `json:"captured_at"`
	Endpoint           string            `json:"endpoint"`
	Method             string            `json:"method"`
	RequestHeaders     map[string]string `json:"request_headers"`
	RequestBody        []byte            `json:"request_body,omitempty"`
	ResponseStatus     int               `json:"response_status"`
	ResponseHeaders    map[string]string `json:"response_headers"`
	ResponseBody       []byte            `json:"response_body"`
	PaginationMetadata map[string]any    `json:"pagination_metadata,omitempty"`
	CaptureSequence    int               `json:"capture_sequence"`
	Source             string            `json:"source"`
	Checksum           string            `json:"checksum"`
}

// SanitizedFixture is the official artifact used for offline replay.
// All sensitive data (tokens, IDs, emails) must be redacted.
type SanitizedFixture struct {
	SanitizerVersion string            `json:"sanitizer_version"`
	SourceFixtureID  string            `json:"source_fixture_id"`
	SanitizedAt      time.Time         `json:"sanitized_at"`
	SchemaVersion    string            `json:"schema_version"`
	Endpoint         string            `json:"endpoint"`
	Method           string            `json:"method"`
	ResponseStatus   int               `json:"response_status"`
	ResponseHeaders  map[string]string `json:"response_headers"`
	ResponseBody     []byte            `json:"response_body"`
	IntegrityHash    string            `json:"integrity_hash"`
}
