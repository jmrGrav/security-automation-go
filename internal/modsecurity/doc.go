// Package modsecurity will eventually own nginx error-log parsing and the
// temporary Cloudflare ban workflow triggered by ModSecurity anomaly scores.
//
// It is separated now because that logic is operationally distinct from
// CrowdSec ban sync and has its own parsing, deduplication, and expiry rules.
package modsecurity
