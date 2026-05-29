// Package crowdsec defines the local CrowdSec integration seam.
//
// The current Python implementation depends heavily on `cscli`, local
// allowlists, active decisions, and escalation commands. This package makes
// those dependencies explicit so they can be mocked in tests and replaced
// incrementally if a native API client is introduced later.
package crowdsec
