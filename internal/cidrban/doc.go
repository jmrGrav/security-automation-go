// Package cidrban will own network-level escalation logic derived from recent
// IP bans. It is split out because the current Python daemon uses a distinct
// retention window, threshold, and Cloudflare/CrowdSec side effects for IPv4
// `/24` auto-bans, and those semantics need focused tests.
package cidrban
