// Package betterstack owns the log-ingest integration boundary. The current
// Python daemon emits selected Cloudflare WAF events to Better Stack, so this
// package preserves that responsibility without coupling the rest of the
// migration to a concrete HTTP implementation yet.
package betterstack
