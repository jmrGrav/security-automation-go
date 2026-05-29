// Package httpclient provides a context-aware HTTP abstraction with pooled
// connections, bounded retries, and optional rate-limit hooks.
//
// This package exists so future concurrent services share the same cancellation,
// timeout, tracing, and retry semantics without hiding work in background
// goroutines.
package httpclient
