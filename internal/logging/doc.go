// Package logging provides structured logger construction for all binaries.
//
// This package exists so every command emits consistent structured logs and so
// migration-specific metadata can be attached centrally. Using slog keeps the
// implementation in the Go standard library while still improving
// observability compared to ad hoc log formatting in the current Python code.
package logging
