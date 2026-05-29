// Package app wires configuration, logging, storage, and service dependencies
// into runnable command-specific applications.
//
// This package exists so `cmd/*` stays thin and the migration can evolve the
// internal dependency graph without spreading construction logic across several
// binaries.
package app
