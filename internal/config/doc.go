// Package config provides a robust, versioned configuration system for the daemon.
//
// It supports YAML-based configuration with strict schema validation, environment
// variable overrides (12-factor app pattern), and secret masking for safe logging.
// The configuration is designed to be immutable at runtime once loaded.
package config
