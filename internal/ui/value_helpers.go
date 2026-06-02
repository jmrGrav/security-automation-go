package ui

import "strings"

func valueOrFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func providerStateClass(status string, enabled, configured bool) string {
	normalized := strings.ToLower(strings.TrimSpace(status))
	switch {
	case !configured:
		return "degraded"
	case !enabled:
		return "warning"
	case strings.Contains(normalized, "enabled"), strings.Contains(normalized, "ready"), strings.Contains(normalized, "healthy"):
		return "healthy"
	case strings.Contains(normalized, "dry-run"), strings.Contains(normalized, "warning"):
		return "warning"
	case strings.Contains(normalized, "missing"), strings.Contains(normalized, "unavailable"):
		return "degraded"
	case strings.Contains(normalized, "unknown"):
		return "disabled"
	default:
		return "healthy"
	}
}
