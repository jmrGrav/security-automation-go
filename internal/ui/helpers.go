package ui

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

func joinNonEmpty(values []string, sep string) string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, sep)
}

func newUIEventID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "evt-unknown"
	}
	return hex.EncodeToString(buf[:])
}
