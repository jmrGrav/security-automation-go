package fixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/jm/security-automation-go/internal/snapshot"
)

// Checksum returns a stable hash of the given byte slice.
func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// IntegrityHashSanitized generates a stable checksum for a sanitized fixture.
func IntegrityHashSanitized(f SanitizedFixture) string {
	// We use CanonicalJSON to ensure stable serialization regardless of field order or map keys.
	payload := struct {
		SanitizerVersion string            `json:"sanitizer_version"`
		SourceFixtureID  string            `json:"source_fixture_id"`
		SchemaVersion    string            `json:"schema_version"`
		Endpoint         string            `json:"endpoint"`
		Method           string            `json:"method"`
		ResponseStatus   int               `json:"response_status"`
		ResponseHeaders  map[string]string `json:"response_headers"`
		ResponseBody     []byte            `json:"response_body"`
	}{
		SanitizerVersion: f.SanitizerVersion,
		SourceFixtureID:  f.SourceFixtureID,
		SchemaVersion:    f.SchemaVersion,
		Endpoint:         f.Endpoint,
		Method:           f.Method,
		ResponseStatus:   f.ResponseStatus,
		ResponseHeaders:  f.ResponseHeaders,
		ResponseBody:     f.ResponseBody,
	}

	return Checksum([]byte(snapshot.CanonicalJSON(payload)))
}

// ValidateIntegrity checks if the fixture's hash matches its content.
func ValidateIntegrity(f SanitizedFixture) error {
	if f.IntegrityHash != IntegrityHashSanitized(f) {
		return fmt.Errorf("%w: expected %s, got %s", ErrFixtureCorrupted, f.IntegrityHash, IntegrityHashSanitized(f))
	}
	return nil
}

// ChecksumMap generates a stable hash for a map.
func ChecksumMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var data string
	for _, k := range keys {
		data += fmt.Sprintf("%s:%s|", k, m[k])
	}
	return Checksum([]byte(data))
}
