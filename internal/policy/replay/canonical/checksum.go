package canonical

import (
	"crypto/sha256"
	"fmt"

	"github.com/jm/security-automation-go/internal/snapshot"
)

// Checksum computes a SHA-256 hash of a canonicalized object.
func Checksum(v any) (string, error) {
	data := snapshot.CanonicalJSON(v)

	h := sha256.New()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
