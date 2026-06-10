package decode

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jm/security-automation-go/internal/apperr"
)

// Decode decodes raw bytes into target, tolerating unknown JSON fields.
// Use for external Cloudflare API responses where the schema may evolve.
func Decode(raw []byte, target any) error {
	const op = "cloudflare.decode.Decode"

	if len(raw) == 0 {
		return apperr.New(op, "empty response body")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	if err := decoder.Decode(target); err != nil {
		return apperr.Wrap(op, fmt.Errorf("malformed JSON: %w", err))
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != nil {
		if err == io.EOF {
			return nil
		}
		return apperr.Wrap(op, fmt.Errorf("unexpected content after JSON: %w", err))
	}

	return apperr.New(op, "unexpected trailing JSON content")
}

// DecodeStrict decodes the raw bytes into the given target interface.
// It disallows unknown fields — use only for internal payloads with a known schema.
func DecodeStrict(raw []byte, target any) error {
	const op = "cloudflare.decode.DecodeStrict"

	if len(raw) == 0 {
		return apperr.New(op, "empty response body")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()

	if err := decoder.Decode(target); err != nil {
		return apperr.Wrap(op, fmt.Errorf("malformed or incompatible JSON: %w", err))
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != nil {
		if err == io.EOF {
			return nil
		}
		return apperr.Wrap(op, fmt.Errorf("unexpected content after JSON: %w", err))
	}

	return apperr.New(op, "unexpected trailing JSON content")
}
