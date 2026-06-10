package decode_test

import (
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/decode"
)

type zoneFixture struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// TestDecode_UnknownFieldsAccepted verifies that Decode tolerates extra fields
// added by the Cloudflare API (e.g. "development_mode").
func TestDecode_UnknownFieldsAccepted(t *testing.T) {
	raw := []byte(`{"id":"zone-id","name":"example.com","status":"active","development_mode":0,"paused":false}`)
	var z zoneFixture
	if err := decode.Decode(raw, &z); err != nil {
		t.Fatalf("Decode with unknown fields: %v", err)
	}
	if z.ID != "zone-id" || z.Name != "example.com" || z.Status != "active" {
		t.Errorf("unexpected values: %+v", z)
	}
}

// TestDecode_EmptyBodyReturnsError verifies empty input is rejected.
func TestDecode_EmptyBodyReturnsError(t *testing.T) {
	if err := decode.Decode(nil, &zoneFixture{}); err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

// TestDecode_MalformedJSONReturnsError verifies malformed JSON is rejected.
func TestDecode_MalformedJSONReturnsError(t *testing.T) {
	if err := decode.Decode([]byte(`{not json`), &zoneFixture{}); err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestDecodeStrict_UnknownFieldFails verifies DecodeStrict still rejects unknown fields.
func TestDecodeStrict_UnknownFieldFails(t *testing.T) {
	raw := []byte(`{"id":"zone-id","name":"example.com","status":"active","development_mode":0}`)
	var z zoneFixture
	if err := decode.DecodeStrict(raw, &z); err == nil {
		t.Fatal("expected DecodeStrict to fail on unknown field, got nil")
	}
}

// TestDecodeStrict_KnownFieldsPass verifies DecodeStrict accepts a conforming payload.
func TestDecodeStrict_KnownFieldsPass(t *testing.T) {
	raw := []byte(`{"id":"zone-id","name":"example.com","status":"active"}`)
	var z zoneFixture
	if err := decode.DecodeStrict(raw, &z); err != nil {
		t.Fatalf("DecodeStrict with known fields: %v", err)
	}
}
