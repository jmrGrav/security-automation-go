package snapshot

import (
	"testing"
	"time"
)

func TestBuildDeterministicForSameInput(t *testing.T) {
	builder := NewBuilder()
	fixedTime := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	input := BuilderInput{
		RawJSON: []byte(`{
			"items": [
				{"id": "cf-b", "mode": "block", "configuration": {"target": "ip", "value": "1.2.3.4"}},
				{"id": "cf-a", "mode": "block", "configuration": {"target": "ip", "value": "5.6.7.8"}}
			]
		}`),
		CreatedAt:  fixedTime,
		CapturedAt: fixedTime,
		Source: SnapshotSource{
			Provider:    "cloudflare",
			Endpoint:    "ip_access_rules",
			CaptureMode: "fixture",
		},
		ResourceType: ResourceIPAccessRules,
		Scope: RawScope{
			AccountID: "acc-1",
			ZoneID:    "zone-1",
			ScopeType: "zone",
		},
		Pagination: PaginationMetadata{
			Paginated:        true,
			PageCount:        1,
			TotalExpected:    2,
			TotalObserved:    2,
			SequenceComplete: true,
		},
		ObjectsPath: []string{"items"},
	}

	first, err := builder.Build(input)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	second, err := builder.Build(input)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if first.Integrity.SnapshotChecksum != second.Integrity.SnapshotChecksum {
		t.Fatalf("checksum mismatch: %q != %q", first.Integrity.SnapshotChecksum, second.Integrity.SnapshotChecksum)
	}
	if first.SnapshotID != second.SnapshotID {
		t.Fatalf("snapshot ID mismatch: %q != %q", first.SnapshotID, second.SnapshotID)
	}
	if len(first.Collection.Objects) != 2 {
		t.Fatalf("unexpected object count: %d", len(first.Collection.Objects))
	}

	// Verify StableIdentityKey sorting (ip:ip:1.2.3.4:block < ip:ip:5.6.7.8:block)
	if first.Collection.Objects[0].StableIdentityKey != "ip:ip:1.2.3.4:block" {
		t.Errorf("expected SIK ip:ip:1.2.3.4:block, got %s", first.Collection.Objects[0].StableIdentityKey)
	}
}

func TestBuildOrderingIndependentForObjectList(t *testing.T) {
	builder := NewBuilder()
	fixedTime := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)

	base := BuilderInput{
		CreatedAt:  fixedTime,
		CapturedAt: fixedTime,
		Source: SnapshotSource{
			Provider: "cloudflare",
		},
		ResourceType: ResourceIPAccessRules,
		ObjectsPath:  []string{"items"},
	}

	left := base
	left.RawJSON = []byte(`{"items":[{"id":"a","mode":"block","configuration":{"target":"ip","value":"1"}},{"id":"b","mode":"block","configuration":{"target":"ip","value":"2"}}]}`)

	right := base
	right.RawJSON = []byte(`{"items":[{"id":"b","mode":"block","configuration":{"target":"ip","value":"2"}},{"id":"a","mode":"block","configuration":{"target":"ip","value":"1"}}]}`)

	leftSnapshot, err := builder.Build(left)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	rightSnapshot, err := builder.Build(right)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if leftSnapshot.Integrity.CanonicalHash != rightSnapshot.Integrity.CanonicalHash {
		t.Fatalf("expected equal canonical hashes, got %q and %q", leftSnapshot.Integrity.CanonicalHash, rightSnapshot.Integrity.CanonicalHash)
	}
}

func TestBuildFiltersVolatileAttributes(t *testing.T) {
	builder := NewBuilder()
	fixedTime := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	input := BuilderInput{
		RawJSON: []byte(`{
			"items": [
				{
					"id": "cf-1",
					"mode": "block",
					"configuration": {"target": "ip", "value": "1.1.1.1"},
					"created_on": "2024-01-01T00:00:00Z",
					"modified_on": "2024-01-02T00:00:00Z",
					"internal_ref": "secret"
				}
			]
		}`),
		CreatedAt:    fixedTime,
		CapturedAt:   fixedTime,
		Source:       SnapshotSource{Provider: "cloudflare"},
		ResourceType: ResourceIPAccessRules,
		ObjectsPath:  []string{"items"},
	}

	snap, err := builder.Build(input)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	attrs := snap.Collection.Objects[0].Attributes
	if _, ok := attrs["created_on"]; ok {
		t.Error("volatile attribute created_on should have been filtered out")
	}
	if _, ok := attrs["id"]; ok {
		t.Error("id should have been filtered out of attributes (stored in ObjectID)")
	}
	if snap.Collection.Objects[0].ObjectID != "cf-1" {
		t.Errorf("expected ObjectID cf-1, got %s", snap.Collection.Objects[0].ObjectID)
	}
}

func TestBuildHashesScope(t *testing.T) {
	builder := NewBuilder()
	fixedTime := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	input := BuilderInput{
		RawJSON:    []byte(`{"items":[]}`),
		CreatedAt:  fixedTime,
		CapturedAt: fixedTime,
		Source:     SnapshotSource{Provider: "cloudflare"},
		Scope: RawScope{
			AccountID: "my-real-account-id",
			ZoneID:    "my-real-zone-id",
		},
		ObjectsPath: []string{"items"},
	}

	snap, err := builder.Build(input)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if snap.Scope.AccountIDHash == "" || snap.Scope.AccountIDHash == "my-real-account-id" {
		t.Error("AccountID should be hashed and non-empty")
	}
}
