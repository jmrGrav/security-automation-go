package builder

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestAssembler_DuplicateDetection(t *testing.T) {
	assembler := NewAssembler(snapshot.ResourceIPAccessRules)

	objs := []snapshot.NormalizedObject{
		{StableIdentityKey: "ip:1.1.1.1:block", ObjectType: "rule"},
	}

	if err := assembler.Add(objs); err != nil {
		t.Fatalf("failed to add first object: %v", err)
	}

	if err := assembler.Add(objs); err == nil {
		t.Fatal("expected error when adding duplicate StableIdentityKey, got nil")
	}
}

func TestAssembler_DeterministicOrdering(t *testing.T) {
	fixedTime := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)

	build := func() snapshot.Snapshot {
		assembler := NewAssembler(snapshot.ResourceIPAccessRules)
		assembler.SetCreatedAt(fixedTime)

		_ = assembler.Add([]snapshot.NormalizedObject{
			{StableIdentityKey: "z", ObjectType: "rule"},
			{StableIdentityKey: "a", ObjectType: "rule"},
		})

		snap, _ := assembler.Build()
		return snap
	}

	snap1 := build()
	snap2 := build()

	if snap1.Integrity.SnapshotChecksum != snap2.Integrity.SnapshotChecksum {
		t.Errorf("checksums differ: %s != %s", snap1.Integrity.SnapshotChecksum, snap2.Integrity.SnapshotChecksum)
	}

	if snap1.Collection.Objects[0].StableIdentityKey != "a" || snap1.Collection.Objects[1].StableIdentityKey != "z" {
		t.Errorf("objects not sorted: %v", snap1.Collection.Objects)
	}
}

func TestAssembler_ProvenancePreservation(t *testing.T) {
	assembler := NewAssembler(snapshot.ResourceIPAccessRules)

	prov := snapshot.ProvenanceMetadata{
		FixtureID:   "fix-123",
		ReplayID:    "rep-456",
		GeneratedBy: "test-discovery",
	}

	assembler.SetMetadata("custom-id", snapshot.SnapshotSource{}, snapshot.ScopeMetadata{}, snapshot.PaginationMetadata{}, prov)

	snap, _ := assembler.Build()

	if snap.Provenance.FixtureID != "fix-123" || snap.Provenance.ReplayID != "rep-456" {
		t.Errorf("provenance not preserved: %+v", snap.Provenance)
	}
	if snap.SnapshotID != "custom-id" {
		t.Errorf("SnapshotID not preserved: %s", snap.SnapshotID)
	}
}

func TestAssembler_MultiPageAssembly(t *testing.T) {
	assembler := NewAssembler(snapshot.ResourceIPAccessRules)

	// Page 1
	_ = assembler.Add([]snapshot.NormalizedObject{
		{StableIdentityKey: "page1-obj", ObjectType: "rule"},
	})

	// Page 2
	_ = assembler.Add([]snapshot.NormalizedObject{
		{StableIdentityKey: "page2-obj", ObjectType: "rule"},
	})

	snap, _ := assembler.Build()

	if snap.Collection.ObjectCount != 2 {
		t.Errorf("expected 2 objects, got %d", snap.Collection.ObjectCount)
	}
}
