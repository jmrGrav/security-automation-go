package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Assembler handles the deterministic assembly of normalized objects into a Snapshot.
type Assembler struct {
	snapshotID   string
	resourceType snapshot.ResourceType
	source       snapshot.SnapshotSource
	scope        snapshot.ScopeMetadata
	pagination   snapshot.PaginationMetadata
	provenance   snapshot.ProvenanceMetadata

	objects   map[string]snapshot.NormalizedObject
	createdAt time.Time
}

func NewAssembler(rt snapshot.ResourceType) *Assembler {
	return &Assembler{
		resourceType: rt,
		objects:      make(map[string]snapshot.NormalizedObject),
		createdAt:    time.Now().UTC(),
	}
}

// SetMetadata initializes the non-collection metadata for the snapshot.
func (a *Assembler) SetMetadata(
	id string,
	source snapshot.SnapshotSource,
	scope snapshot.ScopeMetadata,
	pagination snapshot.PaginationMetadata,
	provenance snapshot.ProvenanceMetadata,
) {
	a.snapshotID = id
	a.source = source
	a.scope = scope
	a.pagination = pagination
	a.provenance = provenance
}

// SetCreatedAt allows injecting a deterministic build time.
func (a *Assembler) SetCreatedAt(t time.Time) {
	a.createdAt = t.UTC()
}

// Add appends normalized objects to the assembly.
// It performs duplicate detection based on StableIdentityKey.
func (a *Assembler) Add(objects []snapshot.NormalizedObject) error {
	const op = "snapshot.builder.Assembler.Add"

	for _, obj := range objects {
		if obj.StableIdentityKey == "" {
			return apperr.New(op, "object missing StableIdentityKey")
		}
		if _, exists := a.objects[obj.StableIdentityKey]; exists {
			return apperr.Newf(op, "duplicate StableIdentityKey detected: %s", obj.StableIdentityKey)
		}
		a.objects[obj.StableIdentityKey] = obj
	}
	return nil
}

// Build finalizes the assembly and produces an immutable Snapshot.
func (a *Assembler) Build() (snapshot.Snapshot, error) {
	const op = "snapshot.builder.Assembler.Build"

	// 1. Finalize collection with deterministic ordering
	sortedKeys := make([]string, 0, len(a.objects))
	for k := range a.objects {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	finalObjects := make([]snapshot.NormalizedObject, 0, len(a.objects))
	for _, k := range sortedKeys {
		finalObjects = append(finalObjects, a.objects[k])
	}

	snap := snapshot.Snapshot{
		SnapshotID:      a.snapshotID,
		SnapshotVersion: snapshot.SnapshotVersion,
		CreatedAt:       a.createdAt,
		Source:          a.source,
		ResourceType:    a.resourceType,
		Scope:           a.scope,
		Pagination:      a.pagination,
		Collection: snapshot.ResourceCollection{
			ObjectCount: len(finalObjects),
			Objects:     finalObjects,
		},
		Provenance: a.provenance,
	}

	// 2. Calculate integrity
	integrity, err := a.calculateIntegrity(snap)
	if err != nil {
		return snapshot.Snapshot{}, apperr.Wrap(op, err)
	}
	snap.Integrity = integrity

	// 3. Derive SnapshotID if missing
	if snap.SnapshotID == "" {
		snap.SnapshotID = fmt.Sprintf("snap-%s", snap.Integrity.SnapshotChecksum[:16])
	}

	return snap, nil
}

func (a *Assembler) calculateIntegrity(s snapshot.Snapshot) (snapshot.IntegrityMetadata, error) {
	var objHashes []string
	for _, obj := range s.Collection.Objects {
		h := sha256.Sum256([]byte(snapshot.CanonicalJSON(obj.Attributes) + obj.StableIdentityKey))
		objHashes = append(objHashes, hex.EncodeToString(h[:]))
	}

	// Canonical hash of discovery state (resource type + sorted objects)
	canonPayload := struct {
		ResourceType snapshot.ResourceType       `json:"resource_type"`
		Objects      []snapshot.NormalizedObject `json:"objects"`
	}{
		ResourceType: s.ResourceType,
		Objects:      s.Collection.Objects,
	}
	ch := sha256.Sum256([]byte(snapshot.CanonicalJSON(canonPayload)))

	// Snapshot checksum (full payload)
	sh := sha256.Sum256([]byte(snapshot.CanonicalJSON(s)))

	return snapshot.IntegrityMetadata{
		SnapshotChecksum: hex.EncodeToString(sh[:]),
		CanonicalHash:    hex.EncodeToString(ch[:]),
		ObjectHashes:     objHashes,
	}, nil
}
