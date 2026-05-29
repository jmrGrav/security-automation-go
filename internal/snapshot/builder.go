package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// RawScope represents unhashed IDs before they are normalized into ScopeMetadata.
type RawScope struct {
	AccountID string
	ZoneID    string
	ScopeType string
}

// BuilderInput provides the data and context required to generate a Snapshot.
type BuilderInput struct {
	SnapshotID   string
	CreatedAt    time.Time
	Source       SnapshotSource
	ResourceType ResourceType
	Scope        RawScope
	Pagination   PaginationMetadata
	Provenance   ProvenanceMetadata

	RawJSON     []byte
	ObjectsPath []string

	CapturedAt    time.Time
	SourcePage    int
	SchemaVersion int
}

type Builder struct{}

func NewBuilder() Builder {
	return Builder{}
}

func (b Builder) Build(input BuilderInput) (Snapshot, error) {
	const op = "snapshot.Builder.Build"

	if len(input.RawJSON) == 0 {
		return Snapshot{}, apperr.New(op, "raw JSON is required")
	}
	if strings.TrimSpace(input.Source.Provider) == "" {
		return Snapshot{}, apperr.New(op, "source provider is required")
	}

	createdAt := input.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	capturedAt := input.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = createdAt
	}

	root, err := b.decodeStrict(input.RawJSON)
	if err != nil {
		return Snapshot{}, apperr.Wrap(op, err)
	}

	items, err := b.extractObjects(root, input.ObjectsPath)
	if err != nil {
		return Snapshot{}, apperr.Wrap(op, err)
	}

	objects, err := b.normalizeObjects(input, capturedAt, items)
	if err != nil {
		return Snapshot{}, apperr.Wrap(op, err)
	}

	// Ensure deterministic ordering
	sort.Slice(objects, func(i, j int) bool {
		if objects[i].StableIdentityKey != objects[j].StableIdentityKey {
			return objects[i].StableIdentityKey < objects[j].StableIdentityKey
		}
		return CanonicalJSON(objects[i].Attributes) < CanonicalJSON(objects[j].Attributes)
	})

	snapshot := Snapshot{
		SnapshotID:      input.SnapshotID,
		SnapshotVersion: SnapshotVersion,
		CreatedAt:       createdAt,
		Source:          input.Source,
		ResourceType:    input.ResourceType,
		Scope: ScopeMetadata{
			AccountIDHash: b.hashID(input.Scope.AccountID),
			ZoneIDHash:    b.hashID(input.Scope.ZoneID),
			ScopeType:     input.Scope.ScopeType,
		},
		Pagination: input.Pagination,
		Collection: ResourceCollection{
			ObjectCount: len(objects),
			Objects:     objects,
		},
		Provenance: input.Provenance,
	}

	if snapshot.Provenance.GeneratedAt.IsZero() {
		snapshot.Provenance.GeneratedAt = snapshot.CreatedAt
	}

	// Finalize integrity
	integrity, err := b.calculateIntegrity(snapshot)
	if err != nil {
		return Snapshot{}, apperr.Wrap(op, err)
	}
	snapshot.Integrity = integrity

	if snapshot.SnapshotID == "" {
		snapshot.SnapshotID = fmt.Sprintf("snap-%s", snapshot.Integrity.SnapshotChecksum[:16])
	}

	return snapshot, nil
}

func (b Builder) decodeStrict(raw []byte) (any, error) {
	const op = "snapshot.decodeStrict"

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, apperr.Wrap(op, err)
	}

	// Check for trailing garbage
	var trailing any
	if err := decoder.Decode(&trailing); err != nil {
		if err == io.EOF {
			return root, nil
		}
		return nil, apperr.Wrap(op, err)
	}
	return nil, apperr.New(op, "unexpected trailing JSON content")
}

func (b Builder) extractObjects(root any, path []string) ([]any, error) {
	const op = "snapshot.extractObjects"

	current := root
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, apperr.New(op, fmt.Sprintf("path traversal failed at %q", key))
		}
		next, ok := m[key]
		if !ok {
			return nil, apperr.New(op, fmt.Sprintf("key %q not found in path", key))
		}
		current = next
	}

	switch v := current.(type) {
	case []any:
		return v, nil
	case map[string]any:
		return []any{v}, nil
	case nil:
		return []any{}, nil
	default:
		return nil, apperr.New(op, "extracted objects must be an array or a single object")
	}
}

func (b Builder) normalizeObjects(input BuilderInput, capturedAt time.Time, items []any) ([]NormalizedObject, error) {
	const op = "snapshot.normalizeObjects"

	objects := make([]NormalizedObject, 0, len(items))
	for i, item := range items {
		rawAttrs, ok := item.(map[string]any)
		if !ok {
			return nil, apperr.New(op, fmt.Sprintf("item %d is not an object", i))
		}

		// 1. Filter and normalize attributes
		attrs := b.filterAttributes(input.ResourceType, rawAttrs)

		// 2. Generate stable identity key
		sik := b.generateSIK(input.ResourceType, attrs)

		// 3. Capture provider ID (informational)
		objectID, _ := rawAttrs["id"].(string)

		objects = append(objects, NormalizedObject{
			ObjectID:          objectID,
			ObjectType:        string(input.ResourceType),
			StableIdentityKey: sik,
			Attributes:        attrs,
			Metadata: ObjectMetadata{
				SourcePage:    input.SourcePage,
				CapturedAt:    capturedAt,
				SchemaVersion: input.SchemaVersion,
			},
		})
	}
	return objects, nil
}

func (b Builder) filterAttributes(rt ResourceType, raw map[string]any) map[string]any {
	// Only include stable, decision-making attributes.
	// We avoid Cloudflare-managed timestamps, internal refs, etc.
	out := make(map[string]any)

	switch rt {
	case ResourceIPAccessRules:
		b.copyKeys(out, raw, "mode", "notes")
		if config, ok := raw["configuration"].(map[string]any); ok {
			conf := make(map[string]any)
			b.copyKeys(conf, config, "target", "value")
			out["configuration"] = conf
		}
	case ResourceListItems:
		b.copyKeys(out, raw, "ip", "comment")
	case ResourceLists:
		b.copyKeys(out, raw, "name", "description", "kind")
	default:
		// Generic fallback: include all keys except common volatile ones
		for k, v := range raw {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "time") || strings.Contains(kl, "date") || kl == "id" || kl == "modified_on" || kl == "created_on" {
				continue
			}
			out[k] = v
		}
	}
	return out
}

func (b Builder) copyKeys(dst, src map[string]any, keys ...string) {
	for _, k := range keys {
		if v, ok := src[k]; ok {
			dst[k] = b.normalizeValue(v)
		}
	}
}

func (b Builder) normalizeValue(v any) any {
	switch typed := v.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]any:
		return b.cloneMap(typed)
	case []any:
		return b.cloneSlice(typed)
	default:
		return v
	}
}

func (b Builder) generateSIK(rt ResourceType, attrs map[string]any) string {
	// StableIdentityKey logic: domain-controlled identity
	switch rt {
	case ResourceIPAccessRules:
		mode, _ := attrs["mode"].(string)
		if config, ok := attrs["configuration"].(map[string]any); ok {
			target, _ := config["target"].(string)
			value, _ := config["value"].(string)
			return fmt.Sprintf("ip:%s:%s:%s", target, value, mode)
		}
	case ResourceListItems:
		if ip, ok := attrs["ip"].(string); ok {
			return fmt.Sprintf("list_item:%s", ip)
		}
	case ResourceLists:
		if name, ok := attrs["name"].(string); ok {
			return fmt.Sprintf("list:%s", name)
		}
	}

	// Fallback to hashing stable attributes if no specific logic exists
	sum := sha256.Sum256([]byte(string(rt) + ":" + CanonicalJSON(attrs)))
	return "derived:" + hex.EncodeToString(sum[:16])
}

func (b Builder) hashID(id string) string {
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

func (b Builder) calculateIntegrity(s Snapshot) (IntegrityMetadata, error) {
	const op = "snapshot.calculateIntegrity"

	var objHashes []string
	for _, obj := range s.Collection.Objects {
		h := sha256.Sum256([]byte(CanonicalJSON(obj.Attributes) + obj.StableIdentityKey))
		objHashes = append(objHashes, hex.EncodeToString(h[:]))
	}

	// Canonical hash of objects only (discovery state)
	canonPayload := struct {
		ResourceType ResourceType       `json:"resource_type"`
		Objects      []NormalizedObject `json:"objects"`
	}{
		ResourceType: s.ResourceType,
		Objects:      s.Collection.Objects,
	}
	ch := sha256.Sum256([]byte(CanonicalJSON(canonPayload)))

	// Snapshot checksum (full payload)
	sh := sha256.Sum256([]byte(CanonicalJSON(s)))

	return IntegrityMetadata{
		SnapshotChecksum: hex.EncodeToString(sh[:]),
		CanonicalHash:    hex.EncodeToString(ch[:]),
		ObjectHashes:     objHashes,
	}, nil
}

func (b Builder) cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = b.cloneValue(v)
	}
	return out
}

func (b Builder) cloneSlice(src []any) []any {
	out := make([]any, len(src))
	for i, v := range src {
		out[i] = b.cloneValue(v)
	}
	return out
}

func (b Builder) cloneValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return b.cloneMap(typed)
	case []any:
		return b.cloneSlice(typed)
	default:
		return v
	}
}

func CanonicalJSON(value any) string {
	var buf bytes.Buffer
	writeCanonicalJSON(&buf, value)
	return buf.String()
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) {
	switch typed := value.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		encoded, _ := json.Marshal(typed)
		buf.Write(encoded)
	case bool:
		if typed {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(typed.String())
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			json.NewEncoder(buf).Encode(k)
			buf.Truncate(buf.Len() - 1) // Remove newline from Encode
			buf.WriteByte(':')
			writeCanonicalJSON(buf, typed[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, v := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalJSON(buf, v)
		}
		buf.WriteByte(']')
	case time.Time:
		buf.WriteByte('"')
		buf.WriteString(typed.UTC().Format(time.RFC3339Nano))
		buf.WriteByte('"')
	default:
		json.NewEncoder(buf).Encode(typed)
		buf.Truncate(buf.Len() - 1)
	}
}
