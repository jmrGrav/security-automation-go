package manifest

import (
	"time"
)

type SignatureEnvelope struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	Signature []byte    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

type ProvenanceMetadata struct {
	SourceRepo    string `json:"source_repo,omitempty"`
	CommitSHA     string `json:"commit_sha,omitempty"`
	BuildPipeline string `json:"build_pipeline,omitempty"`
	Author        string `json:"author,omitempty"`
}

type CompatibilityMatrix struct {
	MinRuntimeVersion string   `json:"min_runtime_version"`
	MaxRuntimeVersion string   `json:"max_runtime_version,omitempty"`
	RequiredInputs    []string `json:"required_inputs,omitempty"`
}

type RegoFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// BundleManifest is the root metadata for a signed policy bundle.
type BundleManifest struct {
	BundleID      string              `json:"bundle_id"`
	Version       string              `json:"version"`
	CreatedAt     time.Time           `json:"created_at"`
	CreatedBy     string              `json:"created_by"`
	SHA256        string              `json:"sha256"`
	Files         []RegoFile          `json:"files"`
	Signature     SignatureEnvelope   `json:"signature"`
	Provenance    ProvenanceMetadata  `json:"provenance"`
	Compatibility CompatibilityMatrix `json:"compatibility"`
}
