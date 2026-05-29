package result

import (
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// PipelineResult aggregates the output of all stages in a single execution.
type PipelineResult struct {
	StartTime time.Time     `json:"start_time"`
	Duration  time.Duration `json:"duration_ms"`

	// Stage Results
	Discovery   DiscoveryStats   `json:"discovery"`
	Snapshot    SnapshotStats    `json:"snapshot"`
	Planning    PlanningStats    `json:"planning"`
	Translation TranslationStats `json:"translation"`

	// Final Artifacts (Dry-run)
	Plan    *reconciliation.Plan         `json:"plan,omitempty"`
	Actions []models.ExecutableOperation `json:"actions,omitempty"`

	// Metadata
	Provenance snapshot.ProvenanceMetadata `json:"provenance"`
	Warnings   []string                    `json:"warnings,omitempty"`
	Success    bool                        `json:"success"`
}

type DiscoveryStats struct {
	ResourceCount int `json:"resource_count"`
	PageCount     int `json:"page_count"`
}

type SnapshotStats struct {
	ObjectCount int    `json:"object_count"`
	Checksum    string `json:"checksum"`
}

type PlanningStats struct {
	OperationCount int `json:"operation_count"`
	Creates        int `json:"creates"`
	Updates        int `json:"updates"`
	Deletes        int `json:"deletions"`
}

type TranslationStats struct {
	ActionCount int `json:"action_count"`
}
