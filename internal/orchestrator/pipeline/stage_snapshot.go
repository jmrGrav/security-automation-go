package pipeline

import (
	"fmt"
	"time"

	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/snapshot"
	"github.com/jm/security-automation-go/internal/snapshot/builder"
)

func (o *Orchestrator) runSnapshotStage(rt snapshot.ResourceType, rules []cfmodels.IPAccessRule, provenance snapshot.ProvenanceMetadata) (*snapshot.Snapshot, error) {
	objects := o.cfClient.Normalizer.IPAccessRules(rules)
	assembler := builder.NewAssembler(rt)
	assembler.SetMetadata(fmt.Sprintf("run-%d", time.Now().Unix()), snapshot.SnapshotSource{Provider: "cloudflare"}, snapshot.ScopeMetadata{}, snapshot.PaginationMetadata{}, provenance)
	if err := assembler.Add(objects); err != nil {
		return nil, err
	}
	snap, err := assembler.Build()
	if err != nil {
		return nil, err
	}
	metrics.SnapshotObjectsTotal.Set(float64(snap.Collection.ObjectCount))
	return &snap, nil
}
