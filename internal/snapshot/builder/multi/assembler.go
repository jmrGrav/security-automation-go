package multi

import (
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/snapshot"
	"github.com/jm/security-automation-go/internal/snapshot/builder"
	"github.com/jm/security-automation-go/internal/snapshot/graph"
)

// GraphAssembler orchestrates the assembly of multiple resource types based on their dependencies.
type GraphAssembler struct {
	registry *resources.Registry
	builders map[snapshot.ResourceType]*builder.Assembler
	order    []snapshot.ResourceType

	provenance snapshot.ProvenanceMetadata
	createdAt  time.Time
}

func NewGraphAssembler(registry *resources.Registry) (*GraphAssembler, error) {
	const op = "snapshot.builder.multi.NewGraphAssembler"

	g := graph.New()
	for _, d := range registry.All() {
		for _, dep := range d.Dependencies {
			g.AddLink(d.Type, dep)
		}
	}

	order, err := g.ResolveOrder()
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	builders := make(map[snapshot.ResourceType]*builder.Assembler)
	for _, rt := range order {
		builders[rt] = builder.NewAssembler(rt)
	}

	return &GraphAssembler{
		registry:  registry,
		builders:  builders,
		order:     order,
		createdAt: time.Now().UTC(),
	}, nil
}

func (a *GraphAssembler) SetMetadata(prov snapshot.ProvenanceMetadata) {
	a.provenance = prov
}

func (a *GraphAssembler) SetCreatedAt(t time.Time) {
	a.createdAt = t.UTC()
	for _, b := range a.builders {
		b.SetCreatedAt(a.createdAt)
	}
}

// Add appends objects for a specific resource type.
func (a *GraphAssembler) Add(rt snapshot.ResourceType, objects []snapshot.NormalizedObject) error {
	const op = "snapshot.builder.multi.GraphAssembler.Add"

	b, ok := a.builders[rt]
	if !ok {
		return apperr.Newf(op, "unsupported resource type: %s", rt)
	}

	return b.Add(objects)
}

// BuildAll produces a list of snapshots in dependency order.
func (a *GraphAssembler) BuildAll() ([]snapshot.Snapshot, error) {
	const op = "snapshot.builder.multi.GraphAssembler.BuildAll"

	var snaps []snapshot.Snapshot
	for _, rt := range a.order {
		b := a.builders[rt]

		// In a multi-resource run, we might pass cross-resource metadata here.

		s, err := b.Build()
		if err != nil {
			return nil, apperr.Wrapf(op, err, "failed to build snapshot for %s", rt)
		}

		snaps = append(snaps, s)
	}

	return snaps, nil
}
