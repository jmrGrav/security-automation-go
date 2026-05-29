package ownership

import (
	"context"
	"fmt"
	"time"
)

type LineageSearchOptions struct {
	ScopeID         string
	ResourceID      string
	BeforeCreatedAt time.Time
	BeforeID        string
	Limit           int
}

type LineageStore interface {
	GetLineage(ctx context.Context, eventID string) (LineageEvent, bool, error)
	ListLineage(ctx context.Context, scopeID string, resourceID string, limit int) ([]LineageEvent, error)
	ListLineageCursor(ctx context.Context, scopeID string, resourceID string, beforeCreatedAt time.Time, beforeID string, limit int) ([]LineageEvent, error)
}

type LineageQueryService struct {
	store LineageStore
}

func NewLineageQueryService(store LineageStore) *LineageQueryService {
	return &LineageQueryService{store: store}
}

func (s *LineageQueryService) Get(ctx context.Context, eventID string) (LineageEvent, bool, error) {
	if s == nil || s.store == nil {
		return LineageEvent{}, false, fmt.Errorf("ownership lineage store unavailable")
	}
	return s.store.GetLineage(ctx, eventID)
}

func (s *LineageQueryService) Search(ctx context.Context, opts LineageSearchOptions) ([]LineageEvent, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("ownership lineage store unavailable")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}
	return s.store.ListLineageCursor(ctx, opts.ScopeID, opts.ResourceID, opts.BeforeCreatedAt, opts.BeforeID, limit)
}

type LineageExplanation struct {
	EventID       string    `json:"event_id"`
	ScopeID       string    `json:"scope_id"`
	ResourceID    string    `json:"resource_id"`
	DomainID      string    `json:"domain_id"`
	EventType     string    `json:"event_type"`
	Decision      string    `json:"decision,omitempty"`
	RequiredRight string    `json:"required_right,omitempty"`
	OwnerDomain   string    `json:"owner_domain,omitempty"`
	Epoch         int64     `json:"epoch,omitempty"`
	FencingToken  int64     `json:"fencing_token,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	DecisionHash  string    `json:"decision_hash"`
	CreatedAt     time.Time `json:"created_at"`
	HumanReason   string    `json:"human_reason"`
}

func ExplainLineageEvent(event LineageEvent) LineageExplanation {
	reason := "ownership lineage event recorded"
	switch event.EventType {
	case LineageEventClaim:
		reason = "ownership claim asserted"
	case LineageEventResolve:
		if event.Decision == "allow" || event.Decision == "override" {
			reason = "ownership resolution granted mutation rights"
		} else {
			reason = "ownership resolution denied or restricted mutation rights"
		}
	}
	return LineageExplanation{
		EventID:       event.ID,
		ScopeID:       event.ScopeID,
		ResourceID:    event.ResourceID,
		DomainID:      event.DomainID,
		EventType:     string(event.EventType),
		Decision:      event.Decision,
		RequiredRight: string(event.RequiredRight),
		OwnerDomain:   event.OwnerDomain,
		Epoch:         event.Epoch,
		FencingToken:  event.FencingToken,
		Reason:        event.Reason,
		DecisionHash:  event.DecisionHash,
		CreatedAt:     event.CreatedAt,
		HumanReason:   reason,
	}
}
