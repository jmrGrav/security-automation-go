package ownership

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

type LineageRecorder interface {
	Append(event LineageEvent) error
}

func BuildDecisionHash(eventType LineageEventType, scopeID string, resourceID string, domainID string, decision string, reason string, requiredRight Right, owner string, epoch int64) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%d", eventType, scopeID, resourceID, domainID, decision, reason, requiredRight, owner, epoch)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func RebuildClaimsFromLineage(events []LineageEvent) map[string]OwnershipClaim {
	sorted := make([]LineageEvent, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})

	out := make(map[string]OwnershipClaim)
	for _, event := range sorted {
		if event.EventType != LineageEventClaim {
			continue
		}
		key := claimKey(event.ScopeID, event.ResourceID)
		out[key] = OwnershipClaim{
			ScopeID:    event.ScopeID,
			ResourceID: event.ResourceID,
			DomainID:   event.DomainID,
			Epoch:      event.Epoch,
			Timestamp:  event.CreatedAt,
		}
	}
	return out
}

func claimKey(scopeID string, resourceID string) string {
	return scopeID + "|" + resourceID
}

func NewLineageEventID(scopeID string, resourceID string, createdAt time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", scopeID, resourceID, createdAt.UTC().UnixNano())))
	return hex.EncodeToString(sum[:16])
}
