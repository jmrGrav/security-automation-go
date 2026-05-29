package drift

import (
	"strings"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Classifier determines the nature of the detected drift.
type Classifier struct {
	registry *resources.Registry
}

func NewClassifier(r *resources.Registry) *Classifier {
	return &Classifier{registry: r}
}

func (c *Classifier) Classify(event *DriftEvent) {
	// 1. Ownership check
	descriptor, ok := c.registry.Get(snapshot.ResourceType(event.ResourceType))
	if ok && descriptor.DefaultOwner == resources.OwnershipExternallyOwned {
		event.Classification = ClassOwnership
		return
	}

	// 2. Convergence artifacts (post-apply)
	if strings.Contains(strings.ToLower(event.Diff), "convergence") {
		event.Classification = ClassConvergence
		return
	}

	// 3. Destructive changes (Hostile candidate)
	if strings.Contains(strings.ToLower(event.Diff), "deleted") ||
		strings.Contains(strings.ToLower(event.Diff), "removed") {
		event.Classification = ClassHostile
		return
	}

	// Default to operator or benign depending on content
	if event.Diff == "" || strings.Contains(event.Diff, "timestamp") {
		event.Classification = ClassBenign
	} else {
		event.Classification = ClassOperator
	}
}

// Scorer calculates the risk severity and score.
type Scorer struct{}

func NewScorer() *Scorer {
	return &Scorer{}
}

func (s *Scorer) Score(event *DriftEvent) {
	switch event.Classification {
	case ClassHostile:
		event.RiskLevel = LevelCritical
		event.RiskScore = 0.9
	case ClassOwnership:
		event.RiskLevel = LevelHigh
		event.RiskScore = 0.8
	case ClassOscillation:
		event.RiskLevel = LevelHigh
		event.RiskScore = 0.7
	case ClassConvergence:
		event.RiskLevel = LevelMedium
		event.RiskScore = 0.5
	case ClassOperator:
		event.RiskLevel = LevelLow
		event.RiskScore = 0.2
	case ClassBenign:
		event.RiskLevel = LevelInfo
		event.RiskScore = 0.1
	default:
		event.RiskLevel = LevelMedium
		event.RiskScore = 0.4
	}
}
