// Package confidence scores security decisions before they are allowed to
// propagate into stronger enforcement layers. The goal is fail-safe governance:
// weak or ambiguous evidence must degrade toward review, quarantine, or
// observe-only behavior rather than hard deny and broad propagation.
package confidence

import (
	"math"
	"sort"
)

type Evidence struct {
	Source      string  `json:"source"`
	Category    string  `json:"category"`
	Weight      float64 `json:"weight"`
	Reference   string  `json:"reference"`
	Penalty     float64 `json:"penalty"`
	ReplayToken string  `json:"replay_token"`
}

type Policy struct {
	ReviewThreshold float64 `json:"review_threshold"`
	HardDenyFloor   float64 `json:"hard_deny_floor"`
	GlobalFloor     float64 `json:"global_floor"`
}

type DecisionConfidence struct {
	Score               float64  `json:"score"`
	EvidenceCount       int      `json:"evidence_count"`
	Sources             []string `json:"sources"`
	DetectionCategory   string   `json:"detection_category"`
	ReplayEvidence      []string `json:"replay_evidence"`
	RequiresHumanReview bool     `json:"requires_human_review"`
	AllowHardDeny       bool     `json:"allow_hard_deny"`
	AllowGlobalAction   bool     `json:"allow_global_action"`
}

func DefaultPolicy() Policy {
	return Policy{
		ReviewThreshold: 0.70,
		HardDenyFloor:   0.85,
		GlobalFloor:     0.95,
	}
}

func Score(evidence []Evidence, detectionCategory string, policy Policy) DecisionConfidence {
	score := 0.0
	sourcesSet := make(map[string]struct{}, len(evidence))
	replay := make([]string, 0, len(evidence))

	for _, item := range evidence {
		weight := clamp(item.Weight-item.Penalty, 0, 1)
		score += weight
		if item.Source != "" {
			sourcesSet[item.Source] = struct{}{}
		}
		if item.ReplayToken != "" {
			replay = append(replay, item.ReplayToken)
		}
	}

	normalized := 0.0
	if len(evidence) > 0 {
		normalized = clamp(score/float64(len(evidence)), 0, 1)
	}

	sources := make([]string, 0, len(sourcesSet))
	for source := range sourcesSet {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	sort.Strings(replay)

	return DecisionConfidence{
		Score:               normalized,
		EvidenceCount:       len(evidence),
		Sources:             sources,
		DetectionCategory:   detectionCategory,
		ReplayEvidence:      replay,
		RequiresHumanReview: normalized < policy.ReviewThreshold || len(evidence) == 0,
		AllowHardDeny:       normalized >= policy.HardDenyFloor,
		AllowGlobalAction:   normalized >= policy.GlobalFloor,
	}
}

func clamp(v, minV, maxV float64) float64 {
	return math.Max(minV, math.Min(maxV, v))
}
