package reporting

import (
	"sort"
	"strings"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
)

const abuseAggregationWindow = 30 * time.Second

func buildAggregatedReport(req Request, cls classifier.Classification, now time.Time) abmodels.ExecutableReport {
	uris := eventURIs(req.Event)
	ruleIDValue := ruleID(req.Event.RuleID)
	report := abmodels.ExecutableReport{
		ExecutionID:       executionID(req, cls),
		StableIdentityKey: fingerprint(req, cls),
		IP:                req.Event.IP,
		Source:            string(req.Source),
		AbuseType:         cls.AbuseType,
		Categories:        categoryIDs(cls.Categories),
		Action:            strings.TrimSpace(req.Event.Action),
		Comment:           "",
		OriginatingOpID:   req.Event.RuleID,
		CreatedAt:         now.UTC(),
		Hits:              maxIntLocal(1, req.Event.Hits),
		WindowSec:         int(abuseAggregationWindow.Seconds()),
		URIs:              append([]string(nil), uris...),
		RuleIDs:           []string{ruleIDValue},
		Sources:           []string{telemetrySource(req.Source)},
		ConfidenceSum:     cls.Confidence,
		ConfidenceCount:   1,
		ConfidenceMax:     cls.Confidence,
	}
	report.Comment = aggregatedAbuseComment(report)
	return report
}

func MergeExecutableReports(existing, incoming abmodels.ExecutableReport) abmodels.ExecutableReport {
	if existing.ExecutionID == "" {
		existing.ExecutionID = incoming.ExecutionID
	}
	if existing.StableIdentityKey == "" {
		existing.StableIdentityKey = incoming.StableIdentityKey
	}
	if existing.IP == "" {
		existing.IP = incoming.IP
	}
	if existing.Source == "" {
		existing.Source = incoming.Source
	}
	if existing.AbuseType == "" {
		existing.AbuseType = incoming.AbuseType
	}
	if existing.OriginatingOpID == "" {
		existing.OriginatingOpID = incoming.OriginatingOpID
	}
	if existing.CreatedAt.IsZero() || (!incoming.CreatedAt.IsZero() && incoming.CreatedAt.Before(existing.CreatedAt)) {
		existing.CreatedAt = incoming.CreatedAt
	}
	if existing.WindowSec < incoming.WindowSec {
		existing.WindowSec = incoming.WindowSec
	}
	if existing.Action == "" {
		existing.Action = incoming.Action
	} else if incoming.Action != "" && !strings.Contains(","+existing.Action+",", ","+incoming.Action+",") {
		existing.Action = existing.Action + "," + incoming.Action
	}
	existing.Hits += incoming.Hits
	existing.Categories = mergeCSV(existing.Categories, incoming.Categories)
	existing.URIs = mergeUnique(existing.URIs, incoming.URIs)
	existing.RuleIDs = mergeUnique(existing.RuleIDs, incoming.RuleIDs)
	existing.Sources = mergeUnique(existing.Sources, incoming.Sources)
	existing.ConfidenceSum += incoming.ConfidenceSum
	existing.ConfidenceCount += incoming.ConfidenceCount
	if incoming.ConfidenceMax > existing.ConfidenceMax {
		existing.ConfidenceMax = incoming.ConfidenceMax
	}
	existing.Comment = aggregatedAbuseComment(existing)
	return existing
}

func aggregatedAbuseComment(report abmodels.ExecutableReport) string {
	confidence := report.ConfidenceMax
	if report.ConfidenceCount > 0 {
		confidence = report.ConfidenceSum / float64(report.ConfidenceCount)
	}
	categories := splitCSV(report.Categories)
	uris := append([]string(nil), report.URIs...)
	sort.Strings(categories)
	sort.Strings(uris)
	action := strings.TrimSpace(report.Action)
	if action == "" {
		action = "block"
	}
	source := abuseformat.Source(report.Source)
	if source == "" {
		source = abuseformat.SourceCloudflareWAF
	}
	ruleID := ""
	if len(report.RuleIDs) > 0 {
		ruleID = report.RuleIDs[0]
	}
	return abuseformat.Build(abuseformat.Input{
		Source:     source,
		Hits:       report.Hits,
		WindowSec:  maxIntLocal(1, report.WindowSec),
		Action:     action,
		AbuseType:  report.AbuseType,
		Categories: categories,
		RuleID:     ruleID,
		URIs:       uris,
		Confidence: confidence,
	})
}

func mergeCSV(existing, incoming string) string {
	return strings.Join(mergeUnique(splitCSV(existing), splitCSV(incoming)), ",")
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func mergeUnique(values ...[]string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, list := range values {
		for _, value := range list {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	return out
}

func maxIntLocal(a, b int) int {
	if a > b {
		return a
	}
	return b
}
