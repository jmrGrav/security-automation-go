package reporting

import (
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type preparedDecision struct {
	classification classifier.Classification
	comment        string
	telemetry      tmevents.SecurityEvent
}

func (s *Service) prepareDecision(req Request) preparedDecision {
	cls := classifier.Classify(req.Event)
	comment := abuseformat.Build(abuseformat.Input{
		Source:     req.Source,
		Hits:       req.Event.Hits,
		WindowSec:  req.Event.WindowSec,
		Action:     req.Event.Action,
		AbuseType:  cls.AbuseType,
		Categories: cls.Categories,
		RuleID:     ruleID(req.Event.RuleID),
		URIs:       eventURIs(req.Event),
		Confidence: cls.Confidence,
	})
	recordCommentMetrics(req.Source, req.Event, comment, cls)
	return preparedDecision{
		classification: cls,
		comment:        comment,
		telemetry:      baseTelemetryEvent(req, cls, comment),
	}
}

func baseTelemetryEvent(req Request, cls classifier.Classification, comment string) tmevents.SecurityEvent {
	return tmevents.SecurityEvent{
		Timestamp:         req.Event.Timestamp,
		Source:            telemetrySource(req.Source),
		IP:                req.Event.IP,
		URI:               req.Event.URI,
		Hostname:          req.Event.Hostname,
		RuleID:            req.Event.RuleID,
		AbuseType:         cls.AbuseType,
		RiskScore:         cls.RiskScore,
		Confidence:        cls.Confidence,
		EnforcementStage:  cls.EnforcementStage,
		Propagated:        false,
		AbuseIPDBReported: false,
		CloudflareBanned:  false,
		Severity:          severityFor(cls.AbuseType),
		Metadata: map[string]any{
			"canonical_comment": comment,
			"categories":        append([]string(nil), cls.Categories...),
			"replay_evidence":   append([]string(nil), cls.Evidence...),
		},
	}
}
