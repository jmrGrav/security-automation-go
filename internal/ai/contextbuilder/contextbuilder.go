package contextbuilder

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// Context is the sanitized payload intended for future explain providers.
type Context struct {
	Hash    string
	Payload string
}

// Builder constructs a read-only, redacted context for a future AI request.
type Builder interface {
	Build(ctx context.Context, req ai.ExplainRequest) (Context, error)
}

// EvidenceReader fetches stored pipeline decisions for an IP from the evidence store.
type EvidenceReader interface {
	Search(ctx context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error)
}

// IPEnricher performs real-time IP intelligence enrichment.
type IPEnricher interface {
	Enrich(ctx context.Context, ip netip.Addr, opts enrichment.LookupOptions) (enrichment.EnrichmentSummary, error)
}

// DefaultBuilder renders a JSON payload including relevant evidence.
type DefaultBuilder struct {
	Audit    audit.AuditReader
	Evidence EvidenceReader
	Enricher IPEnricher
}

type contextualAuditReader interface {
	EntriesContext(context.Context) ([]audit.AuditEntry, error)
}

// Build creates a compact context payload suitable for redaction and hashing.
func (b DefaultBuilder) Build(ctx context.Context, req ai.ExplainRequest) (Context, error) {
	if err := ctx.Err(); err != nil {
		return Context{}, err
	}

	// For intelligence (IP) subject type, pull enrichment data and evidence history.
	if req.SubjectType == ai.SubjectIntelligence {
		return b.buildIPContext(ctx, req)
	}

	var evidence []audit.AuditEntry
	if b.Audit != nil {
		all, err := readAuditEntries(ctx, b.Audit)
		if err != nil {
			return Context{}, err
		}
		for _, e := range all {
			if err := ctx.Err(); err != nil {
				return Context{}, err
			}
			if e.EventID == req.SubjectID || e.Correlation == req.SubjectID || e.Target == req.SubjectID {
				evidence = append(evidence, e)
			}
		}
		if len(evidence) == 0 && len(all) > 0 {
			start := len(all) - 10
			if start < 0 {
				start = 0
			}
			evidence = all[start:]
		}
	}

	payload := struct {
		SubjectType        ai.SubjectType     `json:"subject_type"`
		SubjectID          string             `json:"subject_id"`
		ProviderPreference string             `json:"provider_preference"`
		Evidence           []audit.AuditEntry `json:"evidence,omitempty"`
	}{
		SubjectType:        req.SubjectType,
		SubjectID:          req.SubjectID,
		ProviderPreference: req.ProviderPreference,
		Evidence:           evidence,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Context{}, fmt.Errorf("build ai context: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Context{}, err
	}
	return Context{Payload: string(raw)}, nil
}

func (b DefaultBuilder) buildIPContext(ctx context.Context, req ai.ExplainRequest) (Context, error) {
	ipStr := strings.TrimSpace(req.SubjectID)
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		// Fall back to audit-only if the subject ID is not a valid IP.
		return b.buildAuditOnlyContext(ctx, req)
	}

	type ipContextPayload struct {
		SubjectType        ai.SubjectType     `json:"subject_type"`
		SubjectID          string             `json:"subject_id"`
		ProviderPreference string             `json:"provider_preference"`
		Enrichment         *enrichmentSection `json:"enrichment,omitempty"`
		RecentDecisions    []decisionSummary  `json:"recent_decisions,omitempty"`
		AuditTrail         []audit.AuditEntry `json:"audit_trail,omitempty"`
	}

	ipCtx := ipContextPayload{
		SubjectType:        req.SubjectType,
		SubjectID:          ipStr,
		ProviderPreference: req.ProviderPreference,
	}

	// Enrichment: DNS, ASN, VT, CrowdSec.
	if b.Enricher != nil {
		summary, enrichErr := b.Enricher.Enrich(ctx, ip, enrichment.LookupOptions{ManualForensics: true})
		if enrichErr == nil {
			ipCtx.Enrichment = buildEnrichmentSection(summary)
		}
	}

	// Recent evidence decisions for this IP.
	if b.Evidence != nil {
		records, searchErr := b.Evidence.Search(ctx, reporting.EvidenceSearchOptions{
			IP:    ipStr,
			Limit: 15,
		})
		if searchErr == nil && len(records) > 0 {
			ipCtx.RecentDecisions = buildDecisionSummaries(records)
		}
	}

	// Audit trail entries targeting this IP.
	if b.Audit != nil {
		all, auditErr := readAuditEntries(ctx, b.Audit)
		if auditErr == nil {
			for _, e := range all {
				if e.Target == ipStr || e.EventID == req.SubjectID || e.Correlation == req.SubjectID {
					ipCtx.AuditTrail = append(ipCtx.AuditTrail, e)
				}
			}
		}
	}

	raw, err := json.Marshal(ipCtx)
	if err != nil {
		return Context{}, fmt.Errorf("build ip ai context: %w", err)
	}
	return Context{Payload: string(raw)}, nil
}

func (b DefaultBuilder) buildAuditOnlyContext(ctx context.Context, req ai.ExplainRequest) (Context, error) {
	var evidence []audit.AuditEntry
	if b.Audit != nil {
		all, err := readAuditEntries(ctx, b.Audit)
		if err != nil {
			return Context{}, err
		}
		for _, e := range all {
			if e.EventID == req.SubjectID || e.Correlation == req.SubjectID || e.Target == req.SubjectID {
				evidence = append(evidence, e)
			}
		}
		if len(evidence) == 0 && len(all) > 0 {
			start := len(all) - 10
			if start < 0 {
				start = 0
			}
			evidence = all[start:]
		}
	}
	payload := struct {
		SubjectType ai.SubjectType     `json:"subject_type"`
		SubjectID   string             `json:"subject_id"`
		Evidence    []audit.AuditEntry `json:"evidence,omitempty"`
	}{
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		Evidence:    evidence,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return Context{}, fmt.Errorf("build ai context: %w", err)
	}
	return Context{Payload: string(raw)}, nil
}

type enrichmentSection struct {
	Hostname  string            `json:"hostname,omitempty"`
	ASN       int               `json:"asn,omitempty"`
	ASNOrg    string            `json:"asn_org,omitempty"`
	Country   string            `json:"country,omitempty"`
	Providers []providerVerdict `json:"providers,omitempty"`
	CacheHit  bool              `json:"cache_hit,omitempty"`
}

type providerVerdict struct {
	Provider string `json:"provider"`
	Listed   bool   `json:"listed"`
	Score    int    `json:"score"`
	Detail   string `json:"detail,omitempty"`
}

type decisionSummary struct {
	EvidenceID        string `json:"evidence_id"`
	Timestamp         string `json:"timestamp"`
	Decision          string `json:"decision"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
	AbuseType         string `json:"abuse_type,omitempty"`
	Source            string `json:"source,omitempty"`
}

func buildEnrichmentSection(s enrichment.EnrichmentSummary) *enrichmentSection {
	sec := &enrichmentSection{
		Hostname: s.DNS.Hostname,
		ASN:      s.ASN.ASN,
		ASNOrg:   s.ASN.Org,
		Country:  s.ASN.Country,
		CacheHit: s.CacheHit,
	}
	for _, v := range s.Providers {
		sec.Providers = append(sec.Providers, providerVerdict{
			Provider: v.Provider,
			Listed:   v.Score > 0,
			Score:    v.Score,
			Detail:   v.Note,
		})
	}
	return sec
}

func buildDecisionSummaries(records []reporting.DecisionEvidence) []decisionSummary {
	out := make([]decisionSummary, 0, len(records))
	for _, r := range records {
		out = append(out, decisionSummary{
			EvidenceID:        r.EvidenceID,
			Timestamp:         r.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			Decision:          r.Decision,
			SuppressionReason: r.SuppressionReason,
			AbuseType:         r.AbuseType,
			Source:            r.Source,
		})
	}
	return out
}

func readAuditEntries(ctx context.Context, reader audit.AuditReader) ([]audit.AuditEntry, error) {
	if contextual, ok := reader.(contextualAuditReader); ok {
		return contextual.EntriesContext(ctx)
	}
	return reader.Entries(), nil
}
