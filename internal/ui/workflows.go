package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/a-h/templ"
)

type workflowSection struct {
	Title       string
	Description string
	Rows        []keyValueRow
	Items       []string
	EmptyText   string
}

type workflowProjectionView struct {
	Title       string
	Headline    string
	Subtitle    string
	Active      string
	Intro       string
	Badges      []StatusItem
	SummaryRows []keyValueRow
	Sections    []workflowSection
	EmptyText   string
}

func workflowProjectionPage(view workflowProjectionView) templ.Component {
	return ConsoleLayout(shellView{
		Title:       view.Title,
		Headline:    view.Headline,
		Subtitle:    view.Subtitle,
		Active:      view.Active,
		BadgeLabels: view.Badges,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if len(view.SummaryRows) > 0 {
				if _, err := fmt.Fprint(w, `<div class="panel"><h3 style="margin:0 0 .65rem">Operator Summary</h3><div class="kv">`); err != nil {
					return err
				}
				for _, row := range view.SummaryRows {
					if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(valueOrUnknown(row.Value))); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(view.Intro)); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `</p></div>`); err != nil {
				return err
			}
			if len(view.Sections) == 0 {
				return writeEmptyState(w, valueOrUnknown(view.EmptyText))
			}
			if _, err := fmt.Fprint(w, `<section class="grid">`); err != nil {
				return err
			}
			for _, section := range view.Sections {
				if err := renderWorkflowSection(w, section); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</section>`)
			return err
		}),
	})
}

func renderWorkflowSection(w io.Writer, section workflowSection) error {
	if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<h2>%s</h2>`, html.EscapeString(section.Title)); err != nil {
		return err
	}
	if strings.TrimSpace(section.Description) != "" {
		if _, err := fmt.Fprintf(w, `<p class="muted">%s</p>`, html.EscapeString(section.Description)); err != nil {
			return err
		}
	}
	switch {
	case len(section.Rows) > 0:
		if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
			return err
		}
		for _, row := range section.Rows {
			if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(valueOrUnknown(row.Value))); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</div>`); err != nil {
			return err
		}
	case len(section.Items) > 0:
		if _, err := fmt.Fprint(w, `<div class="stack">`); err != nil {
			return err
		}
		for _, item := range section.Items {
			if _, err := fmt.Fprintf(w, `<div class="badge">%s</div>`, html.EscapeString(valueOrUnknown(item))); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</div>`); err != nil {
			return err
		}
	default:
		if _, err := fmt.Fprintf(w, `<div class="empty">%s</div>`, html.EscapeString(valueOrUnknown(section.EmptyText))); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func (s *Server) cloudflareDiffView() workflowProjectionView {
	cloudflare := s.providerHealthEntry("Cloudflare")
	tokenConfigured := s.cfSentinelToken() != ""
	zoneConfigured := s.cfZoneIDFromSetup(context.Background()) != ""
	desiredMode := cloudflareModeText(s.cfSentinelToken(), s.cfZoneIDFromSetup(context.Background()), s.cfg.Cloudflare.MutationsEnabled)
	desiredRows := []keyValueRow{
		{Key: "mode", Value: desiredMode},
		{Key: "mutations enabled", Value: boolDetail(s.cfg.Cloudflare.MutationsEnabled, "enabled", "disabled")},
		{Key: "token configured", Value: configuredText(tokenConfigured)},
		{Key: "zone configured", Value: configuredText(zoneConfigured)},
	}
	summaryRows := []keyValueRow{
		{Key: "configured", Value: boolDetail(tokenConfigured && zoneConfigured, "YES", "NO")},
		{Key: "token", Value: boolDetail(tokenConfigured, "YES", "NO — configure via wizard")},
		{Key: "zone", Value: boolDetail(zoneConfigured, "YES", "NO — configure via wizard")},
		{Key: "mode", Value: strings.ToUpper(desiredMode)},
		{Key: "quota", Value: cloudflare.QuotaRemaining},
		{Key: "next action", Value: cloudflareDiffNextAction(tokenConfigured, zoneConfigured, desiredMode)},
	}
	observedRows := []keyValueRow{
		{Key: "provider status", Value: cloudflare.Status},
		{Key: "enabled state", Value: cloudflare.EnabledState},
		{Key: "configured state", Value: cloudflare.ConfiguredState},
		{Key: "last validation", Value: cloudflare.LastValidation},
		{Key: "last success", Value: cloudflare.LastSuccess},
		{Key: "last error", Value: cloudflare.LastError},
		{Key: "quota state", Value: cloudflare.RateLimitCount},
		{Key: "quota remaining", Value: cloudflare.QuotaRemaining},
		{Key: "quota reset", Value: cloudflare.QuotaReset},
	}
	missing := []string{}
	if !tokenConfigured {
		missing = append(missing, "API token is missing from the local configuration")
	}
	if !zoneConfigured {
		missing = append(missing, "zone ID is missing from the local configuration")
	}
	if strings.EqualFold(cloudflare.ConfiguredState, "missing") {
		missing = append(missing, "Cloudflare provider boundary is not fully configured")
	}
	divergent := []string{}
	if strings.EqualFold(cloudflare.Status, "unknown") {
		divergent = append(divergent, "observed Cloudflare provider state is unavailable")
	}
	extra := []string{
		"no live mutation path is exposed from the UI",
	}
	return workflowProjectionView{
		Title:       "Cloudflare Diff",
		Headline:    "Cloudflare Diff",
		Subtitle:    "Read-only desired-versus-observed projection for Cloudflare boundary health.",
		Active:      "/cloudflare/diff",
		Intro:       "This view compares the local Cloudflare intent with the currently observed provider posture. It is forensic only and does not execute mutations.",
		SummaryRows: summaryRows,
		Badges: []StatusItem{
			{Label: "State", Level: providerStateClass(cloudflare.Status, strings.EqualFold(cloudflare.EnabledState, "enabled"), strings.EqualFold(cloudflare.ConfiguredState, "configured")), Detail: valueOrFallback(cloudflare.Status, "unknown")},
			{Label: "Mode", Level: "dry-run", Detail: desiredMode},
		},
		Sections: []workflowSection{
			{Title: "Desired state", Description: "Local operator intent derived from configuration and feature flags.", Rows: desiredRows},
			{Title: "Observed state", Description: "Read-only provider posture projected from the current UI-visible state.", Rows: observedRows},
			{Title: "Missing resources", Description: "Items that remain unset or unavailable in the current configuration.", Items: missing, EmptyText: "No missing resources surfaced by the UI projection."},
			{Title: "Divergent resources", Description: "Observed mismatches between intent and projection.", Items: divergent, EmptyText: "No divergent resources surfaced by the UI projection."},
			{Title: "Extra resources", Description: "Any read-only hints that do not map back to desired state.", Items: extra, EmptyText: "No extra resources surfaced by the UI projection."},
			{Title: "Drift summary", Description: "High-level summary of the Cloudflare boundary state.", Rows: []keyValueRow{
				{Key: "summary", Value: cloudflareDiffSummary(cloudflare, desiredMode)},
				{Key: "quota", Value: cloudflare.QuotaRemaining},
				{Key: "status code", Value: cloudflare.StatusCode},
			}},
			{Title: "Convergence summary", Description: "Read-only convergence posture and operator gating.", Rows: []keyValueRow{
				{Key: "gate", Value: "read-only"},
				{Key: "mutation path", Value: "not exposed in UI"},
				{Key: "validation", Value: cloudflare.LastValidation},
			}},
		},
	}
}

func cloudflareModeText(token, zoneID string, live bool) string {
	if strings.TrimSpace(token) == "" || strings.TrimSpace(zoneID) == "" {
		return "missing"
	}
	if live {
		return "live"
	}
	return "dry-run"
}

func cloudflareDiffSummary(entry providerHealthCenterEntry, desiredMode string) string {
	switch {
	case strings.EqualFold(entry.ConfiguredState, "missing"):
		return "Cloudflare configuration is incomplete, so the operator console can only project a dry-run boundary."
	case strings.EqualFold(desiredMode, "live") && strings.EqualFold(entry.Status, "unknown"):
		return "Live Cloudflare intent is configured, but the observed provider posture is unavailable from the UI server."
	case strings.EqualFold(desiredMode, "dry-run"):
		return "Cloudflare is intentionally held in dry-run mode by local feature flags."
	default:
		return "Read-only diff projection only; no live mutation path is exposed from this console."
	}
}

func cloudflareDiffNextAction(tokenConfigured, zoneConfigured bool, mode string) string {
	switch {
	case !tokenConfigured:
		return "configure API token via setup wizard"
	case !zoneConfigured:
		return "configure zone ID via setup wizard"
	case strings.EqualFold(mode, "missing"):
		return "complete Cloudflare configuration before enabling"
	case strings.EqualFold(mode, "dry-run"):
		return "review dry-run outputs, then enable mutations via config if satisfied"
	default:
		return "monitor live boundary — no action required"
	}
}

func (s *Server) providerHealthEntry(name string) providerHealthCenterEntry {
	for _, entry := range s.providerHealthCenterView() {
		if strings.EqualFold(entry.Name, name) {
			return entry
		}
	}
	return providerHealthCenterEntry{
		Name:            name,
		Description:     "unavailable",
		Status:          "unknown",
		Mode:            "unknown",
		EnabledState:    "disabled",
		ConfiguredState: "missing",
		LastValidation:  "unavailable",
		LastSuccess:     "unavailable",
		LastError:       "unavailable",
		ErrorCount:      "unavailable",
		RateLimitCount:  "unknown",
		QuotaRemaining:  providerQuotaNotExposed,
		QuotaUsed:       providerQuotaNotExposed,
		QuotaReset:      providerQuotaNotExposed,
		AvgLatency:      "unavailable",
		LastLatency:     "unavailable",
		CacheHits:       "unavailable",
		CacheMisses:     "unavailable",
		LastLookup:      "unavailable",
		StatusCode:      "unavailable",
	}
}
