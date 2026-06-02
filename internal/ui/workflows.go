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
	Title     string
	Headline  string
	Subtitle  string
	Active    string
	Intro     string
	Badges    []StatusItem
	Sections  []workflowSection
	EmptyText string
}

func workflowProjectionPage(view workflowProjectionView) templ.Component {
	return ConsoleLayout(shellView{
		Title:       view.Title,
		Headline:    view.Headline,
		Subtitle:    view.Subtitle,
		Active:      view.Active,
		BadgeLabels: view.Badges,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
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
	desiredMode := cloudflareModeText(s.cfg.Cloudflare.APIToken, s.cfg.Cloudflare.ZoneID, s.cfg.Cloudflare.MutationsEnabled)
	desiredRows := []keyValueRow{
		{Key: "mode", Value: desiredMode},
		{Key: "mutations enabled", Value: boolDetail(s.cfg.Cloudflare.MutationsEnabled, "enabled", "disabled")},
		{Key: "token configured", Value: configuredText(strings.TrimSpace(s.cfg.Cloudflare.APIToken) != "")},
		{Key: "zone configured", Value: configuredText(strings.TrimSpace(s.cfg.Cloudflare.ZoneID) != "")},
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
	if strings.TrimSpace(s.cfg.Cloudflare.APIToken) == "" {
		missing = append(missing, "API token is missing from the local configuration")
	}
	if strings.TrimSpace(s.cfg.Cloudflare.ZoneID) == "" {
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
		Title:    "Cloudflare Diff",
		Headline: "Cloudflare Diff",
		Subtitle: "Read-only desired-versus-observed projection for Cloudflare boundary health.",
		Active:   "/cloudflare/diff",
		Intro:    "This view compares the local Cloudflare intent with the currently observed provider posture. It is forensic only and does not execute mutations.",
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

func (s *Server) replayView() workflowProjectionView {
	return workflowProjectionView{
		Title:    "Replay",
		Headline: "Replay Center",
		Subtitle: "Checkpoint and snapshot projection for deterministic replay analysis.",
		Active:   "/replay",
		Intro:    "Replay remains read-only in the UI shell. This page explains the operator-facing data that will be shown once the replay store is wired through the control-plane.",
		Badges: []StatusItem{
			{Label: "Mode", Level: "dry-run", Detail: "read-only"},
			{Label: "Execution", Level: "warning", Detail: "not wired"},
		},
		Sections: []workflowSection{
			{Title: "Checkpoints", Description: "Runtime checkpoints visible to the UI server.", Rows: []keyValueRow{
				{Key: "latest checkpoint", Value: "unavailable"},
				{Key: "checkpoint scope", Value: "unavailable"},
				{Key: "checkpoint sequence", Value: "unavailable"},
			}},
			{Title: "Snapshots", Description: "Snapshot inventory available for replay inspection.", Rows: []keyValueRow{
				{Key: "available snapshots", Value: "unavailable"},
				{Key: "snapshot age", Value: "unavailable"},
				{Key: "snapshot source", Value: "not exposed to UI server"},
			}},
			{Title: "Replay status", Description: "Operator-visible replay state and gating.", Rows: []keyValueRow{
				{Key: "state", Value: "unavailable"},
				{Key: "validation", Value: "unavailable"},
				{Key: "execution", Value: "disabled in UI"},
			}},
			{Title: "Replay explain", Description: "Human-readable replay reasoning and lineage explanation.", Items: []string{
				"read-only projection only",
				"no replay execution path exposed",
				"checkpoint-aware explanation will appear once the store is wired",
			}},
			{Title: "Consistency indicators", Description: "Signals that matter for forensic replay review.", Rows: []keyValueRow{
				{Key: "deterministic replay", Value: "unavailable"},
				{Key: "evidence lineage", Value: "unavailable"},
				{Key: "ownership invariants", Value: "unavailable"},
			}},
		},
	}
}

func (s *Server) recoveryView() workflowProjectionView {
	return workflowProjectionView{
		Title:    "Recovery",
		Headline: "Recovery Center",
		Subtitle: "Snapshot, checkpoint, and validation projection for read-only recovery review.",
		Active:   "/recovery",
		Intro:    "Recovery remains read-only and does not expose a restore action from the UI. The page is structured so the future recovery store can be projected into the same operator shell.",
		Badges: []StatusItem{
			{Label: "Mode", Level: "dry-run", Detail: "read-only"},
			{Label: "Restore", Level: "disabled", Detail: "not exposed"},
		},
		Sections: []workflowSection{
			{Title: "Available snapshots", Description: "Snapshot inventory visible to the UI server.", Rows: []keyValueRow{
				{Key: "snapshot count", Value: "unavailable"},
				{Key: "latest snapshot", Value: "unavailable"},
				{Key: "snapshot retention", Value: "unavailable"},
			}},
			{Title: "Available checkpoints", Description: "Checkpoint inventory visible to the UI server.", Rows: []keyValueRow{
				{Key: "checkpoint count", Value: "unavailable"},
				{Key: "latest checkpoint", Value: "unavailable"},
				{Key: "checkpoint state", Value: "unavailable"},
			}},
			{Title: "Last recovery", Description: "The most recent recovery outcome projected into the console.", Rows: []keyValueRow{
				{Key: "last recovery", Value: "unavailable"},
				{Key: "recovery mode", Value: "unavailable"},
				{Key: "recovery result", Value: "unavailable"},
			}},
			{Title: "Recovery validation", Description: "Validation gates that protect the recovery path.", Items: []string{
				"restore from UI disabled",
				"validation remains read-only",
				"no second writer is introduced",
			}},
			{Title: "Recovery signals", Description: "Operator signals that will matter once the store is surfaced.", Rows: []keyValueRow{
				{Key: "snapshot age", Value: "unavailable"},
				{Key: "WAL health", Value: "unavailable"},
				{Key: "evidence status", Value: "unavailable"},
			}},
		},
	}
}

func (s *Server) driftView() workflowProjectionView {
	return workflowProjectionView{
		Title:    "Drift",
		Headline: "Drift Center",
		Subtitle: "Convergence and ownership drift projection for forensic review.",
		Active:   "/drift",
		Intro:    "Drift is read-only in the UI shell. The page is reserved for eventual convergence, oscillation, and ownership projection without exposing mutation controls.",
		Badges: []StatusItem{
			{Label: "Mode", Level: "dry-run", Detail: "read-only"},
			{Label: "Convergence", Level: "warning", Detail: "not wired"},
		},
		Sections: []workflowSection{
			{Title: "Active drift", Description: "Current drift indicators visible to the UI server.", Rows: []keyValueRow{
				{Key: "active drift", Value: "unknown"},
				{Key: "severity", Value: "unavailable"},
				{Key: "scope", Value: "unavailable"},
			}},
			{Title: "Historical drift", Description: "Historical drift evidence projected into the console.", Rows: []keyValueRow{
				{Key: "history", Value: "unavailable"},
				{Key: "last change", Value: "unavailable"},
				{Key: "drift source", Value: "not exposed to UI server"},
			}},
			{Title: "Oscillations", Description: "Oscillation signals and instability hotspots.", Rows: []keyValueRow{
				{Key: "oscillation count", Value: "unavailable"},
				{Key: "hotspots", Value: "unavailable"},
				{Key: "trend", Value: "unavailable"},
			}},
			{Title: "Impacted scopes", Description: "Scopes and resources that would be reviewed by the drift center.", Items: []string{
				"unavailable",
			}},
			{Title: "Ownership impact", Description: "Ownership lineage impact and quarantine hints.", Rows: []keyValueRow{
				{Key: "ownership impact", Value: "unavailable"},
				{Key: "lineage impact", Value: "unavailable"},
				{Key: "quarantine", Value: "unavailable"},
			}},
			{Title: "Convergence indicators", Description: "Signals that describe whether the system is converging or diverging.", Rows: []keyValueRow{
				{Key: "convergence", Value: "unavailable"},
				{Key: "determinism", Value: "unavailable"},
				{Key: "audit alignment", Value: "unavailable"},
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
