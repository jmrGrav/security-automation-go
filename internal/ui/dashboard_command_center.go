package ui

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

const dashboardActivityLimit = 8

func dashboardHealthScore(statuses []StatusItem, env EnvironmentWidget, providers []AIProviderDashboardView, nonAIProviders []NonAIProviderEntry, freshness []DashboardFreshnessView, evidenceWired bool) DashboardHealthScoreView {
	total := 0
	points := 0
	var reasons []string

	add := func(label, level, detail string) {
		level = strings.ToLower(strings.TrimSpace(level))
		detail = strings.TrimSpace(detail)
		total++
		switch level {
		case "healthy", "live", "ready":
			points += 100
		case "warning", "degraded":
			points += 65
			reasons = append(reasons, dashboardReason(label, detail, level))
		case "disabled":
			points += 45
			reasons = append(reasons, dashboardReason(label, detail, level))
		case "unavailable", "unknown":
			points += 25
			reasons = append(reasons, dashboardReason(label, detail, level))
		case "error", "critical":
			reasons = append(reasons, dashboardReason(label, detail, level))
		default:
			points += 40
			reasons = append(reasons, dashboardReason(label, detail, "unknown"))
		}
	}

	for _, status := range statuses {
		add(status.Label, status.Level, status.Detail)
	}
	if env.Total > 0 {
		total++
		envScore := (env.Healthy * 100) / env.Total
		points += envScore
		if envScore < 100 {
			reasons = append(reasons, fmt.Sprintf("Environment: %d of %d healthy", env.Healthy, env.Total))
		}
	}
	for _, provider := range providers {
		add(provider.Name, provider.Status, provider.LastError)
	}
	for _, provider := range nonAIProviders {
		add(provider.Name, dashboardNonAIProviderLevel(provider), provider.LastErrorCode)
	}
	for _, item := range freshness {
		add(item.Label+" freshness", item.Level, item.Detail)
	}
	if !evidenceWired {
		total++
		points += 25
		reasons = append(reasons, "Evidence store: unavailable")
	}

	if total == 0 {
		return DashboardHealthScoreView{Score: 0, Level: "unavailable", Summary: "No health sources available", Reasons: []string{"No health sources available"}}
	}

	score := points / total
	level := "healthy"
	switch {
	case score < 40:
		level = "error"
	case score < 75:
		level = "warning"
	case score < 95:
		level = "degraded"
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "All tracked dashboard sources are healthy")
	}
	return DashboardHealthScoreView{
		Score:   score,
		Level:   level,
		Summary: fmt.Sprintf("%d%% platform health", score),
		Reasons: reasons,
	}
}

func dashboardReason(label, detail, fallback string) string {
	label = strings.TrimSpace(label)
	detail = strings.TrimSpace(detail)
	if label == "" {
		label = "Unknown"
	}
	if detail == "" {
		detail = fallback
	}
	return label + ": " + detail
}

func dashboardNonAIProviderLevel(provider NonAIProviderEntry) string {
	if strings.TrimSpace(provider.Status) != "" {
		return provider.Status
	}
	switch {
	case provider.Enabled && provider.Configured:
		return "ready"
	case provider.Enabled || provider.Configured:
		return "warning"
	default:
		return "disabled"
	}
}

func dashboardSearchTarget(raw string) string {
	q := strings.TrimSpace(raw)
	if q == "" {
		return "/timeline"
	}
	if ip := net.ParseIP(q); ip != nil {
		return "/forensic?ip=" + url.QueryEscape(q)
	}
	lower := strings.ToLower(q)
	if strings.HasPrefix(lower, "ev-") || strings.HasPrefix(lower, "report-ev-") {
		return "/evidence/" + url.PathEscape(q)
	}
	for _, provider := range []string{"cloudflare", "crowdsec", "abuseipdb", "openai", "anthropic", "gemini", "spamhaus", "virustotal"} {
		if strings.Contains(lower, provider) {
			return "/providers?q=" + url.QueryEscape(q)
		}
	}
	if strings.HasPrefix(lower, "as") {
		return "/intelligence?q=" + url.QueryEscape(q)
	}
	return "/timeline?q=" + url.QueryEscape(q)
}

func dashboardTimeWindow(raw string) DashboardTimeWindowView {
	active := strings.TrimSpace(raw)
	switch active {
	case "15m", "1h", "24h", "7d":
	default:
		active = "24h"
	}
	options := []DashboardTimeWindowOption{
		{Label: "15m", Value: "15m"},
		{Label: "1h", Value: "1h"},
		{Label: "24h", Value: "24h"},
		{Label: "7d", Value: "7d"},
	}
	for i := range options {
		options[i].Active = options[i].Value == active
		options[i].Href = "/?window=" + url.QueryEscape(options[i].Value)
	}
	return DashboardTimeWindowView{Active: active, Options: options}
}

func dashboardWindowStart(active string, now time.Time) time.Time {
	switch active {
	case "15m":
		return now.Add(-15 * time.Minute)
	case "1h":
		return now.Add(-time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	default:
		return now.Add(-24 * time.Hour)
	}
}

func dashboardFreshness(label string, available bool, updatedAt time.Time) DashboardFreshnessView {
	if !available {
		return DashboardFreshnessView{Label: label, Level: "unavailable", Detail: "source unavailable"}
	}
	if updatedAt.IsZero() {
		return DashboardFreshnessView{Label: label, Level: "warning", Detail: "freshness unknown"}
	}
	age := time.Since(updatedAt)
	if age < 0 {
		age = 0
	}
	if age > 5*time.Minute {
		return DashboardFreshnessView{Label: label, Level: "warning", Detail: "stale by " + age.Round(time.Second).String()}
	}
	return DashboardFreshnessView{Label: label, Level: "healthy", Detail: "updated " + age.Round(time.Second).String() + " ago"}
}

func (s *Server) dashboardActivityFeed(ctx context.Context) DashboardActivityFeedView {
	return s.dashboardActivityFeedForWindow(ctx, time.Time{})
}

func (s *Server) dashboardActivityFeedForWindow(ctx context.Context, from time.Time) DashboardActivityFeedView {
	feed := DashboardActivityFeedView{
		Limit:      dashboardActivityLimit,
		MoreHref:   "/timeline",
		Source:     "Evidence",
		SourceHref: "/evidence",
		EmptyText:  "No recent activity available. Evidence events will appear here when the daemon records security events.",
	}
	if s.evidence == nil {
		feed.EmptyText = "Live activity unavailable because the evidence store is not wired."
		return feed
	}
	rows, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: dashboardActivityLimit, From: from})
	if err != nil {
		feed.EmptyText = "Live activity unavailable: " + err.Error()
		return feed
	}
	for _, row := range rows {
		feed.Items = append(feed.Items, dashboardActivityItem(row))
	}
	return feed
}

func (s *Server) dashboardEvidenceFreshness(ctx context.Context) DashboardFreshnessView {
	if s.evidence == nil {
		return dashboardFreshness("Evidence", false, time.Time{})
	}
	rows, err := s.evidence.Search(ctx, reporting.EvidenceSearchOptions{Limit: 1})
	if err != nil || len(rows) == 0 {
		return dashboardFreshness("Evidence", true, time.Time{})
	}
	return dashboardFreshness("Evidence", true, rows[0].Timestamp)
}

func latestProviderTestAt(aiProviders []AIProviderDashboardView, nonAIProviders []NonAIProviderEntry) time.Time {
	var latest time.Time
	consider := func(raw string) {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
		if err != nil {
			return
		}
		if t.After(latest) {
			latest = t
		}
	}
	for _, provider := range aiProviders {
		consider(provider.LastTestAt)
	}
	for _, provider := range nonAIProviders {
		consider(provider.LastTestAt)
	}
	return latest
}

func dashboardActivityItem(ev reporting.DecisionEvidence) DashboardActivityItemView {
	title := strings.TrimSpace(ev.Decision)
	if title == "" {
		title = "evidence"
	}
	detail := strings.TrimSpace(ev.IP)
	if ev.Source != "" {
		if detail != "" {
			detail += " · "
		}
		detail += ev.Source
	}
	href := "/evidence"
	if ev.EvidenceID != "" {
		href = "/evidence/" + url.PathEscape(ev.EvidenceID)
	} else if ev.IP != "" {
		href = "/forensic?ip=" + url.QueryEscape(ev.IP)
	}
	return DashboardActivityItemView{
		Timestamp: ev.Timestamp.UTC().Format(time.RFC3339),
		Severity:  evidenceSeverity(ev),
		Title:     title,
		Detail:    detail,
		Href:      href,
	}
}

func evidenceSeverity(ev reporting.DecisionEvidence) string {
	if ev.AbuseIPDBReported {
		return "error"
	}
	if ev.Suppressed {
		return "warning"
	}
	if strings.Contains(strings.ToLower(ev.Decision), "pending") {
		return "live"
	}
	return "healthy"
}
