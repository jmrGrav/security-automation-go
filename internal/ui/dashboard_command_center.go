package ui

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const dashboardActivityLimit = 8

func dashboardHealthScore(statuses []StatusItem, env EnvironmentWidget, providers []AIProviderDashboardView, evidenceWired bool) DashboardHealthScoreView {
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
