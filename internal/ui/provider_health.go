package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/security/quota"
)

const providerQuotaNotExposed = "quota not exposed by provider"
const quotaFreshnessWindow = 30 * time.Minute

type providerHealthCenterEntry struct {
	Name            string
	Description     string
	Status          string
	Mode            string
	EnabledState    string
	ConfiguredState string
	QuotaPlan       string
	QuotaSource     string
	QuotaAge        string
	LastValidation  string
	LastSuccess     string
	LastError       string
	ErrorCount      string
	RateLimitCount  string
	QuotaRemaining  string
	QuotaUsed       string
	QuotaReset      string
	AvgLatency      string
	LastLatency     string
	CacheHits       string
	CacheMisses     string
	LastLookup      string
	StatusCode      string
}

func (s *Server) providerHealthCenterView() []providerHealthCenterEntry {
	cloudflareConfigured := s.cfSentinelToken() != "" && s.cfZoneIDFromSetup(context.Background()) != ""
	crowdSecConfigured := strings.TrimSpace(s.cfg.CrowdSec.APIKey) != "" || strings.TrimSpace(s.cfg.CrowdSec.DecisionsLog) != ""
	abuseConfigured := strings.TrimSpace(providerConfiguredValue(s.cfg.AbuseIPDB.APIKey, s.secretProvider, "ABUSEIPDB_KEY")) != ""
	spamhausConfigured := strings.TrimSpace(providerConfiguredValue(s.cfg.Spamhaus.APIKey, s.secretProvider, "SPAMHAUS_API_KEY")) != ""
	virusTotalConfigured := strings.TrimSpace(providerConfiguredValue(s.cfg.VirusTotal.APIKey, s.secretProvider, "VIRUSTOTAL_API_KEY")) != ""
	dnsConfigured := s.cfg.Enrichment.Enabled && s.cfg.Enrichment.DNSEnabled
	asnConfigured := s.cfg.Enrichment.Enabled && s.cfg.Enrichment.ASNEnabled
	qr := quota.DefaultRegistry()
	now := time.Now().UTC()

	return []providerHealthCenterEntry{
		{
			Name:            "Cloudflare",
			Description:     "read-only boundary for zone health and dry-run inspection",
			Status:          quotaStateValue(qr, "cloudflare"),
			Mode:            "dry-run",
			EnabledState:    enabledText(cloudflareConfigured),
			ConfiguredState: configuredText(cloudflareConfigured),
			QuotaPlan:       quotaPlanValue(qr, "cloudflare"),
			QuotaSource:     quotaSourceValue(qr, "cloudflare"),
			QuotaAge:        quotaAgeValue(qr, "cloudflare", now),
			LastValidation:  quotaPlanValue(qr, "cloudflare"),
			LastSuccess:     quotaObservedValue(qr, "cloudflare"),
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  quotaStateValue(qr, "cloudflare"),
			QuotaRemaining:  quotaRemainingValue(qr, "cloudflare"),
			QuotaUsed:       quotaUsedValue(qr, "cloudflare"),
			QuotaReset:      quotaResetValue(qr, "cloudflare"),
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      quotaSourceValue(qr, "cloudflare"),
			StatusCode:      unavailableValue(),
		},
		{
			Name:            "CrowdSec",
			Description:     "read-only boundary for decisions log and local read-only checks",
			Status:          quotaStateValue(qr, "crowdsec"),
			Mode:            "read-only",
			EnabledState:    enabledText(crowdSecConfigured),
			ConfiguredState: configuredText(crowdSecConfigured),
			QuotaPlan:       unavailableValue(),
			QuotaSource:     unavailableValue(),
			QuotaAge:        unavailableValue(),
			LastValidation:  quotaPlanValue(qr, "crowdsec"),
			LastSuccess:     quotaObservedValue(qr, "crowdsec"),
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  quotaStateValue(qr, "crowdsec"),
			QuotaRemaining:  quotaRemainingValue(qr, "crowdsec"),
			QuotaUsed:       quotaUsedValue(qr, "crowdsec"),
			QuotaReset:      quotaResetValue(qr, "crowdsec"),
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      quotaSourceValue(qr, "crowdsec"),
			StatusCode:      unavailableValue(),
		},
		{
			Name:            "AbuseIPDB",
			Description:     "read-only reputation lookup",
			Status:          quotaStateValue(qr, "abuseipdb"),
			Mode:            "lookup",
			EnabledState:    enabledText(s.cfg.AbuseIPDB.Enabled),
			ConfiguredState: configuredText(abuseConfigured),
			QuotaPlan:       quotaPlanValue(qr, "abuseipdb"),
			QuotaSource:     quotaSourceValue(qr, "abuseipdb"),
			QuotaAge:        quotaAgeValue(qr, "abuseipdb", now),
			LastValidation:  quotaPlanValue(qr, "abuseipdb"),
			LastSuccess:     quotaObservedValue(qr, "abuseipdb"),
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  quotaStateValue(qr, "abuseipdb"),
			QuotaRemaining:  quotaRemainingValue(qr, "abuseipdb"),
			QuotaUsed:       quotaUsedValue(qr, "abuseipdb"),
			QuotaReset:      quotaResetValue(qr, "abuseipdb"),
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      quotaSourceValue(qr, "abuseipdb"),
			StatusCode:      unavailableValue(),
		},
		{
			Name:            "Spamhaus",
			Description:     "read-only reputation lookup",
			Status:          quotaStateValue(qr, "spamhaus"),
			Mode:            "lookup",
			EnabledState:    enabledText(s.cfg.Spamhaus.Enabled),
			ConfiguredState: configuredText(spamhausConfigured),
			QuotaPlan:       quotaPlanValue(qr, "spamhaus"),
			QuotaSource:     quotaSourceValue(qr, "spamhaus"),
			QuotaAge:        quotaAgeValue(qr, "spamhaus", now),
			LastValidation:  quotaPlanValue(qr, "spamhaus"),
			LastSuccess:     quotaObservedValue(qr, "spamhaus"),
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  quotaStateValue(qr, "spamhaus"),
			QuotaRemaining:  quotaRemainingValue(qr, "spamhaus"),
			QuotaUsed:       quotaUsedValue(qr, "spamhaus"),
			QuotaReset:      quotaResetValue(qr, "spamhaus"),
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      quotaSourceValue(qr, "spamhaus"),
			StatusCode:      unavailableValue(),
		},
		{
			Name:            "VirusTotal",
			Description:     "read-only reputation lookup",
			Status:          quotaStateValue(qr, "virustotal"),
			Mode:            "manual-forensics",
			EnabledState:    enabledText(s.cfg.VirusTotal.Enabled),
			ConfiguredState: configuredText(virusTotalConfigured),
			QuotaPlan:       quotaPlanValue(qr, "virustotal"),
			QuotaSource:     quotaSourceValue(qr, "virustotal"),
			QuotaAge:        quotaAgeValue(qr, "virustotal", now),
			LastValidation:  quotaPlanValue(qr, "virustotal"),
			LastSuccess:     quotaObservedValue(qr, "virustotal"),
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  quotaStateValue(qr, "virustotal"),
			QuotaRemaining:  quotaRemainingValue(qr, "virustotal"),
			QuotaUsed:       quotaUsedValue(qr, "virustotal"),
			QuotaReset:      quotaResetValue(qr, "virustotal"),
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      quotaSourceValue(qr, "virustotal"),
			StatusCode:      unavailableValue(),
		},
		{
			Name:            "DNS",
			Description:     "local resolver enrichment, read-only",
			Status:          "n/a",
			Mode:            "local",
			EnabledState:    enabledText(s.cfg.Enrichment.DNSEnabled),
			ConfiguredState: configuredText(dnsConfigured),
			LastValidation:  "n/a",
			LastSuccess:     "n/a",
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  unavailableValue(),
			QuotaRemaining:  "n/a",
			QuotaUsed:       "n/a",
			QuotaReset:      "n/a",
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      "local resolver",
			StatusCode:      unavailableValue(),
		},
		{
			Name:            "ASN",
			Description:     "local ASN classifier, read-only",
			Status:          "n/a",
			Mode:            "local",
			EnabledState:    enabledText(s.cfg.Enrichment.ASNEnabled),
			ConfiguredState: configuredText(asnConfigured),
			LastValidation:  "n/a",
			LastSuccess:     "n/a",
			LastError:       unavailableValue(),
			ErrorCount:      unavailableValue(),
			RateLimitCount:  unavailableValue(),
			QuotaRemaining:  "n/a",
			QuotaUsed:       "n/a",
			QuotaReset:      "n/a",
			AvgLatency:      unavailableValue(),
			LastLatency:     unavailableValue(),
			CacheHits:       unavailableValue(),
			CacheMisses:     unavailableValue(),
			LastLookup:      "local classifier",
			StatusCode:      unavailableValue(),
		},
	}
}

func ProviderHealthCenterPage(views []providerHealthCenterEntry, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Providers",
		Headline: "Provider Health Center",
		Subtitle: "Read-only provider posture, local masking, and explicit unavailable states for every boundary.",
		Active:   "/providers",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">This page is read-only. configured and missing providers are shown explicitly, no provider mutation endpoints are exposed here, and secrets, tokens, cookies, and authorization headers are never rendered.</p></div>`); err != nil {
				return err
			}
			if len(views) == 0 {
				return writeEmptyState(w, "No provider health entries available.")
			}
			if err := renderProviderQuotaOverview(w, views); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `<section class="grid">`); err != nil {
				return err
			}
			for _, view := range views {
				if err := renderProviderHealthCard(w, view, csrfToken); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</section>`)
			return err
		}),
	})
}

func renderProviderHealthCard(w io.Writer, view providerHealthCenterEntry, csrfToken string) error {
	if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<h2>%s</h2>`, html.EscapeString(view.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<p class="muted">%s</p>`, html.EscapeString(view.Description)); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<div class="badges">`); err != nil {
		return err
	}
	if err := renderStateBadge(w, view.EnabledState); err != nil {
		return err
	}
	if err := renderStateBadge(w, view.ConfiguredState); err != nil {
		return err
	}
	if err := renderStateBadge(w, view.Mode); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `</div>`); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
		return err
	}
	rows := []struct {
		label string
		value string
	}{
		{label: "status", value: valueOrFallback(view.Status, providerQuotaNotExposed)},
		{label: "mode", value: view.Mode},
		{label: "quota plan", value: valueOrFallback(view.QuotaPlan, providerQuotaNotExposed)},
		{label: "quota source", value: valueOrFallback(view.QuotaSource, providerQuotaNotExposed)},
		{label: "observed age", value: valueOrFallback(view.QuotaAge, providerQuotaNotExposed)},
		{label: "last validation", value: view.LastValidation},
		{label: "last success", value: view.LastSuccess},
		{label: "last error", value: view.LastError},
		{label: "error count", value: view.ErrorCount},
		{label: "rate-limit count", value: view.RateLimitCount},
		{label: "quota remaining", value: view.QuotaRemaining},
		{label: "quota used", value: view.QuotaUsed},
		{label: "quota reset", value: view.QuotaReset},
		{label: "avg latency", value: view.AvgLatency},
		{label: "last latency", value: view.LastLatency},
		{label: "cache hits", value: view.CacheHits},
		{label: "cache misses", value: view.CacheMisses},
		{label: "last lookup", value: view.LastLookup},
		{label: "status code", value: view.StatusCode},
	}
	for _, row := range rows {
		if err := renderProviderHealthRow(w, row.label, row.value); err != nil {
			return err
		}
	}
	if err := renderAIExplainWidget(w, "provider", strings.ToLower(view.Name), csrfToken, "Ask the read-only AI gateway to explain this provider health snapshot. No provider mutation path is involved."); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}

func renderProviderHealthRow(w io.Writer, label, value string) error {
	_, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(label), html.EscapeString(valueOrUnknown(value)))
	return err
}

func renderStateBadge(w io.Writer, state string) error {
	normalized := strings.ToLower(strings.TrimSpace(state))
	if normalized == "" {
		normalized = "badge"
	}
	_, err := fmt.Fprintf(w, `<span class="badge %s">%s</span>`, html.EscapeString(stateBadgeClass(normalized)), html.EscapeString(strings.ToUpper(normalized)))
	return err
}

func stateBadgeClass(state string) string {
	switch state {
	case "enabled", "configured", "ok", "healthy", "read-only", "lookup", "local", "manual-forensics":
		return "healthy"
	case "disabled":
		return "disabled"
	case "missing":
		return "warning"
	case "dry-run", "dryrun":
		return "dryrun"
	default:
		return "badge"
	}
}

func enabledText(ok bool) string {
	if ok {
		return "enabled"
	}
	return "disabled"
}

func configuredText(ok bool) string {
	if ok {
		return "configured"
	}
	return "missing"
}

func unavailableValue() string {
	return "unavailable"
}

func quotaObservationView(qr *quota.Registry, provider string) (quota.Observation, bool) {
	if qr == nil {
		return quota.Observation{}, false
	}
	return qr.Get(provider)
}

func renderProviderQuotaOverview(w io.Writer, views []providerHealthCenterEntry) error {
	qr := quota.DefaultRegistry()
	now := time.Now().UTC()
	observed := 0
	fresh := 0
	stale := 0
	exhausted := 0
	oldest := time.Duration(0)
	oldestSet := false
	const wanted = 4

	if _, err := fmt.Fprint(w, `<div class="panel"><h2>Quota overview</h2><p class="muted">Compact read-only snapshot for external quota providers. Dedicated refresh is deferred while live observations remain fresh.</p><div class="kv">`); err != nil {
		return err
	}
	for _, provider := range []string{"cloudflare", "abuseipdb", "virustotal", "spamhaus"} {
		obs, ok := qr.Get(provider)
		if !ok || obs.ObservedAt.IsZero() {
			continue
		}
		observed++
		age := now.Sub(obs.ObservedAt)
		if age < 0 {
			age = 0
		}
		if age <= quotaFreshnessWindow {
			fresh++
		} else {
			stale++
		}
		if obs.State == quota.Exhausted {
			exhausted++
		}
		if !oldestSet || age > oldest {
			oldest = age
			oldestSet = true
		}
	}
	rows := []struct {
		label string
		value string
	}{
		{label: "providers tracked", value: fmt.Sprintf("%d/%d", observed, wanted)},
		{label: "fresh observations", value: fmt.Sprintf("%d", fresh)},
		{label: "stale observations", value: fmt.Sprintf("%d", stale)},
		{label: "exhausted providers", value: fmt.Sprintf("%d", exhausted)},
		{label: "oldest observation", value: func() string {
			if !oldestSet {
				return providerQuotaNotExposed
			}
			return oldest.Round(time.Second).String()
		}()},
	}
	for _, row := range rows {
		if err := renderProviderHealthRow(w, row.label, row.value); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, `</div><div class="badges">`); err != nil {
		return err
	}
	for _, view := range views {
		if view.Name == "" {
			continue
		}
		if err := renderProviderStateChip(w, view.Name, view.Status); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}

func renderProviderStateChip(w io.Writer, name, state string) error {
	label := fmt.Sprintf("%s: %s", name, valueOrFallback(state, providerQuotaNotExposed))
	class := stateBadgeClass(strings.ToLower(strings.TrimSpace(valueOrFallback(state, "badge"))))
	if _, err := fmt.Fprintf(w, `<span class="badge %s">%s</span>`, html.EscapeString(class), html.EscapeString(label)); err != nil {
		return err
	}
	return nil
}

func quotaStateValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || obs.State == quota.Unknown {
		return providerQuotaNotExposed
	}
	return strings.ToLower(string(obs.State))
}

func quotaRemainingValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || obs.State == quota.Unknown {
		return providerQuotaNotExposed
	}
	if obs.PercentKnown {
		return fmt.Sprintf("%.1f%%", obs.RemainingPercent)
	}
	if obs.RemainingKnown {
		return fmt.Sprintf("%g", obs.Remaining)
	}
	return providerQuotaNotExposed
}

func quotaUsedValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || obs.State == quota.Unknown {
		return providerQuotaNotExposed
	}
	if obs.LimitKnown && obs.UsedKnown {
		return fmt.Sprintf("%g/%g", obs.Used, obs.Limit)
	}
	if obs.UsedKnown {
		return fmt.Sprintf("%g", obs.Used)
	}
	return providerQuotaNotExposed
}

func quotaResetValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || !obs.ResetKnown || obs.ResetAt.IsZero() {
		return providerQuotaNotExposed
	}
	return obs.ResetAt.UTC().Format(time.RFC3339)
}

func quotaObservedValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || obs.ObservedAt.IsZero() {
		return providerQuotaNotExposed
	}
	return obs.ObservedAt.UTC().Format(time.RFC3339)
}

func quotaPlanValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || strings.TrimSpace(obs.Plan) == "" {
		return providerQuotaNotExposed
	}
	return obs.Plan
}

func quotaSourceValue(qr *quota.Registry, provider string) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || strings.TrimSpace(obs.QuotaSource) == "" {
		return providerQuotaNotExposed
	}
	return obs.QuotaSource
}

func quotaAgeValue(qr *quota.Registry, provider string, now time.Time) string {
	obs, ok := quotaObservationView(qr, provider)
	if !ok || obs.ObservedAt.IsZero() {
		return providerQuotaNotExposed
	}
	age := now.Sub(obs.ObservedAt.UTC())
	if age < 0 {
		age = 0
	}
	return age.Round(time.Second).String()
}
