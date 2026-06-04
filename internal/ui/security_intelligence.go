package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	enrichmentdns "github.com/jm/security-automation-go/internal/security/enrichment/dns"
)

type SecurityIntelligenceProviderView struct {
	Name       string
	State      string
	Signal     string
	StatusCode string
}

type SecurityIntelligenceView struct {
	CurrentIP         string
	Error             string
	HasData           bool
	Outcome           string
	Kind              string
	DNS               string
	DNSForwardConfirm string
	ASN               string
	Organisation      string
	Protected         string
	NoHardBan         string
	ScoreDelta        string
	HardBanReason     string
	ProviderNote      string
	CloudflareStatus  string
	CrowdSecStatus    string
	Providers         []SecurityIntelligenceProviderView
	EvidencePreview   []string
}

func (s *Server) handleIntelligencePage(w http.ResponseWriter, r *http.Request) {
	renderSecurityIntelligencePage(r.Context(), w, SecurityIntelligenceView{}, s.csrfTokenFromRequest(r))
}

func (s *Server) handleIntelligenceLookup(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	if !s.validCSRF(r) {
		s.audit.Record("security_intelligence_lookup", map[string]string{
			"source":         "ui",
			"result":         "csrf_rejected",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.audit.Record("security_intelligence_lookup", map[string]string{
			"source":         "ui",
			"ip":             "",
			"result":         "bad_request",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		renderSecurityIntelligencePage(r.Context(), w, SecurityIntelligenceView{
			Error:            "bad request",
			ProviderNote:     "Provider failures stay neutral. External signal alone cannot hard-ban.",
			CurrentIP:        "",
			Kind:             "unknown",
			Outcome:          "neutral",
			Protected:        "unknown",
			NoHardBan:        "unknown",
			ScoreDelta:       "0",
			CloudflareStatus: cloudflareStatus(s.cfg.Cloudflare.APIToken, s.cfg.Cloudflare.ZoneID, s.cfg.Cloudflare.MutationsEnabled),
			CrowdSecStatus:   crowdSecStatus(s.cfg.CrowdSec.DecisionsLog),
		}, s.csrfTokenFromRequest(r))
		return
	}

	ipStr := strings.TrimSpace(r.PostForm.Get("ip"))
	view, result := s.securityIntelligenceLookupView(r.Context(), ipStr)
	s.audit.Record("security_intelligence_lookup", map[string]string{
		"source":         "ui",
		"ip":             ipStr,
		"result":         result,
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	renderSecurityIntelligencePage(r.Context(), w, view, s.csrfTokenFromRequest(r))
}

func (s *Server) securityIntelligenceLookupView(ctx context.Context, ipStr string) (SecurityIntelligenceView, string) {
	view := SecurityIntelligenceView{
		CurrentIP:    ipStr,
		Kind:         "unknown",
		Outcome:      "neutral",
		Protected:    "unknown",
		NoHardBan:    "unknown",
		ScoreDelta:   "0",
		ProviderNote: "Provider failures stay neutral. External signal alone cannot hard-ban.",
	}
	if ipStr == "" {
		view.Error = "invalid IP address"
		return view, "invalid_ip"
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil || !ip.IsValid() {
		view.Error = "invalid IP address"
		return view, "invalid_ip"
	}

	svc := s.securityIntelligenceService()
	if svc == nil {
		view.Error = "enrichment service not configured"
		return view, "service_unavailable"
	}

	summary, err := svc.Enrich(ctx, ip, enrichment.LookupOptions{ManualForensics: true})
	if err != nil {
		view.Error = fmt.Sprintf("enrichment failed: %v", err)
		return view, "lookup_error"
	}

	assessment := svc.Assess(summary)
	view = buildSecurityIntelligenceView(s, summary, assessment, ipStr)

	switch {
	case assessment.NoHardBan:
		return view, "protected_no_hard_ban"
	case assessment.HardBanAllowed:
		return view, "hard_ban_allowed"
	case assessment.Score != 0:
		return view, "external_signal_blocked"
	default:
		return view, "neutral"
	}
}

func (s *Server) securityIntelligenceService() *enrichment.Service {
	if s.enrichment != nil {
		return s.enrichment
	}
	return enrichment.NewService(enrichment.Config{
		Enabled:    s.cfg.Enrichment.Enabled,
		DNSEnabled: s.cfg.Enrichment.DNSEnabled,
		ASNEnabled: s.cfg.Enrichment.ASNEnabled,
		Timeout:    s.cfg.Enrichment.Timeout,
		CacheTTL:   s.cfg.Enrichment.CacheTTL,
	}, enrichmentdns.NewNetResolver(), asn.NewStaticProvider(), nil, nil)
}

func renderSecurityIntelligencePage(ctx context.Context, w http.ResponseWriter, view SecurityIntelligenceView, csrfToken string) {
	_ = SecurityIntelligencePage(view, csrfToken).Render(ctx, w)
}

func SecurityIntelligencePage(view SecurityIntelligenceView, csrfToken string) templ.Component {
	body := templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		if _, err := fmt.Fprint(w, `<section class="grid">`); err != nil {
			return err
		}

		if _, err := fmt.Fprint(w, `<div class="panel"><h2>Read-only lookup</h2><p class="muted">Enter an IP address to inspect DNS, ASN, protected-network flags, and provider signals. Provider failures stay neutral. External signal alone cannot hard-ban.</p><form action="/intelligence" method="post"><label for="ip">IP address</label><input id="ip" name="ip" type="text" value="`); err != nil {
			return err
		}
		if _, err := io.WriteString(w, html.EscapeString(view.CurrentIP)); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, `" placeholder="e.g. 203.0.113.4" autocomplete="off"/><button type="submit">Inspect</button></form></div>`); err != nil {
			return err
		}

		if view.Error != "" {
			if _, err := fmt.Fprintf(w, `<div class="panel"><p class="error">%s</p></div>`, html.EscapeString(view.Error)); err != nil {
				return err
			}
		}

		if !view.HasData {
			if _, err := fmt.Fprint(w, `</section>`); err != nil {
				return err
			}
			return writeEmptyState(w, "Empty state ready. Submit an IP to render the forensic summary.")
		}

		if _, err := fmt.Fprintf(w, `<div class="panel"><div class="badges"><span class="badge %s">%s</span><span class="badge %s">NoHardBan: %s</span><span class="badge %s">Protected: %s</span></div><h2 style="margin-top:.8rem">%s</h2><p class="muted">%s</p><div class="kv">`,
			html.EscapeString(outcomeBadgeClass(view.Outcome)), html.EscapeString(strings.ToUpper(view.Outcome)),
			html.EscapeString(noHardBanBadgeClass(view.NoHardBan)), html.EscapeString(view.NoHardBan),
			html.EscapeString(protectedBadgeClass(view.Protected)), html.EscapeString(view.Protected),
			html.EscapeString(valueOrUnknown(view.CurrentIP)),
			html.EscapeString(view.ProviderNote),
		); err != nil {
			return err
		}

		rows := []keyValueRow{
			{Key: "DNS", Value: view.DNS},
			{Key: "rDNS forward-confirmed", Value: view.DNSForwardConfirm},
			{Key: "ASN", Value: view.ASN},
			{Key: "organisation", Value: view.Organisation},
			{Key: "kind", Value: view.Kind},
			{Key: "protected flag", Value: view.Protected},
			{Key: "NoHardBan", Value: view.NoHardBan},
			{Key: "score delta", Value: view.ScoreDelta},
			{Key: "why / why not hard-ban", Value: view.HardBanReason},
		}
		for _, row := range rows {
			if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(valueOrUnknown(row.Value))); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
			return err
		}

		if err := renderKeyValuePanel(w, "Provider signals", providerRowsAsPairs(view.Providers)); err != nil {
			return err
		}

		if err := renderKeyValuePanel(w, "Other signals", []keyValueRow{
			{Key: "Cloudflare", Value: view.CloudflareStatus},
			{Key: "CrowdSec", Value: view.CrowdSecStatus},
		}); err != nil {
			return err
		}

		if _, err := fmt.Fprint(w, `<div class="panel"><h2>Evidence preview</h2>`); err != nil {
			return err
		}
		if len(view.EvidencePreview) == 0 {
			if _, err := fmt.Fprint(w, `<div class="empty">No evidence preview available.</div></div></section>`); err != nil {
				return err
			}
			return nil
		}
		if _, err := fmt.Fprint(w, `<pre>`); err != nil {
			return err
		}
		for i, line := range view.EvidencePreview {
			if i > 0 {
				if _, err := fmt.Fprint(w, "\n"); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(w, html.EscapeString(line)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</pre></div></section>`); err != nil {
			return err
		}
		if view.HasData {
			if err := renderAIExplainWidget(w, "intelligence", valueOrUnknown(view.CurrentIP), csrfToken, "Explain this intelligence lookup with AI. The response stays read-only and comes back as text only."); err != nil {
				return err
			}
		}
		return nil
	})

	return ConsoleLayout(shellView{
		Title:    "Security Intelligence",
		Headline: "Security Intelligence",
		Subtitle: "Read-only IP lookup with DNS, ASN, protected-network detection, and provider-neutral assessment.",
		Active:   "/intelligence",
		Body:     body,
	})
}

func buildSecurityIntelligenceView(s *Server, summary enrichment.EnrichmentSummary, assessment enrichment.Assessment, ipStr string) SecurityIntelligenceView {
	view := SecurityIntelligenceView{
		CurrentIP:         ipStr,
		HasData:           true,
		Outcome:           securityIntelligenceOutcome(assessment, summary),
		Kind:              securityIntelligenceKind(summary.ASN.Kind, summary.ASN.Protected),
		DNS:               "unavailable",
		DNSForwardConfirm: "unavailable",
		ASN:               "unknown",
		Organisation:      "unknown",
		Protected:         boolText(summary.ASN.Protected),
		NoHardBan:         boolText(assessment.NoHardBan),
		ScoreDelta:        fmt.Sprintf("%+d", assessment.Score),
		HardBanReason:     securityIntelligenceHardBanReason(summary, assessment),
		ProviderNote:      "Provider failures stay neutral. External signal alone cannot hard-ban.",
		CloudflareStatus:  cloudflareStatus(s.cfg.Cloudflare.APIToken, s.cfg.Cloudflare.ZoneID, s.cfg.Cloudflare.MutationsEnabled),
		CrowdSecStatus:    crowdSecStatus(s.cfg.CrowdSec.DecisionsLog),
	}

	if summary.DNS.Hostname != "" {
		view.DNS = summary.DNS.Hostname
		if summary.DNS.Confirmed {
			view.DNSForwardConfirm = "yes"
		} else {
			view.DNSForwardConfirm = "no"
		}
	}
	if summary.ASN.ASN > 0 {
		view.ASN = fmt.Sprintf("AS%d", summary.ASN.ASN)
	}
	if org := strings.TrimSpace(summary.ASN.Org); org != "" {
		view.Organisation = org
	}

	view.Providers = buildSecurityIntelligenceProviders(s, summary)
	view.EvidencePreview = buildSecurityIntelligenceEvidence(view, summary, assessment)
	return view
}

func buildSecurityIntelligenceProviders(s *Server, summary enrichment.EnrichmentSummary) []SecurityIntelligenceProviderView {
	lookup := func(name string) (enrichment.ProviderVerdict, bool) {
		for _, verdict := range summary.Providers {
			if strings.EqualFold(verdict.Provider, name) {
				return verdict, true
			}
		}
		return enrichment.ProviderVerdict{}, false
	}

	providers := []struct {
		name       string
		enabled    bool
		configured bool
	}{
		{
			name:       "AbuseIPDB",
			enabled:    s.cfg.AbuseIPDB.Enabled,
			configured: providerConfiguredValue(s.cfg.AbuseIPDB.APIKey, s.secretProvider, "ABUSEIPDB_KEY") != "",
		},
		{
			name:       "VirusTotal",
			enabled:    s.cfg.VirusTotal.Enabled,
			configured: providerConfiguredValue(s.cfg.VirusTotal.APIKey, s.secretProvider, "VIRUSTOTAL_API_KEY") != "",
		},
		{
			name:       "Spamhaus",
			enabled:    s.cfg.Spamhaus.Enabled,
			configured: providerConfiguredValue(s.cfg.Spamhaus.APIKey, s.secretProvider, "SPAMHAUS_API_KEY") != "",
		},
	}

	rows := make([]SecurityIntelligenceProviderView, 0, len(providers))
	for _, provider := range providers {
		state := providerStateText(provider.enabled, provider.configured)
		signal := "neutral / unavailable"
		if !provider.enabled {
			signal = "disabled"
		} else if !provider.configured {
			signal = "missing configuration"
		} else if verdict, ok := lookup(provider.name); ok {
			signal = providerSignalText(verdict)
		}
		rows = append(rows, SecurityIntelligenceProviderView{
			Name:       provider.name,
			State:      state,
			Signal:     signal,
			StatusCode: "not exposed",
		})
	}
	return rows
}

func buildSecurityIntelligenceEvidence(view SecurityIntelligenceView, summary enrichment.EnrichmentSummary, assessment enrichment.Assessment) []string {
	lines := []string{
		"IP: " + valueOrUnknown(view.CurrentIP),
		"DNS: " + valueOrUnknown(view.DNS),
		"rDNS forward-confirmed: " + valueOrUnknown(view.DNSForwardConfirm),
		"ASN: " + valueOrUnknown(view.ASN),
		"Organisation: " + valueOrUnknown(view.Organisation),
		"Kind: " + valueOrUnknown(view.Kind),
		"Protected: " + valueOrUnknown(view.Protected),
		"NoHardBan: " + valueOrUnknown(view.NoHardBan),
		"Score delta: " + valueOrUnknown(view.ScoreDelta),
		"Why: " + valueOrUnknown(view.HardBanReason),
	}
	for _, provider := range view.Providers {
		lines = append(lines, fmt.Sprintf("%s: %s (%s)", provider.Name, valueOrUnknown(provider.Signal), valueOrUnknown(provider.State)))
	}
	lines = append(lines, "Cloudflare: "+valueOrUnknown(view.CloudflareStatus))
	lines = append(lines, "CrowdSec: "+valueOrUnknown(view.CrowdSecStatus))
	lines = append(lines, fmt.Sprintf("Assessment: score=%+d no_hard_ban=%t hard_ban_allowed=%t", assessment.Score, assessment.NoHardBan, assessment.HardBanAllowed))
	if summary.DNS.TrustedBot {
		lines = append(lines, "DNS trust: trusted forward-confirmed bot")
	}
	return lines
}

func providerRowsAsPairs(providers []SecurityIntelligenceProviderView) []keyValueRow {
	rows := make([]keyValueRow, 0, len(providers)*2)
	if len(providers) == 0 {
		return []keyValueRow{{Key: "providers", Value: "unavailable"}}
	}
	for _, provider := range providers {
		rows = append(rows, keyValueRow{
			Key:   provider.Name,
			Value: provider.State + " · " + provider.Signal + " · status code: " + valueOrUnknown(provider.StatusCode),
		})
	}
	return rows
}

func securityIntelligenceKind(kind asn.Kind, protected bool) string {
	if protected {
		switch kind {
		case asn.KindSearchBot:
			return "searchbot"
		case asn.KindAIAgent:
			return "aiagent"
		case asn.KindMonitoring:
			return "monitoring"
		default:
			return "protected"
		}
	}
	switch kind {
	case asn.KindSearchBot:
		return "searchbot"
	case asn.KindAIAgent:
		return "aiagent"
	case asn.KindMonitoring:
		return "monitoring"
	default:
		return "unknown"
	}
}

func securityIntelligenceHardBanReason(summary enrichment.EnrichmentSummary, assessment enrichment.Assessment) string {
	switch {
	case assessment.NoHardBan:
		return "protected network: no hard ban"
	case assessment.HardBanAllowed:
		return "local signal plus enrichment threshold met"
	case assessment.Score != 0:
		return "external signal alone cannot hard-ban; local signal required"
	case summary.DNS.Hostname != "" || summary.ASN.Org != "":
		return "neutral: enrichment is informational only"
	default:
		return "neutral: no signal strong enough to escalate"
	}
}

func securityIntelligenceOutcome(assessment enrichment.Assessment, summary enrichment.EnrichmentSummary) string {
	switch {
	case assessment.NoHardBan:
		return "protected"
	case assessment.HardBanAllowed:
		return "hard-ban allowed"
	case assessment.Score != 0:
		return "external-signal blocked"
	case summary.DNS.Hostname != "" || summary.ASN.Org != "":
		return "neutral"
	default:
		return "neutral"
	}
}

func providerStateText(enabled, configured bool) string {
	switch {
	case !enabled:
		return "disabled"
	case !configured:
		return "missing configuration"
	default:
		return "enabled / configured"
	}
}

func providerSignalText(verdict enrichment.ProviderVerdict) string {
	switch {
	case verdict.Score > 0:
		return fmt.Sprintf("score %+d", verdict.Score)
	case verdict.Score < 0:
		return fmt.Sprintf("score %+d", verdict.Score)
	default:
		return "neutral"
	}
}

func boolText(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func outcomeBadgeClass(outcome string) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "protected":
		return "healthy"
	case "hard-ban allowed":
		return "error"
	case "external-signal blocked":
		return "warning"
	default:
		return "healthy"
	}
}

func noHardBanBadgeClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes":
		return "healthy"
	case "no":
		return "warning"
	default:
		return "disabled"
	}
}

func protectedBadgeClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes":
		return "warning"
	case "no":
		return "disabled"
	default:
		return "disabled"
	}
}
