package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
)

func (s *Server) handleTrustedNetworksPage(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	s.audit.Record("trusted_networks_view", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "trusted-networks",
		"result":         "read-only",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	_ = TrustedNetworksPage(s.trustedNetworksView()).Render(r.Context(), w)
}

func (s *Server) handleTrustedNetworksRefreshDryRun(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	s.audit.Record("trusted_networks_refresh_dry_run", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "trusted-networks",
		"result":         "dry-run",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	_ = trustedNetworksPlaceholderPage(
		"Trusted Networks Refresh",
		"Refresh source is currently dry-run only. The registry is rendered from the local source of truth and no live sync is performed.",
		r.URL.Path,
	).Render(r.Context(), w)
}

func (s *Server) handleTrustedNetworksDiff(w http.ResponseWriter, r *http.Request) {
	_ = trustedNetworksPlaceholderPage(
		"Trusted Networks Diff",
		"Diff view will compare source registry updates against the current local registry snapshot. For now it is a read-only placeholder.",
		r.URL.Path,
	).Render(r.Context(), w)
}

func (s *Server) handleTrustedNetworksExport(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	s.audit.Record("trusted_networks_export", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "trusted-networks",
		"result":         "export",
		"correlation_id": eventID,
		"event_id":       eventID,
	})

	view := s.trustedNetworksView()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "Trusted Networks Registry Export")
	for _, entry := range view.Entries {
		_, _ = fmt.Fprintf(w, "\n[%s]\n", trustedNetworkDisplayName(entry.Organization))
		_, _ = fmt.Fprintf(w, "organization=%s\n", entry.Organization)
		_, _ = fmt.Fprintf(w, "kind=%s\n", entry.Kind)
		_, _ = fmt.Fprintf(w, "cidr_count=%d\n", entry.CIDRCount)
		_, _ = fmt.Fprintf(w, "source_url=%s\n", entry.SourceURL)
		_, _ = fmt.Fprintf(w, "last_verified=%s\n", entry.LastVerified)
		_, _ = fmt.Fprintf(w, "status=%s\n", entry.Status)
		_, _ = fmt.Fprintf(w, "no_hard_ban=%t\n", entry.NoHardBan)
		_, _ = fmt.Fprintf(w, "hard_ban_allowed=%t\n", entry.HardBanAllowed)
		_, _ = fmt.Fprintf(w, "allowlisted=%t\n", entry.Allowlisted)
		_, _ = fmt.Fprintf(w, "cloudflare_whitelist=%s\n", entry.CloudflareWhitelist)
		_, _ = fmt.Fprintf(w, "crowdsec_allowlist=%s\n", entry.CrowdSecAllowlist)
		if len(entry.CIDRs) > 0 {
			_, _ = fmt.Fprintln(w, "cidrs:")
			for _, cidr := range entry.CIDRs {
				_, _ = fmt.Fprintf(w, "- %s\n", cidr)
			}
		}
		if len(entry.Notes) > 0 {
			_, _ = fmt.Fprintln(w, "notes:")
			for _, note := range entry.Notes {
				_, _ = fmt.Fprintf(w, "- %s\n", note)
			}
		}
	}
}

func TrustedNetworksPage(view TrustedNetworksView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Trusted Networks",
		Headline: "Trusted Networks Explorer",
		Subtitle: "Registry-backed read-only inventory of protected networks and crawler/monitoring ranges.",
		Active:   "/trusted-networks",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<section class="stack"><div class="panel"><p class="muted">Registry data is rendered read-only from the local source of truth. Refresh, diff, and export remain dry-run or read-only only.</p><div class="stack" style="margin-top:.75rem"><a class="badge dryrun" href="/trusted-networks/refresh">Refresh source</a><a class="badge" href="/trusted-networks/diff">View diff</a><a class="badge live" href="/trusted-networks/export">Export registry</a><button type="button" disabled>Approve update</button></div></div>`); err != nil {
				return err
			}
			if view.Error != "" {
				if _, err := fmt.Fprintf(w, `<div class="panel"><p class="error">%s</p></div>`, html.EscapeString(view.Error)); err != nil {
					return err
				}
			}
			if len(view.Entries) == 0 {
				if err := writeEmptyState(w, "No trusted-network registry entries available."); err != nil {
					return err
				}
				_, err := fmt.Fprint(w, `</section>`)
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="grid">`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if err := renderTrustedNetworkCard(w, entry); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</div></section>`)
			return err
		}),
	})
}

func trustedNetworksPlaceholderPage(title, description, active string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    title,
		Headline: title,
		Subtitle: description,
		Active:   active,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprintf(w, `<div class="panel"><div class="badge dryrun">read-only placeholder</div><p class="muted" style="margin-top:.8rem">%s</p></div>`, html.EscapeString(description)); err != nil {
				return err
			}
			return writeEmptyState(w, "Placeholder ready.")
		}),
	})
}

func (s *Server) trustedNetworksView() TrustedNetworksView {
	entries := asn.DefaultRegistry()
	views := make([]TrustedNetworkEntryView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, TrustedNetworkEntryView{
			Organization:        entry.Organization,
			Kind:                string(entry.Kind),
			CIDRCount:           len(entry.CIDRs),
			CIDRs:               append([]string(nil), entry.CIDRs...),
			SourceURL:           valueOrFallback(entry.SourceURL, "unavailable"),
			LastVerified:        valueOrFallback(entry.LastVerified, "unavailable"),
			Status:              string(entry.Status()),
			Notes:               trustedNetworkNotes(entry),
			NoHardBan:           true,
			HardBanAllowed:      false,
			Allowlisted:         false,
			CloudflareWhitelist: "not synced",
			CrowdSecAllowlist:   "not synced",
		})
	}
	return TrustedNetworksView{Entries: views}
}

func renderTrustedNetworkCard(w io.Writer, entry TrustedNetworkEntryView) error {
	if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
		return err
	}
	statusClassName := trustedNetworkStatusClass(entry.Status)
	if _, err := fmt.Fprintf(w, `<div class="pagehead" style="align-items:center"><div><h2>%s</h2><p class="muted">%s</p></div><div class="badges"><span class="badge %s">%s</span><span class="badge healthy">%s</span></div></div>`,
		html.EscapeString(trustedNetworkDisplayName(entry.Organization)),
		html.EscapeString(strings.TrimSpace(joinNonEmpty(entry.Notes, " · "))),
		html.EscapeString(statusClassName),
		html.EscapeString(trustedNetworkStatusLabel(entry.Status)),
		html.EscapeString(strings.ToUpper(valueOrFallback(entry.Kind, "unknown"))),
	); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
		return err
	}
	rows := []struct {
		label string
		value string
	}{
		{"organization", trustedNetworkDisplayName(entry.Organization)},
		{"kind", valueOrFallback(entry.Kind, "unknown")},
		{"CIDR count", fmt.Sprintf("%d", entry.CIDRCount)},
		{"SourceURL", valueOrFallback(entry.SourceURL, "unavailable")},
		{"LastVerified", valueOrFallback(entry.LastVerified, "unavailable")},
		{"status", trustedNetworkStatusLabel(entry.Status)},
		{"NoHardBan=true", "read-only"},
		{"HardBanAllowed=false", "read-only"},
		{"allowlisted=false", "default"},
		{"Cloudflare whitelist not synced", valueOrFallback(entry.CloudflareWhitelist, "not synced")},
		{"CrowdSec allowlist not synced", valueOrFallback(entry.CrowdSecAllowlist, "not synced")},
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.label), html.EscapeString(row.value)); err != nil {
			return err
		}
	}
	if len(entry.CIDRs) > 0 {
		if _, err := fmt.Fprint(w, `<div class="row"><span>CIDRs</span><span class="stack">`); err != nil {
			return err
		}
		limit := len(entry.CIDRs)
		if limit > 4 {
			limit = 4
		}
		for i := 0; i < limit; i++ {
			if _, err := fmt.Fprintf(w, `<code>%s</code>`, html.EscapeString(entry.CIDRs[i])); err != nil {
				return err
			}
		}
		if len(entry.CIDRs) > limit {
			if _, err := fmt.Fprintf(w, `<details><summary class="badge">+%d more CIDRs</summary><div class="stack" style="margin-top:.5rem">`, len(entry.CIDRs)-limit); err != nil {
				return err
			}
			for _, cidr := range entry.CIDRs[limit:] {
				if _, err := fmt.Fprintf(w, `<code>%s</code>`, html.EscapeString(cidr)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</div></details>`); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</span></div>`); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}

func trustedNetworkStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case string(asn.RegistryStatusLoaded):
		return "loaded / up to date"
	case string(asn.RegistryStatusTooVolatile):
		return "manual review required / too volatile"
	case string(asn.RegistryStatusSourceUnavailable):
		return "source unavailable"
	default:
		return valueOrFallback(status, "unknown")
	}
}

func trustedNetworkDisplayName(organization string) string {
	switch strings.ToLower(strings.TrimSpace(organization)) {
	case "cloudflare":
		return "Cloudflare"
	case "google":
		return "Google"
	case "microsoft":
		return "Microsoft/Bing"
	case "betterstack":
		return "BetterStack"
	case "uptime-monitoring":
		return "UptimeRobot/Pingdom"
	case "openai-gptbot":
		return "OpenAI GPTBot"
	case "openai-searchbot":
		return "OpenAI SearchBot"
	case "openai-chatgpt-user":
		return "OpenAI ChatGPT-User"
	case "github-copilot":
		return "GitHub Copilot"
	case "anthropic":
		return "Anthropic"
	default:
		return valueOrFallback(organization, "unknown")
	}
}

func trustedNetworkNotes(entry asn.RegistryEntry) []string {
	if strings.TrimSpace(entry.Notes) == "" {
		return nil
	}
	return []string{strings.TrimSpace(entry.Notes)}
}

func trustedNetworkStatusClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case string(asn.RegistryStatusLoaded):
		return "healthy"
	case string(asn.RegistryStatusTooVolatile):
		return "warning"
	case string(asn.RegistryStatusSourceUnavailable):
		return "degraded"
	default:
		return "disabled"
	}
}
