package ui

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	"github.com/jm/security-automation-go/internal/trustednetworks"
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view := s.trustedNetworksView(r.Context())
	_, _ = fmt.Fprint(w, v2Page("Trusted Networks", "/trusted-networks", renderV2TrustedNetworksContent(view)))
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

	view := s.trustedNetworksView(r.Context())
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

// renderV2TrustedNetworksContent renders the page body wrapped by v2Page().
func renderV2TrustedNetworksContent(view TrustedNetworksView) string {
	var sb strings.Builder
	sb.WriteString(`<style>
.tn-table{width:100%;border-collapse:collapse;font:500 12px 'Hanken Grotesk',sans-serif}
.tn-table th{padding:8px 12px;text-align:left;font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#6b7184;text-transform:uppercase;border-bottom:1px solid #1a1e29;white-space:nowrap;background:#0d0f16}
.tn-table td{padding:8px 12px;border-bottom:1px solid #0f1118;color:#c5cad8;vertical-align:top}
.tn-table tr:last-child td{border-bottom:none}
.tn-table tr:hover td{background:rgba(255,255,255,.02)}
.tn-badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:5px;font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.04em;text-transform:uppercase}
.tn-badge-ok{background:rgba(76,199,154,.1);border:1px solid rgba(76,199,154,.22);color:#4cc79a}
.tn-badge-warn{background:rgba(245,146,30,.1);border:1px solid rgba(245,146,30,.22);color:#f5a443}
.tn-badge-err{background:rgba(239,95,107,.1);border:1px solid rgba(239,95,107,.22);color:#f08591}
.tn-badge-neu{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);color:#9aa0b2}
.tn-muted{color:#6b7184;font-size:.85em}
code{font:500 11px 'JetBrains Mono',monospace;color:#9b8cff}
</style>

<div class="v2-topbar">
  <div>
    <div class="v2-topbar-title">Trusted Networks</div>
    <div class="v2-topbar-sub">Registry-backed read-only inventory of protected networks and crawler ranges</div>
  </div>
  <span style="flex:1"></span>
  <a href="/trusted-networks/export" style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:8px;border:1px solid #20242f;background:#10121a;font:600 12px 'Hanken Grotesk',sans-serif;color:#c5cad8;text-decoration:none">Export registry</a>
</div>
`)

	// Sync banners
	switch view.SyncMode {
	case "enforce":
		sb.WriteString(`<div class="v2-banner" style="border-color:rgba(76,199,154,.22);background:rgba(76,199,154,.06);margin-bottom:16px"><span class="tn-badge tn-badge-ok">sync: enforce</span><span class="tn-muted">CrowdSec/Cloudflare allowlist sync is actively pushing missing entries.</span></div>`)
	case "shadow":
		sb.WriteString(`<div class="v2-banner" style="border-color:rgba(245,146,30,.22);background:rgba(245,146,30,.06);margin-bottom:16px"><span class="tn-badge tn-badge-warn">sync: shadow</span><span class="tn-muted">CrowdSec/Cloudflare allowlist sync is detect-only — no remote mutations are made.</span></div>`)
	default:
		sb.WriteString(`<div class="v2-banner" style="border-color:rgba(155,140,255,.18);background:rgba(155,140,255,.05);margin-bottom:16px"><span class="tn-badge tn-badge-neu">sync: not running</span><span class="tn-muted">The trusted-networks sync registry has not completed a pass yet.</span></div>`)
	}

	// CrowdSec helper banner
	h := view.CrowdSecHelper
	if h.Available {
		badgeClass, badgeText := "tn-badge-ok", "crowdsec helper: ok"
		if !h.AuthOK || h.LastError != "" {
			badgeClass, badgeText = "tn-badge-err", "crowdsec helper: error"
		} else if h.DriftCount > 0 {
			badgeClass, badgeText = "tn-badge-warn", "crowdsec helper: drift"
		} else if !h.Configured {
			badgeClass, badgeText = "tn-badge-neu", "crowdsec helper: not configured"
		}
		lastSync := valueOrFallback(h.LastSyncAt, "never")
		errPart := ""
		if h.LastError != "" {
			errPart = fmt.Sprintf(` · <span style="color:#f08591">%s</span>`, html.EscapeString(h.LastError))
		}
		sb.WriteString(fmt.Sprintf(
			`<div class="v2-banner" style="border-color:rgba(124,108,242,.18);background:rgba(124,108,242,.05);margin-bottom:16px"><span class="tn-badge %s">%s</span><span class="tn-muted">mode: %s · last sync: %s · desired: %d · current: %d · drift: %d%s</span></div>`,
			html.EscapeString(badgeClass), html.EscapeString(badgeText),
			html.EscapeString(valueOrFallback(h.Mode, "unknown")),
			html.EscapeString(lastSync),
			h.DesiredCount, h.CurrentCount, h.DriftCount, errPart,
		))
	}

	if view.Error != "" {
		sb.WriteString(fmt.Sprintf(`<div class="v2-card" style="padding:14px 18px;border-color:rgba(239,95,107,.25)"><span style="color:#f08591">%s</span></div>`, html.EscapeString(view.Error)))
	}

	if len(view.Entries) == 0 {
		sb.WriteString(`<div class="v2-card"><div class="v2-empty">No trusted-network registry entries available.</div></div>`)
	} else {
		sb.WriteString(`<div class="v2-card"><div style="overflow-x:auto"><table class="tn-table"><thead><tr><th>Name</th><th>Kind</th><th>CIDRs</th><th>Protection</th><th>Allowlist</th><th>Status</th></tr></thead><tbody>`)
		for _, entry := range view.Entries {
			var row strings.Builder
			if err := renderTrustedNetworkRow(&row, entry); err == nil {
				sb.WriteString(row.String())
			}
		}
		sb.WriteString(`</tbody></table></div></div>`)
	}

	return sb.String()
}

func TrustedNetworksPage(view TrustedNetworksView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Trusted Networks",
		Headline: "Trusted Networks Explorer",
		Subtitle: "Registry-backed read-only inventory of protected networks and crawler/monitoring ranges.",
		Active:   "/trusted-networks",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<section class="stack"><div class="panel"><p class="muted">Registry data is rendered read-only from the local source of truth.</p><div class="stack" style="margin-top:.75rem"><a class="badge live" href="/trusted-networks/export">Export registry</a><button type="button" disabled>Approve update</button></div></div>`); err != nil {
				return err
			}
			if err := writeTrustedNetworksSyncBanner(w, view.SyncMode); err != nil {
				return err
			}
			if err := writeCrowdSecHelperBanner(w, view.CrowdSecHelper); err != nil {
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
			if _, err := fmt.Fprint(w, `<div style="overflow-x:auto"><table><thead><tr><th>Name</th><th>Kind</th><th>CIDRs</th><th>Protection</th><th>Allowlist</th><th>Status</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if err := renderTrustedNetworkRow(w, entry); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div></section>`)
			return err
		}),
	})
}

// writeTrustedNetworksSyncBanner renders the hub-and-spoke registry's
// current Sync mode (shadow/enforce) so operators can see at a glance
// whether the CF/CrowdSec allowlist columns below reflect live state or
// have never run yet.
func writeTrustedNetworksSyncBanner(w io.Writer, syncMode string) error {
	switch syncMode {
	case "enforce":
		_, err := fmt.Fprint(w, `<div class="panel"><span class="badge live">sync: enforce</span> <span class="muted" style="font-size:.85rem">CrowdSec/Cloudflare allowlist sync is actively pushing missing entries.</span></div>`)
		return err
	case "shadow":
		_, err := fmt.Fprint(w, `<div class="panel"><span class="badge dryrun">sync: shadow</span> <span class="muted" style="font-size:.85rem">CrowdSec/Cloudflare allowlist sync is detect-only — no remote mutations are made.</span></div>`)
		return err
	default:
		_, err := fmt.Fprint(w, `<div class="panel"><span class="badge disabled">sync: not running</span> <span class="muted" style="font-size:.85rem">The trusted-networks sync registry has not completed a pass yet (daemon not running or feature disabled).</span></div>`)
		return err
	}
}

// writeCrowdSecHelperBanner renders the root-owned cf-allowlist-sync
// helper's last reconcile status. This is the only honest source for
// CrowdSec allowlist status — the long-lived daemon and the UI never
// invoke cscli themselves.
func writeCrowdSecHelperBanner(w io.Writer, helper CrowdSecHelperStatusView) error {
	if !helper.Available {
		_, err := fmt.Fprint(w, `<div class="panel"><span class="badge disabled">crowdsec helper: not wired</span> <span class="muted" style="font-size:.85rem">No CrowdSec allowlist status store is configured for this instance.</span></div>`)
		return err
	}
	if !helper.Configured {
		_, err := fmt.Fprint(w, `<div class="panel"><span class="badge disabled">crowdsec helper: not configured</span> <span class="muted" style="font-size:.85rem">The cf-allowlist-sync helper has not run with a configured allowlist name yet.</span></div>`)
		return err
	}

	badge := `<span class="badge healthy">crowdsec helper: ok</span>`
	if !helper.AuthOK || helper.LastError != "" {
		badge = `<span class="badge error">crowdsec helper: error</span>`
	} else if helper.DriftCount > 0 {
		badge = `<span class="badge warning">crowdsec helper: drift</span>`
	}

	lastSync := helper.LastSyncAt
	if lastSync == "" {
		lastSync = "never"
	}

	if _, err := fmt.Fprintf(w,
		`<div class="panel">%s <span class="muted" style="font-size:.85rem">mode: %s · last sync: %s · desired: %d · current: %d · drift: %d</span>`,
		badge,
		html.EscapeString(valueOrFallback(helper.Mode, "unknown")),
		html.EscapeString(lastSync),
		helper.DesiredCount,
		helper.CurrentCount,
		helper.DriftCount,
	); err != nil {
		return err
	}
	if helper.LastError != "" {
		if _, err := fmt.Fprintf(w, `<br><span class="muted error" style="font-size:.85rem">last error: %s</span>`, html.EscapeString(helper.LastError)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func (s *Server) trustedNetworksView(ctx context.Context) TrustedNetworksView {
	report, hasReport := s.trustedNetworksCache.Get()
	helper := s.crowdSecHelperStatusView(ctx)

	entries := asn.DefaultRegistry()
	views := make([]TrustedNetworkEntryView, 0, len(entries))
	for _, entry := range entries {
		cf, cs, allowlisted := trustedNetworkSyncStatus(report, hasReport, helper, entry.CIDRs)
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
			Allowlisted:         allowlisted,
			CloudflareWhitelist: cf,
			CrowdSecAllowlist:   cs,
		})
	}
	syncMode := ""
	if hasReport {
		syncMode = report.Mode
	}
	return TrustedNetworksView{Entries: views, SyncMode: syncMode, CrowdSecHelper: helper}
}

// crowdSecHelperStatusView reads the root-owned cf-allowlist-sync helper's
// most recently persisted reconcile result. The daemon's own CrowdSec spoke
// is always nil (see buildTrustedNetworksRegistry in cmd/cf-sync), so this
// store is the only honest source of CrowdSec allowlist status — the UI
// must never shell out to cscli itself.
func (s *Server) crowdSecHelperStatusView(ctx context.Context) CrowdSecHelperStatusView {
	if s.crowdSecStatusStore == nil {
		return CrowdSecHelperStatusView{}
	}
	name := crowdSecAllowlistNameFromConfig(s.cfg)
	status, found, err := s.crowdSecStatusStore.GetCrowdSecAllowlistStatus(ctx, name)
	if err != nil || !found {
		return CrowdSecHelperStatusView{Available: true}
	}
	lastSync := ""
	if !status.LastSyncAt.IsZero() {
		lastSync = status.LastSyncAt.UTC().Format(time.RFC3339)
	}
	return CrowdSecHelperStatusView{
		Available:    true,
		Configured:   status.Configured,
		AuthOK:       status.AuthOK,
		LastSyncAt:   lastSync,
		LastError:    status.LastError,
		DesiredCount: status.DesiredCount,
		CurrentCount: status.CurrentCount,
		DriftCount:   status.DriftCount,
		Mode:         status.Mode,
	}
}

// crowdSecAllowlistNameFromConfig mirrors app.allowlistNameFromConfig:
// TrustedNetworks.CrowdSec.AllowlistName when set, falling back to the
// legacy top-level CrowdSec.AllowlistName.
func crowdSecAllowlistNameFromConfig(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if cfg.TrustedNetworks.CrowdSec.AllowlistName != "" {
		return cfg.TrustedNetworks.CrowdSec.AllowlistName
	}
	return cfg.CrowdSec.AllowlistName
}

// trustedNetworkSyncStatus derives per-organization Cloudflare/CrowdSec
// whitelist status from the trustednetworks.Registry's most recent
// SyncReport. cidrs with no loaded CIDRs (e.g. too-volatile entries that
// were never seeded into the registry) always report "not seeded" since
// they were deliberately excluded from seedTrustedNetworksFromASN.
//
// The daemon's own report.CrowdSec spoke is always disabled (Enabled ==
// false — see buildTrustedNetworksRegistry), since CrowdSec reconcile now
// runs entirely inside the separate root-owned cf-allowlist-sync helper.
// When that's the case, the CrowdSec column falls back to the helper's
// aggregate status instead of misleadingly reporting "disabled".
func trustedNetworkSyncStatus(report trustednetworks.SyncReport, hasReport bool, helper CrowdSecHelperStatusView, cidrs []string) (cloudflare, crowdsec string, allowlisted bool) {
	if len(cidrs) == 0 {
		return "not seeded", "not seeded", false
	}

	cfLabel := "awaiting first sync"
	cfSynced := false
	if hasReport {
		cfStatus := spokeStatusForValues(report.Cloudflare, cidrs)
		cfLabel = spokeStatusLabel(cfStatus, report.Mode)
		cfSynced = cfStatus == spokeSynced
	}

	if hasReport && report.CrowdSec.Enabled {
		csStatus := spokeStatusForValues(report.CrowdSec, cidrs)
		csLabel := spokeStatusLabel(csStatus, report.Mode)
		return cfLabel, csLabel, cfSynced && csStatus == spokeSynced
	}

	csLabel, csSynced := crowdSecHelperEntryLabel(helper)
	return cfLabel, csLabel, cfSynced && csSynced
}

// crowdSecHelperEntryLabel renders a per-entry CrowdSec label from the
// helper's aggregate status (it does not track per-CIDR sync state, only
// desired/current/drift counts for the whole allowlist).
func crowdSecHelperEntryLabel(helper CrowdSecHelperStatusView) (label string, synced bool) {
	if !helper.Available {
		return "awaiting helper status", false
	}
	if !helper.Configured {
		return "not configured", false
	}
	if !helper.AuthOK || helper.LastError != "" {
		return "helper error", false
	}
	if helper.DriftCount > 0 {
		return "drift detected (helper)", false
	}
	if helper.Mode != "enforce" {
		return "pending (shadow mode, helper)", false
	}
	return "synced (helper)", true
}

type spokeSyncState int

const (
	spokeDisabled spokeSyncState = iota
	spokePendingShadow
	spokeSynced
)

func spokeStatusForValues(res trustednetworks.SpokeResult, cidrs []string) spokeSyncState {
	if !res.Enabled {
		return spokeDisabled
	}
	synced := make(map[string]bool, len(res.AlreadySynced)+len(res.Pushed))
	for _, v := range res.AlreadySynced {
		synced[v] = true
	}
	for _, v := range res.Pushed {
		synced[v] = true
	}
	for _, cidr := range cidrs {
		if !synced[cidr] {
			return spokePendingShadow
		}
	}
	return spokeSynced
}

func spokeStatusLabel(state spokeSyncState, mode string) string {
	switch state {
	case spokeSynced:
		return "synced"
	case spokePendingShadow:
		if mode == "enforce" {
			return "pending"
		}
		return "pending (shadow mode)"
	default:
		return "disabled"
	}
}

func renderTrustedNetworkRow(w io.Writer, entry TrustedNetworkEntryView) error {
	statusClass := trustedNetworkStatusClass(entry.Status)
	name := html.EscapeString(trustedNetworkDisplayName(entry.Organization))
	kind := html.EscapeString(strings.ToUpper(valueOrFallback(entry.Kind, "unknown")))
	notes := strings.TrimSpace(joinNonEmpty(entry.Notes, " · "))

	// Name cell
	if notes != "" {
		if _, err := fmt.Fprintf(w, `<tr><td><strong>%s</strong><br><span class="muted" style="font-size:.8rem">%s</span></td>`, name, html.EscapeString(notes)); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, `<tr><td><strong>%s</strong></td>`, name); err != nil {
			return err
		}
	}

	// Kind cell
	if _, err := fmt.Fprintf(w, `<td><span class="badge">%s</span></td>`, kind); err != nil {
		return err
	}

	// CIDRs cell — first 2 inline, rest in <details>
	if _, err := fmt.Fprint(w, `<td>`); err != nil {
		return err
	}
	if len(entry.CIDRs) == 0 {
		if _, err := fmt.Fprint(w, `<span class="muted">none</span>`); err != nil {
			return err
		}
	} else {
		visible := entry.CIDRs
		hidden := []string(nil)
		if len(visible) > 2 {
			visible, hidden = entry.CIDRs[:2], entry.CIDRs[2:]
		}
		for _, cidr := range visible {
			if _, err := fmt.Fprintf(w, `<code style="display:block;margin-bottom:.2rem">%s</code>`, html.EscapeString(cidr)); err != nil {
				return err
			}
		}
		if len(hidden) > 0 {
			if _, err := fmt.Fprintf(w, `<details style="margin-top:.2rem"><summary class="badge" style="cursor:pointer">+%d more</summary>`, len(hidden)); err != nil {
				return err
			}
			for _, cidr := range hidden {
				if _, err := fmt.Fprintf(w, `<code style="display:block;margin-top:.2rem">%s</code>`, html.EscapeString(cidr)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</details>`); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, `<span class="muted" style="font-size:.75rem;display:block;margin-top:.2rem">%d total</span></td>`, entry.CIDRCount); err != nil {
		return err
	}

	// Protection cell
	protBadge := `<span class="badge healthy">no hard ban</span>`
	if entry.HardBanAllowed {
		protBadge = `<span class="badge warning">hard ban allowed</span>`
	}
	if _, err := fmt.Fprintf(w, `<td>%s</td>`, protBadge); err != nil {
		return err
	}

	// Allowlist cell
	cfSync := html.EscapeString(valueOrFallback(entry.CloudflareWhitelist, "not synced"))
	csSync := html.EscapeString(valueOrFallback(entry.CrowdSecAllowlist, "not synced"))
	if _, err := fmt.Fprintf(w, `<td><span class="muted" style="font-size:.8rem">CF: %s</span><br><span class="muted" style="font-size:.8rem">CS: %s</span></td>`, cfSync, csSync); err != nil {
		return err
	}

	// Status cell
	_, err := fmt.Fprintf(w, `<td><span class="badge %s">%s</span></td></tr>`,
		html.EscapeString(statusClass),
		html.EscapeString(trustedNetworkStatusLabel(entry.Status)),
	)
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
