package ui

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleV2Providers(w http.ResponseWriter, r *http.Request) {
	view, _ := s.unifiedProvidersView()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, renderV2ProvidersPage(view, s.csrfTokenFromRequest(r)))
}

func renderV2ProvidersPage(view UnifiedProvidersView, csrfToken string) string {
	var sb strings.Builder
	summary := summarizeProviderOverview(view)
	totalProviders := len(view.AI.Providers) + len(view.NonAI)
	attention := summary.Warning + summary.Error
	postureTitle := "All providers operational"
	postureClass := "ok"
	if attention > 0 {
		postureTitle = fmt.Sprintf("%d provider issue(s) need review", attention)
		postureClass = "warn"
	}
	if summary.Error > 0 {
		postureClass = "error"
	}

	sb.WriteString(`<style>
.v2-providers-wrap{width:100%}
.v2-integrations{background:#13151c;border:1px solid #242838;border-radius:12px;box-shadow:0 12px 34px rgba(0,0,0,.18);overflow:hidden;color:#e8eaf1}
.v2-integrations-top{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid #20242f}
.v2-integrations-title{font:700 14px 'Hanken Grotesk',sans-serif;color:#eef0f6}
.v2-integrations-sub{font:500 12px 'JetBrains Mono',monospace;color:#6b7184}
.v2-action{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:5px 11px;border-radius:7px;background:#1c2030;border:1px solid #2a2f42;font:600 11px 'Hanken Grotesk',sans-serif;color:#c5cad8;text-decoration:none;cursor:pointer;min-height:28px}
.v2-action.primary{background:rgba(124,108,242,.14);border-color:rgba(124,108,242,.3);color:#a99cff}
.v2-action.warn{background:rgba(245,146,30,.1);border-color:rgba(245,146,30,.22);color:#f5b563}
.v2-action:disabled{opacity:.6;cursor:wait}
.v2-provider-posture{padding:18px;border-bottom:1px solid #20242f}
.v2-posture-line{display:flex;align-items:center;gap:14px}
.v2-posture-dot{width:14px;height:14px;border-radius:50%;background:#4cc79a;box-shadow:0 0 0 4px rgba(76,199,154,.15);flex:none}
.v2-posture-dot.warn{background:#f5921e;box-shadow:0 0 0 4px rgba(245,146,30,.15)}
.v2-posture-dot.error{background:#ef5f6b;box-shadow:0 0 0 4px rgba(239,95,107,.15)}
.v2-posture-title{font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6}
.v2-posture-meta{font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-top:2px}
.v2-chip-row{display:flex;gap:7px;flex-wrap:wrap}
.v2-chip{display:inline-flex;align-items:center;gap:5px;font:600 11px 'JetBrains Mono',monospace;border-radius:6px;padding:3px 9px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);color:#9aa0b2}
.v2-chip.ok{color:#54c79a;background:rgba(76,199,154,.12);border-color:rgba(76,199,154,.22)}
.v2-chip.warn{color:#f5b563;background:rgba(245,146,30,.1);border-color:rgba(245,146,30,.22)}
.v2-chip.error{color:#f08591;background:rgba(239,95,107,.1);border-color:rgba(239,95,107,.22)}
.v2-advisory{display:flex;align-items:center;gap:10px;margin-top:14px;padding:10px 12px;border-radius:9px;background:rgba(245,146,30,.07);border:1px solid rgba(245,146,30,.2)}
.v2-advisory.error{background:rgba(239,95,107,.07);border-color:rgba(239,95,107,.2)}
.v2-section{padding:16px 18px;border-bottom:1px solid #20242f}
.v2-section:last-child{border-bottom:none}
.v2-section-head{display:flex;align-items:center;margin-bottom:11px;gap:10px}
.v2-section-title{font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase}
.v2-section-note{font:500 10px 'JetBrains Mono',monospace;color:#6b7184;margin-left:auto}
.v2-provider-list{display:flex;flex-direction:column;gap:8px}
.v2-provider-row{display:grid;grid-template-columns:9px minmax(92px,1.1fr) minmax(100px,1.3fr) minmax(60px,.7fr) minmax(86px,.8fr) auto;align-items:center;gap:11px;padding:9px 11px;border:1px solid #20242f;border-radius:9px;background:#10121a;transition:border-color .14s ease,background .14s ease,transform .14s ease}
.v2-provider-row:hover{border-color:#2f3548;background:#12151f;transform:translateY(-1px)}
.v2-provider-row.warn{border-color:rgba(245,146,30,.2);background:rgba(245,146,30,.045)}
.v2-provider-row.error{border-color:rgba(239,95,107,.22);background:rgba(239,95,107,.045)}
.v2-provider-row.disabled{border-color:rgba(255,255,255,.06);background:rgba(255,255,255,.025)}
.v2-status-dot{width:7px;height:7px;border-radius:50%;background:#4cc79a}
.v2-status-dot.warn{background:#f5921e}
.v2-status-dot.error{background:#ef5f6b}
.v2-status-dot.disabled{background:#6b7184}
.v2-provider-name{font:600 13px 'Hanken Grotesk',sans-serif;color:#e3e6ef;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.v2-model-tag{display:inline-flex;align-items:center;width:max-content;max-width:100%;font:500 11px 'JetBrains Mono',monospace;color:#9aa0b2;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:2px 7px;border-radius:5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.v2-muted{font:500 11px 'JetBrains Mono',monospace;color:#6b7184;white-space:nowrap}
.v2-state{font:600 10px 'JetBrains Mono',monospace;color:#54c79a;background:rgba(76,199,154,.1);padding:2px 7px;border-radius:5px;text-transform:lowercase;width:max-content;white-space:nowrap}
.v2-state.warn{color:#f5b563;background:rgba(245,146,30,.1)}
.v2-state.error{color:#f08591;background:rgba(239,95,107,.1)}
.v2-state.disabled{color:#8c93a8;background:rgba(255,255,255,.04)}
.v2-row-actions{display:flex;align-items:center;gap:7px;justify-content:flex-end;flex-wrap:wrap}
.v2-row-actions form{display:inline-flex;margin:0}
.v2-provider-details{margin-top:8px;border:1px solid #20242f;border-radius:10px;background:#10121a;overflow:hidden}
.v2-provider-details>summary{cursor:pointer;list-style:none;padding:9px 12px;font:600 11px 'Hanken Grotesk',sans-serif;color:#a99cff}
.v2-provider-details>summary::-webkit-details-marker{display:none}
.v2-detail-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:1px solid #20242f}
.v2-detail-cell{padding:9px 12px;border-right:1px solid #1a1e29;border-bottom:1px solid #1a1e29;min-width:0}
.v2-detail-cell:nth-child(3n){border-right:none}
.v2-detail-key{font:700 9px 'Hanken Grotesk',sans-serif;color:#7b8196;letter-spacing:.06em;text-transform:uppercase}
.v2-detail-val{margin-top:3px;font:500 11px 'JetBrains Mono',monospace;color:#c5cad8;overflow-wrap:anywhere}
.v2-key-form{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.v2-key-form label{font:700 9px 'Hanken Grotesk',sans-serif;color:#7b8196;text-transform:uppercase;letter-spacing:.06em}
.v2-key-form input{width:170px;background:#0d0f14;border:1px solid #2a2f42;border-radius:7px;color:#e8eaf1;padding:6px 8px;font:500 12px 'JetBrains Mono',monospace}
.v2-boundary-strip{border:1px solid rgba(76,199,154,.2);border-radius:10px;background:rgba(76,199,154,.04);padding:12px 13px}
.v2-boundary-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.v2-toast{position:fixed;right:18px;bottom:18px;z-index:250;background:#151823;border:1px solid #2a2f42;color:#e8eaf1;border-radius:9px;padding:10px 12px;font:600 12px 'Hanken Grotesk',sans-serif;box-shadow:0 12px 34px rgba(0,0,0,.3)}
@media(max-width:780px){.v2-providers-wrap{max-width:none}.v2-posture-line{align-items:flex-start;flex-wrap:wrap}.v2-provider-row{grid-template-columns:9px minmax(0,1fr)!important;gap:7px 9px;align-items:start}.v2-provider-name,.v2-provider-row .v2-model-tag,.v2-provider-row .v2-muted,.v2-provider-row .v2-state,.v2-row-actions{grid-column:2}.v2-provider-row .v2-model-tag{width:auto;max-width:100%;white-space:normal;line-height:1.35}.v2-provider-row .v2-muted{white-space:normal}.v2-row-actions{justify-content:flex-start}.v2-detail-grid{grid-template-columns:1fr}.v2-detail-cell{border-right:none}.v2-integrations-top{flex-wrap:wrap}.v2-section-head{align-items:flex-start;flex-direction:column}.v2-section-note{margin-left:0}.v2-key-form input{width:min(100%,220px)}.v2-boundary-row{display:grid;grid-template-columns:1fr;align-items:start}.v2-boundary-row .v2-provider-name{white-space:normal}.v2-boundary-row .v2-model-tag,.v2-boundary-row .v2-action{width:max-content;max-width:100%}.v2-boundary-row>span[style*="flex:1"]{width:100%;line-height:1.45}.v2-chip-row{align-items:flex-start}}
</style>`)

	sb.WriteString(`<div class="v2-topbar"><h1 class="v2-topbar-title">Providers</h1><button class="v2-kbd-trigger" data-palette-trigger type="button">⌘K</button><span class="v2-live-badge"><span class="v2-live-dot"></span>LIVE</span></div>`)
	sb.WriteString(`<div class="v2-providers-wrap"><div id="providers-live-shell" class="v2-integrations" data-live-shell="providers" data-refresh-url="/v2/providers">`)
	sb.WriteString(`<div class="v2-integrations-top"><span class="v2-integrations-title">Provider mesh</span><span class="v2-integrations-sub">· providers · boundary · diagnostics</span><span style="flex:1"></span>`)
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/test-all" method="post"><input type="hidden" name="csrf_token" value="%s"><button class="v2-action primary" type="submit">Test all</button></form>`, html.EscapeString(csrfToken)))
	sb.WriteString(`</div>`)

	now := time.Now()
	sb.WriteString(fmt.Sprintf(`<div class="v2-provider-posture"><div class="v2-posture-line"><span class="v2-posture-dot %s"></span><div style="flex:1"><div class="v2-posture-title">%s</div><div class="v2-posture-meta">%d providers · server-rendered · <span data-ts="%d" data-ts-full="%s" title="%s">just now</span></div></div><div class="v2-chip-row"><span class="v2-chip ok">%d healthy</span><span class="v2-chip warn">%d attention</span><span class="v2-chip error">%d error</span><span class="v2-chip">%d disabled</span></div></div>`,
		html.EscapeString(postureClass),
		html.EscapeString(postureTitle),
		totalProviders,
		now.Unix(),
		html.EscapeString(now.UTC().Format(time.RFC3339)),
		html.EscapeString(now.UTC().Format("2006-01-02 15:04:05 UTC")),
		summary.Healthy,
		summary.Warning,
		summary.Error,
		summary.Disabled,
	))
	advisory := providerAdvisory(view)
	if advisory != "" {
		advisoryClass := "v2-advisory"
		if summary.Error > 0 {
			advisoryClass += " error"
		}
		sb.WriteString(fmt.Sprintf(`<div class="%s"><span class="v2-status-dot warn"></span><span style="font:600 12px 'Hanken Grotesk',sans-serif;color:#f5b563">Needs operator</span><span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#aab0c2;flex:1">%s</span><span style="font:600 11px 'Hanken Grotesk',sans-serif;color:#f5b563">Review</span></div>`, advisoryClass, html.EscapeString(advisory)))
	}
	if view.Error != "" {
		sb.WriteString(fmt.Sprintf(`<div class="v2-advisory error"><span class="v2-status-dot error"></span><span style="font:600 12px 'Hanken Grotesk',sans-serif;color:#f08591">View error</span><span style="font:500 12px 'Hanken Grotesk',sans-serif;color:#aab0c2;flex:1">%s</span></div>`, html.EscapeString(view.Error)))
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="v2-section"><div class="v2-section-head"><span class="v2-section-title">AI Providers</span><span class="v2-section-note">key/enable/test managed</span></div><div class="v2-provider-list">`)
	for _, p := range view.AI.Providers {
		sb.WriteString(renderV2AIProviderRow(p, csrfToken))
	}
	if len(view.AI.Providers) == 0 {
		sb.WriteString(`<div class="v2-empty">No AI providers configured.</div>`)
	}
	sb.WriteString(`</div></div>`)

	managed, infra := splitNonAIProviders(view.NonAI)
	sb.WriteString(`<div class="v2-section"><div class="v2-section-head"><span class="v2-section-title">Reporting &amp; Enrichment</span><span class="v2-section-note">key rotation</span></div><div class="v2-provider-list">`)
	for _, p := range managed {
		sb.WriteString(renderV2NonAIProviderRow(p, csrfToken))
	}
	if len(managed) == 0 {
		sb.WriteString(`<div class="v2-empty">No enrichment providers configured.</div>`)
	}
	sb.WriteString(`</div></div>`)

	sb.WriteString(`<div class="v2-section"><div class="v2-section-head"><span class="v2-section-title">Boundary · infrastructure</span><span class="v2-section-note">config-managed · read-only</span></div>`)
	sb.WriteString(renderV2BoundaryStrip(infra))
	if len(infra) > 0 {
		sb.WriteString(`<div class="v2-provider-list" style="margin-top:8px">`)
		for _, p := range infra {
			sb.WriteString(renderV2InfraProviderRow(p))
		}
		sb.WriteString(`</div>`)
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`<div class="v2-section"><div class="v2-section-head"><span class="v2-section-title">Trusted networks</span><span class="v2-section-note">deduplicated context</span></div><div class="v2-boundary-strip" style="border-color:rgba(124,108,242,.16);background:rgba(124,108,242,.06)"><div class="v2-boundary-row"><span class="v2-model-tag" style="color:#a99cff;background:rgba(124,108,242,.14)">sync: read-only</span><span style="font:500 11px 'Hanken Grotesk',sans-serif;color:#9aa0b2;flex:1">Trusted Networks remains the source of truth; this page links to the existing registry without duplicating CIDR rows.</span><a class="v2-action primary" href="/trusted-networks">Open registry</a></div></div></div>`)

	sb.WriteString(`<script src="/v2/static/providers-live.js" defer></script></div></div>`)
	return v2Page("Providers", "/v2/providers", sb.String())
}

func splitNonAIProviders(entries []NonAIProviderEntry) (managed []NonAIProviderEntry, infra []NonAIProviderEntry) {
	for _, p := range entries {
		if p.HasKeyManagement {
			managed = append(managed, p)
		} else {
			infra = append(infra, p)
		}
	}
	return managed, infra
}

func providerAdvisory(view UnifiedProvidersView) string {
	var items []string
	for _, p := range view.AI.Providers {
		switch providerTone(p.Status, p.EnabledState, p.SecretState, p.HealthyState) {
		case "error", "warn":
			items = append(items, p.Name+" "+strings.ToLower(displayProviderErrorCode(valueOrFallback(p.LastErrorCode, p.Status))))
		}
	}
	for _, p := range view.NonAI {
		switch providerTone(p.Status, p.EnabledState, p.ConfiguredState, p.HealthyState) {
		case "error", "warn":
			if !p.Enabled {
				items = append(items, p.Name+" disabled")
			} else if !p.Configured {
				items = append(items, p.Name+" missing key")
			} else {
				items = append(items, p.Name+" "+strings.ToLower(displayProviderErrorCode(p.LastErrorCode)))
			}
		}
	}
	if len(items) == 0 {
		return ""
	}
	if len(items) > 3 {
		items = append(items[:3], fmt.Sprintf("+%d more", len(items)-3))
	}
	return strings.Join(items, " · ")
}

func renderV2AIProviderRow(p AIProviderManagementEntry, csrfToken string) string {
	tone := providerTone(p.Status, p.EnabledState, p.SecretState, p.HealthyState)
	statusText := providerCompactStatus(p.Status, p.EnabledState, p.SecretState, p.LastTestStatus)
	latency := valueOrFallback(p.LastTestLatencyMS, "n/a")
	model := valueOrFallback(p.Model, "model unset")
	nameSlug := strings.ToLower(p.Name)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<div class="v2-provider-row %s"><span class="v2-status-dot %s"></span><span class="v2-provider-name">%s</span><span class="v2-model-tag">%s</span><span class="v2-muted">%s</span><span class="v2-state %s">%s</span><span class="v2-row-actions">`,
		html.EscapeString(tone),
		html.EscapeString(tone),
		html.EscapeString(p.Name),
		html.EscapeString(model),
		html.EscapeString(latency),
		html.EscapeString(tone),
		html.EscapeString(statusText),
	))
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/%s/test" method="post"><input type="hidden" name="csrf_token" value="%s"><button type="submit" class="v2-action">Test</button></form>`, html.EscapeString(nameSlug), html.EscapeString(csrfToken)))
	toggleAction := "enable"
	toggleLabel := "Enable"
	toggleClass := "v2-action primary"
	if p.Enabled {
		toggleAction = "disable"
		toggleLabel = "Disable"
		toggleClass = "v2-action"
	}
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/%s/%s" method="post"><input type="hidden" name="csrf_token" value="%s"><button type="submit" class="%s">%s</button></form>`, html.EscapeString(nameSlug), toggleAction, html.EscapeString(csrfToken), toggleClass, toggleLabel))
	sb.WriteString(`</span></div>`)
	sb.WriteString(fmt.Sprintf(`<details class="v2-provider-details"><summary>Details · key rotation · diagnostic JSON</summary><div class="v2-detail-grid">%s</div><div style="padding:10px 12px;border-top:1px solid #20242f;display:flex;gap:8px;align-items:center;flex-wrap:wrap">`, renderV2DetailCells([][2]string{
		{"configured", p.ConfiguredState},
		{"enabled", p.EnabledState},
		{"secret", p.SecretState},
		{"healthy", p.HealthyState},
		{"last test", p.LastTestAt},
		{"last success", p.LastSuccessAt},
		{"last failure", p.LastFailureAt},
		{"test status", displayProviderTestStatus(p.LastTestStatus)},
		{"last error", displayProviderErrorCode(p.LastErrorCode)},
		{"validation", p.ValidationMessage},
	})))
	sb.WriteString(fmt.Sprintf(`<form class="v2-key-form" data-live-provider-form="true" action="/admin/providers/%s/key" method="post"><input type="hidden" name="csrf_token" value="%s"><input type="hidden" name="confirm_replace" value="yes"><label>new api key</label><input type="password" name="new_api_key" autocomplete="new-password" spellcheck="false"><button type="submit" class="v2-action primary">Update key</button></form>`, html.EscapeString(nameSlug), html.EscapeString(csrfToken)))
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/%s/reset-diagnostics" method="post"><input type="hidden" name="csrf_token" value="%s"><button type="submit" class="v2-action">Reset diagnostics</button></form>`, html.EscapeString(nameSlug), html.EscapeString(csrfToken)))
	sb.WriteString(fmt.Sprintf(`<button type="button" class="v2-action" data-copy-diagnostic="%s">Copy diagnostic JSON</button>`, html.EscapeString(providerDiagnosticJSON(p.Name, p.Status, p.EnabledState, p.SecretState, p.HealthyState, p.LastTestAt, p.LastTestLatencyMS, p.LastErrorCode))))
	sb.WriteString(`</div></details>`)
	return sb.String()
}

func renderV2NonAIProviderRow(p NonAIProviderEntry, csrfToken string) string {
	tone := providerTone(p.Status, p.EnabledState, p.ConfiguredState, p.HealthyState)
	latency := valueOrFallback(p.LastLatencyMS, "n/a")
	statusText := providerCompactStatus(p.Status, p.EnabledState, p.ConfiguredState, p.LastErrorCode)
	slug := strings.ToLower(p.Name)
	keyDisplay := "key not rendered"
	if strings.TrimSpace(p.MaskedKey) != "" {
		keyDisplay = "key " + p.MaskedKey
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<div class="v2-provider-row %s"><span class="v2-status-dot %s"></span><span class="v2-provider-name">%s</span><span class="v2-model-tag">%s</span><span class="v2-muted">%s</span><span class="v2-state %s">%s</span><span class="v2-row-actions">`,
		html.EscapeString(tone),
		html.EscapeString(tone),
		html.EscapeString(p.Name),
		html.EscapeString(p.Category),
		html.EscapeString(latency),
		html.EscapeString(tone),
		html.EscapeString(statusText),
	))
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/%s/test" method="post"><input type="hidden" name="csrf_token" value="%s"><button type="submit" class="v2-action">Test</button></form>`, html.EscapeString(slug), html.EscapeString(csrfToken)))
	toggleAction := "enable"
	toggleLabel := "Enable"
	toggleClass := "v2-action primary"
	if p.Enabled {
		toggleAction = "disable"
		toggleLabel = "Disable"
		toggleClass = "v2-action"
	}
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/%s/%s" method="post"><input type="hidden" name="csrf_token" value="%s"><button type="submit" class="%s">%s</button></form>`, html.EscapeString(slug), toggleAction, html.EscapeString(csrfToken), toggleClass, toggleLabel))
	sb.WriteString(`</span></div>`)
	sb.WriteString(fmt.Sprintf(`<details class="v2-provider-details"><summary>Details · key rotation · diagnostic JSON</summary><div class="v2-detail-grid">%s</div><div style="padding:10px 12px;border-top:1px solid #20242f;display:flex;gap:8px;align-items:center;flex-wrap:wrap">`, renderV2DetailCells([][2]string{
		{"configured", p.ConfiguredState},
		{"enabled", p.EnabledState},
		{"healthy", p.HealthyState},
		{"credential", keyDisplay},
		{"last test", p.LastTestAt},
		{"last success", p.LastSuccessAt},
		{"last failure", p.LastFailureAt},
		{"last error", displayProviderErrorCode(p.LastErrorCode)},
		{"category", p.Category},
	})))
	sb.WriteString(fmt.Sprintf(`<form class="v2-key-form" data-live-provider-form="true" action="/admin/providers/%s/key" method="post"><input type="hidden" name="csrf_token" value="%s"><input type="hidden" name="confirm_replace" value="yes"><label>new api key</label><input type="password" name="new_api_key" autocomplete="new-password" spellcheck="false"><button type="submit" class="v2-action primary">Update key</button></form>`, html.EscapeString(slug), html.EscapeString(csrfToken)))
	sb.WriteString(fmt.Sprintf(`<form data-live-provider-form="true" action="/admin/providers/%s/reset-diagnostics" method="post"><input type="hidden" name="csrf_token" value="%s"><button type="submit" class="v2-action">Reset diagnostics</button></form>`, html.EscapeString(slug), html.EscapeString(csrfToken)))
	sb.WriteString(fmt.Sprintf(`<button type="button" class="v2-action" data-copy-diagnostic="%s">Copy diagnostic JSON</button>`, html.EscapeString(providerDiagnosticJSON(p.Name, p.Status, p.EnabledState, p.ConfiguredState, p.HealthyState, p.LastTestAt, p.LastLatencyMS, p.LastErrorCode))))
	sb.WriteString(`</div></details>`)
	return sb.String()
}

func renderV2InfraProviderRow(p NonAIProviderEntry) string {
	tone := providerTone(p.Status, enabledText(p.Enabled), configuredText(p.Configured), p.HealthyState)
	note := valueOrFallback(p.Notes, p.Category)
	return fmt.Sprintf(`<div class="v2-provider-row %s" style="grid-template-columns:9px minmax(92px,1fr) minmax(120px,1.5fr) minmax(86px,.8fr) auto"><span class="v2-status-dot %s"></span><span class="v2-provider-name">%s</span><span class="v2-model-tag">%s</span><span class="v2-state %s">%s</span><span class="v2-row-actions"><a class="v2-action" href="%s">Open</a></span></div>`,
		html.EscapeString(tone),
		html.EscapeString(tone),
		html.EscapeString(p.Name),
		html.EscapeString(note),
		html.EscapeString(tone),
		html.EscapeString(providerCompactStatus(p.Status, enabledText(p.Enabled), configuredText(p.Configured), "")),
		html.EscapeString(infraProviderHref(p.Name)),
	)
}

func renderV2BoundaryStrip(infra []NonAIProviderEntry) string {
	cfConfigured := false
	for _, p := range infra {
		if strings.EqualFold(p.Name, "Cloudflare") {
			cfConfigured = p.Configured
			break
		}
	}
	tone := "ok"
	status := "boundary converged"
	detail := "config-managed · read-only"
	if !cfConfigured {
		tone = "warn"
		status = "configuration incomplete"
		detail = "Cloudflare token or zone missing"
	}
	return fmt.Sprintf(`<div class="v2-boundary-strip"><div class="v2-boundary-row"><span class="v2-status-dot %s"></span><span class="v2-provider-name">Cloudflare boundary</span><span class="v2-state %s">%s</span><span style="flex:1"></span><span class="v2-muted">%s</span><a class="v2-action primary" href="/cloudflare/diff">View diff</a></div><div class="v2-chip-row" style="margin-top:10px"><span class="v2-chip"><span style="color:#787f93">desired</span> live</span><span class="v2-chip"><span style="color:#787f93">observed</span> config-backed</span><span class="v2-chip ok">no mutation exposed here</span></div></div>`,
		html.EscapeString(tone),
		html.EscapeString(tone),
		html.EscapeString(status),
		html.EscapeString(detail),
	)
}

func renderV2DetailCells(rows [][2]string) string {
	var sb strings.Builder
	for _, row := range rows {
		sb.WriteString(fmt.Sprintf(`<div class="v2-detail-cell"><div class="v2-detail-key">%s</div><div class="v2-detail-val">%s</div></div>`, html.EscapeString(row[0]), html.EscapeString(valueOrFallback(row[1], "n/a"))))
	}
	return sb.String()
}

func providerTone(values ...string) string {
	joined := strings.ToLower(strings.Join(values, " "))
	switch {
	case strings.Contains(joined, "missing_secret"), strings.Contains(joined, "invalid"), strings.Contains(joined, "auth"), strings.Contains(joined, "error"):
		return "error"
	case strings.Contains(joined, "disabled"), strings.Contains(joined, "not configured"):
		return "disabled"
	case strings.Contains(joined, "warning"), strings.Contains(joined, "timeout"), strings.Contains(joined, "rate"), strings.Contains(joined, "quota"), strings.Contains(joined, "failed"), strings.Contains(joined, "missing"):
		return "warn"
	default:
		return "ok"
	}
}

func providerCompactStatus(status, enabled, secretOrConfigured, testStatus string) string {
	status = strings.TrimSpace(status)
	enabled = strings.ToLower(strings.TrimSpace(enabled))
	secretOrConfigured = strings.ToLower(strings.TrimSpace(secretOrConfigured))
	testStatus = strings.TrimSpace(testStatus)
	switch {
	case enabled == "disabled", strings.EqualFold(status, providerStatusDisabled):
		return "disabled by operator"
	case strings.EqualFold(status, providerStatusMissingSecret), strings.Contains(secretOrConfigured, "missing_secret"):
		return "missing secret"
	case strings.Contains(secretOrConfigured, "not configured"), strings.Contains(secretOrConfigured, "missing"):
		return "missing key"
	case testStatus != "":
		return displayProviderTestStatus(testStatus)
	case status != "":
		return displayProviderTestStatus(status)
	default:
		return "ready"
	}
}

func providerDiagnosticJSON(name, status, enabled, secretOrConfigured, healthy, lastTest, latency, errorCode string) string {
	fields := []string{
		`"provider":"` + jsonEscape(name) + `"`,
		`"status":"` + jsonEscape(status) + `"`,
		`"enabled":"` + jsonEscape(enabled) + `"`,
		`"credential_state":"` + jsonEscape(secretOrConfigured) + `"`,
		`"healthy":"` + jsonEscape(healthy) + `"`,
		`"last_test_at":"` + jsonEscape(lastTest) + `"`,
		`"latency":"` + jsonEscape(latency) + `"`,
		`"error_code":"` + jsonEscape(displayProviderErrorCode(errorCode)) + `"`,
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func jsonEscape(s string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return replacer.Replace(s)
}

func infraProviderHref(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cloudflare":
		return "/cloudflare/diff"
	case "crowdsec":
		return "/trusted-networks"
	case "betterstack":
		return "/about"
	default:
		return "/providers"
	}
}
