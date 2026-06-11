package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/security/audit"
)

type navItem struct {
	Label  string
	Href   string
	Active bool
	Soon   bool
}

type shellView struct {
	Title       string
	Headline    string
	Subtitle    string
	Active      string
	Body        templ.Component
	BodyClass   string
	BadgeLabels []StatusItem
}

func ConsoleLayout(view shellView) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		items := consoleNav(view.Active)
		if view.BodyClass == "" {
			view.BodyClass = "page"
		}
		if _, err := fmt.Fprint(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "<title>%s</title>", html.EscapeString(view.Title)); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, `<style>
			:root {
				color-scheme: light;
				--bg: #f4f7fb;
				--panel: #ffffff;
				--panel-strong: #f8fbff;
				--border: #d8e1ef;
				--text: #10243e;
				--muted: #5f6b7a;
				--sidebar: #0f1d33;
				--sidebar-soft: #142544;
				--sidebar-border: rgba(255,255,255,.08);
				--sidebar-text: #dce8ff;
				--sidebar-active: #1f335c;
				--badge: #eef4ff;
				--badge-text: #234;
				--healthy: #0f8b4c;
				--warning: #8f5c00;
				--degraded: #8b5e34;
				--disabled: #69727d;
				--error: #9b1c1c;
				--dryrun: #5b4b9a;
				--live: #0a6b75;
			}
			* { box-sizing: border-box; }
			html, body { min-height: 100%; }
			body {
				margin: 0;
				font-family: system-ui, sans-serif;
				background: var(--bg);
				color: var(--text);
			}
			a { color: inherit; }
			.shell {
				min-height: 100vh;
				display: grid;
				grid-template-columns: minmax(16rem, 18.5rem) minmax(0, 1fr);
			}
			.sidebar {
				background: linear-gradient(180deg, var(--sidebar), #0d1727);
				color: var(--sidebar-text);
				padding: 1rem 0.9rem 1.2rem;
				border-right: 1px solid var(--sidebar-border);
				position: sticky;
				top: 0;
				height: 100vh;
				overflow: auto;
			}
			.brand {
				display: flex;
				flex-direction: column;
				gap: .2rem;
				padding: .25rem .35rem .9rem;
				border-bottom: 1px solid var(--sidebar-border);
				margin-bottom: .9rem;
			}
			.brand strong { font-size: 1rem; }
			.brand span { color: rgba(220,232,255,.72); font-size: .88rem; }
			.nav {
				display: grid;
				gap: .25rem;
			}
			.nav a {
				display: flex;
				align-items: center;
				justify-content: space-between;
				gap: .75rem;
				text-decoration: none;
				padding: .72rem .8rem;
				border-radius: 8px;
				color: var(--sidebar-text);
				border: 1px solid transparent;
			}
			.nav a:hover { background: rgba(255,255,255,.05); }
			.nav a.active {
				background: var(--sidebar-active);
				border-color: rgba(255,255,255,.08);
			}
			.nav .soon {
				font-size: .75rem;
				color: rgba(220,232,255,.75);
				background: rgba(255,255,255,.06);
				padding: .12rem .45rem;
				border-radius: 999px;
				white-space: nowrap;
			}
			.main {
				padding: 1.15rem;
			}
			.page {
				max-width: 1380px;
				margin: 0 auto;
				display: grid;
				gap: 1rem;
			}
			.pagehead {
				display: flex;
				align-items: flex-end;
				justify-content: space-between;
				gap: 1rem;
				flex-wrap: wrap;
			}
			.pagehead h1, .pagehead h2 {
				margin: 0;
				line-height: 1.1;
			}
			.pagehead p {
				margin: .35rem 0 0;
				color: var(--muted);
				max-width: 72ch;
			}
			.badges {
				display: flex;
				flex-wrap: wrap;
				gap: .45rem;
				justify-content: flex-end;
			}
			.badge {
				display: inline-flex;
				align-items: center;
				gap: .25rem;
				padding: .22rem .55rem;
				border-radius: 999px;
				font-size: .78rem;
				background: var(--badge);
				color: var(--badge-text);
				border: 1px solid rgba(0,0,0,.04);
				white-space: nowrap;
			}
			.badge.healthy { color: var(--healthy); background: #e7f8ef; }
			.badge.warning { color: var(--warning); background: #fff4dd; }
			.badge.degraded { color: var(--degraded); background: #f3eadf; }
			.badge.disabled { color: var(--disabled); background: #edf0f3; }
			.badge.error { color: var(--error); background: #fdecec; }
			.badge.dryrun { color: var(--dryrun); background: #f0ecff; }
			.badge.live { color: var(--live); background: #e8fafb; }
			.grid {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
				gap: 1rem;
			}
			.panel {
				background: var(--panel);
				border: 1px solid var(--border);
				border-radius: 10px;
				padding: 1rem;
				box-shadow: 0 1px 2px rgba(16,36,62,.05);
			}
			.panel h2, .panel h3 {
				margin: 0 0 .65rem;
				line-height: 1.15;
			}
			.muted { color: var(--muted); }
			.error { color: var(--error); }
			.kv { display: grid; gap: .4rem; }
			.row {
				display: grid;
				grid-template-columns: minmax(6rem, 9rem) minmax(0, 1fr);
				gap: 1rem;
				align-items: start;
				border-top: 1px solid #edf1f7;
				padding: .55rem 0;
			}
			.row:first-child { border-top: 0; padding-top: 0; }
			.row span:last-child { overflow-wrap: anywhere; }
			table {
				width: 100%;
				border-collapse: collapse;
				background: var(--panel);
				border: 1px solid var(--border);
				border-radius: 10px;
				overflow: hidden;
			}
			thead th {
				text-align: left;
				font-size: .8rem;
				text-transform: uppercase;
				letter-spacing: .02em;
				color: var(--muted);
				background: var(--panel-strong);
				padding: .75rem .7rem;
				border-bottom: 1px solid var(--border);
			}
			tbody td {
				padding: .72rem .7rem;
				border-top: 1px solid #eef2f8;
				vertical-align: top;
			}
			tbody tr:first-child td { border-top: 0; }
			.empty {
				padding: 1rem;
				color: var(--muted);
				background: #fafbfd;
				border: 1px dashed var(--border);
				border-radius: 10px;
			}
			.stack { display: grid; gap: .75rem; }
			@media (max-width: 900px) {
				.shell { grid-template-columns: 1fr; }
				.sidebar {
					position: static;
					height: auto;
					border-right: 0;
					border-bottom: 1px solid var(--sidebar-border);
				}
			}
		</style><script src="/static/ai-explain.js" defer></script></head><body><div class="shell">`); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, `<aside class="sidebar"><div class="brand"><strong>Operator Console</strong><span>Local control surface</span></div><nav class="nav">`); err != nil {
			return err
		}
		for _, item := range items {
			if _, err := fmt.Fprint(w, `<a href="`); err != nil {
				return err
			}
			if _, err := io.WriteString(w, html.EscapeString(item.Href)); err != nil {
				return err
			}
			if item.Active {
				if _, err := fmt.Fprint(w, `" class="active" aria-current="page">`); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprint(w, `">`); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(w, html.EscapeString(item.Label)); err != nil {
				return err
			}
			if item.Soon {
				if _, err := fmt.Fprint(w, `<span class="soon">soon</span>`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</a>`); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</nav></aside><main class="main"><div class="`); err != nil {
			return err
		}
		if _, err := io.WriteString(w, html.EscapeString(view.BodyClass)); err != nil {
			return err
		}
		if _, err := fmt.Fprint(w, `">`); err != nil {
			return err
		}
		if view.Headline != "" || view.Subtitle != "" || len(view.BadgeLabels) > 0 {
			if _, err := fmt.Fprint(w, `<div class="pagehead">`); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, `<div><h1>%s</h1>`, html.EscapeString(view.Headline)); err != nil {
				return err
			}
			if view.Subtitle != "" {
				if _, err := fmt.Fprintf(w, `<p>%s</p>`, html.EscapeString(view.Subtitle)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</div>`); err != nil {
				return err
			}
			if len(view.BadgeLabels) > 0 {
				if _, err := fmt.Fprint(w, `<div class="badges">`); err != nil {
					return err
				}
				for _, badge := range view.BadgeLabels {
					if _, err := fmt.Fprintf(w, `<span class="badge %s">%s</span>`, html.EscapeString(statusClass(badge.Level)), html.EscapeString(badgeText(badge))); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</div>`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(w, `</div>`); err != nil {
				return err
			}
		}
		if view.Body != nil {
			if err := view.Body.Render(ctx, w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</div></main></div></body></html>`); err != nil {
			return err
		}
		return nil
	})
}

func consoleNav(active string) []navItem {
	items := []navItem{
		{Label: "Dashboard", Href: "/"},
		{Label: "Providers", Href: "/providers"},
		{Label: "Health", Href: "/health"},
		{Label: "Forensic", Href: "/forensic"},
		{Label: "Security Intelligence", Href: "/intelligence"},
		{Label: "Timeline", Href: "/timeline"},
		{Label: "Audit Trail", Href: "/audit"},
		{Label: "Trusted Networks", Href: "/trusted-networks"},
		{Label: "Cloudflare Diff", Href: "/cloudflare/diff"},
		{Label: "Replay", Href: "/replay", Soon: true},
		{Label: "Deban", Href: "/deban", Soon: true},
		{Label: "Recovery", Href: "/recovery", Soon: true},
		{Label: "Drift", Href: "/drift", Soon: true},
		{Label: "About/System", Href: "/about"},
	}
	for i := range items {
		items[i].Active = items[i].Href == active
	}
	return items
}

func DashboardConsolePage(view DashboardConsoleView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Operator Dashboard",
		Headline: "Dashboard++",
		Subtitle: "Runtime posture, feature switches, and the main safety rails for the local operator console.",
		Active:   "/",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<section class="grid">`); err != nil {
				return err
			}
			for _, status := range view.Statuses {
				if _, err := fmt.Fprint(w, `<div class="panel"><h2>`); err != nil {
					return err
				}
				if _, err := io.WriteString(w, html.EscapeString(status.Label)); err != nil {
					return err
				}
				if _, err := fmt.Fprint(w, `</h2><div class="badge `+statusClass(status.Level)+`">`); err != nil {
					return err
				}
				if _, err := io.WriteString(w, html.EscapeString(strings.ToUpper(status.Level))); err != nil {
					return err
				}
				if _, err := fmt.Fprint(w, `</div>`); err != nil {
					return err
				}
				if status.Detail != "" {
					if _, err := fmt.Fprintf(w, `<p class="muted">%s</p>`, html.EscapeString(status.Detail)); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</div>`); err != nil {
					return err
				}
			}
			if len(view.AIProviders) > 0 {
				if _, err := fmt.Fprint(w, `<div class="panel" style="grid-column:1/-1"><h2>AI Providers</h2><p class="muted">OpenAI, Anthropic, and Gemini are managed locally through the encrypted SQLite credential store and redacted operator state.</p><div class="grid">`); err != nil {
					return err
				}
				for _, provider := range view.AIProviders {
					if _, err := fmt.Fprint(w, `<div class="panel">`); err != nil {
						return err
					}
					if _, err := fmt.Fprintf(w, `<h3>%s</h3>`, html.EscapeString(provider.Name)); err != nil {
						return err
					}
					if _, err := fmt.Fprintf(w, `<div class="badge %s">%s</div>`, html.EscapeString(statusClass(strings.ToLower(provider.Status))), html.EscapeString(strings.ToUpper(provider.Status))); err != nil {
						return err
					}
					rows := []struct {
						label string
						value string
					}{
						{label: "model", value: provider.Model},
						{label: "last test", value: provider.LastTestAt},
						{label: "latency", value: provider.LastLatency},
						{label: "secret", value: provider.SecretState},
						{label: "enabled", value: provider.EnabledState},
					}
					if _, err := fmt.Fprint(w, `<div class="kv">`); err != nil {
						return err
					}
					for _, row := range rows {
						if err := renderProviderHealthRow(w, row.label, row.value); err != nil {
							return err
						}
					}
					if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprint(w, `</div></div>`); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w,
				`<div class="panel"><h2>Environment &amp; Health</h2>`+
					`<div class="badges">`+
					`<span class="badge healthy">%d GREEN</span>`+
					`<span class="badge warning">%d YELLOW</span>`+
					`<span class="badge error">%d RED</span>`+
					`</div>`+
					`<p class="muted">%d of %d components healthy</p>`+
					`<a href="/health">View Health Center &#x2192;</a>`+
					`</div>`,
				view.Environment.Green, view.Environment.Yellow, view.Environment.Red,
				view.Environment.Healthy, view.Environment.Total,
			); err != nil {
				return err
			}
			_, err := fmt.Fprint(w, `</section>`)
			return err
		}),
	})
}

func ProvidersConsolePage(health []ProviderHealth) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Providers",
		Headline: "Provider Health Center",
		Subtitle: "Configured state, quota placeholders, last success/error, and local masking for every provider boundary.",
		Active:   "/providers",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">Keys are masked locally. Quota is shown only when the provider exposes it; otherwise the page states that it is not exposed.</p></div>`); err != nil {
				return err
			}
			if len(health) == 0 {
				_, err := fmt.Fprint(w, `<div class="empty">No providers configured.</div>`)
				return err
			}
			if _, err := fmt.Fprint(w, `<table><thead><tr><th>Provider</th><th>Status</th><th>Quota</th><th>Latency</th><th>Errors</th><th>Mask</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, p := range health {
				quota := p.QuotaRemaining
				if quota == "" {
					quota = "quota not exposed"
				}
				latency := p.LastLatency
				if latency == "" {
					latency = "n/a"
				}
				if _, err := fmt.Fprintf(w, `<tr><td><strong>%s</strong><br><span class="muted">%s</span></td><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td>%d errors<br>%d rate limits</td><td>%s</td></tr>`,
					html.EscapeString(p.Name),
					html.EscapeString(strings.Join(nonEmpty(p.Notes), " · ")),
					html.EscapeString(statusClass(p.Status)),
					html.EscapeString(strings.ToUpper(p.Status)),
					html.EscapeString(quota),
					html.EscapeString(latency),
					p.ErrorCount,
					p.RateLimitCount,
					html.EscapeString(p.MaskedKey),
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table>`)
			return err
		}),
	})
}

func AuditTrailPage(view AuditTrailView, csrfToken string) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Audit Trail",
		Headline: "Audit Trail",
		Subtitle: "Append-only forensic actions with actor, result, correlation, and evidence identifiers.",
		Active:   "/audit",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><p class="muted">Append-only UI and operator events are shown below. Secrets, tokens, cookies, and authorization values are redacted before persistence and rendering.</p></div>`); err != nil {
				return err
			}
			if len(view.Entries) == 0 {
				return writeEmptyState(w, "No audit events yet. UI lookups and operator actions will appear here when they are recorded.")
			}
			if _, err := fmt.Fprint(w, `<table><thead><tr><th>timestamp</th><th>actor/source</th><th>action</th><th>target</th><th>result</th><th>correlation id</th><th>event id</th><th>ai</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if _, err := fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(valueOrUnknown(entry.Timestamp)),
					html.EscapeString(auditDisplayValue(auditActorSource(entry))),
					html.EscapeString(valueOrUnknown(entry.Action)),
					html.EscapeString(auditDisplayValue(entry.Target)),
					html.EscapeString(auditDisplayValue(entry.Result)),
					html.EscapeString(auditDisplayValue(entry.Correlation)),
					html.EscapeString(auditDisplayValue(entry.EventID)),
					auditAIButtonHTML(entry, csrfToken),
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table>`)
			return err
		}),
	})
}

func auditAIButtonHTML(entry audit.AuditEntry, csrfToken string) string {
	subjectID := auditAIExplainSubjectID(entry)
	return fmt.Sprintf(`<form action="/ui/ai/explain" method="post" data-ai-explain-form style="display:inline"><input type="hidden" name="subject_type" value="audit_event"/><input type="hidden" name="subject_id" value="%s"/><input type="hidden" name="provider_preference" value="auto"/><input type="hidden" name="csrf_token" value="%s"/><button type="submit" class="badge live">Explain with AI</button></form><div class="empty" data-ai-explain-result>AI explanation not requested yet.</div>`, html.EscapeString(subjectID), html.EscapeString(csrfToken))
}

func auditAIExplainSubjectID(entry audit.AuditEntry) string {
	switch {
	case strings.TrimSpace(entry.EventID) != "":
		return entry.EventID
	case strings.TrimSpace(entry.Correlation) != "":
		return entry.Correlation
	default:
		return strings.Join([]string{entry.Timestamp, entry.Action, entry.Target}, "|")
	}
}

func auditActorSource(entry audit.AuditEntry) string {
	if strings.TrimSpace(entry.ActorSession) != "" {
		return entry.ActorSession
	}
	if strings.TrimSpace(entry.Source) != "" {
		return entry.Source
	}
	if strings.TrimSpace(entry.RemoteIP) != "" {
		return entry.RemoteIP
	}
	return "unknown"
}

func auditDisplayValue(value string) string {
	value = valueOrUnknown(value)
	lower := strings.ToLower(value)
	if strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "bearer") {
		return "[redacted]"
	}
	return value
}

func AboutPage(active string, view BuildInfoView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "About / System",
		Headline: "About / System",
		Subtitle: "Build metadata, runtime details, enabled features, provider posture, and documented AI assistance.",
		Active:   active,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<section class="grid">`); err != nil {
				return err
			}
			buildRows := []keyValueRow{
				{Key: "Version", Value: view.Version},
				{Key: "Git commit", Value: view.GitCommit},
				{Key: "Build date", Value: view.BuildDate},
				{Key: "Go version", Value: view.GoVersion},
				{Key: "OS / arch", Value: view.GOOS + " / " + view.GOARCH},
			}
			if view.PackageCount != "" {
				buildRows = append(buildRows,
					keyValueRow{Key: "Packages", Value: view.PackageCount},
					keyValueRow{Key: "Go files", Value: view.GoFileCount},
					keyValueRow{Key: "Approx LOC", Value: view.ApproxLOC},
				)
			}
			if err := renderKeyValuePanel(w, "Build", buildRows); err != nil {
				return err
			}
			if err := renderKeyValuePanel(w, "Features", toKeyValues(view.FeatureStatus)); err != nil {
				return err
			}
			if err := renderKeyValuePanel(w, "Providers", keyValueRowsFromStrings(view.ProviderStatus)); err != nil {
				return err
			}
			if len(view.AIAttribution) > 0 {
				if err := renderListPanel(w, "AI assistance / development tools", view.AIAttribution, ""); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</section>`)
			return err
		}),
	})
}

func ComingSoonPage(view ComingSoonView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    view.Title,
		Headline: view.Title,
		Subtitle: view.Description,
		Active:   view.Active,
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="panel"><div class="badge dryrun">coming soon</div><p class="muted" style="margin-top:.8rem">This route is reserved in the shell so the future workflow can be added without reworking navigation or layout.</p></div>`); err != nil {
				return err
			}
			return writeEmptyState(w, "Empty state ready.")
		}),
	})
}

type keyValueRow struct {
	Key   string
	Value string
}

func renderKeyValuePanel(w io.Writer, title string, rows []keyValueRow) error {
	if _, err := fmt.Fprintf(w, `<div class="panel"><h2>%s</h2><div class="kv">`, html.EscapeString(title)); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span>%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(valueOrUnknown(row.Value))); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}

func renderListPanel(w io.Writer, title string, values []string, empty string) error {
	if _, err := fmt.Fprintf(w, `<div class="panel"><h2>%s</h2>`, html.EscapeString(title)); err != nil {
		return err
	}
	if len(values) == 0 {
		if _, err := fmt.Fprintf(w, `<p class="muted">%s</p></div>`, html.EscapeString(valueOrUnknown(empty))); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprint(w, `<div class="stack">`); err != nil {
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintf(w, `<div class="badge">%s</div>`, html.EscapeString(valueOrUnknown(value))); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div></div>`)
	return err
}

func writeEmptyState(w io.Writer, text string) error {
	_, err := fmt.Fprintf(w, `<div class="empty">%s</div>`, html.EscapeString(text))
	return err
}

func statusClass(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "healthy":
		return "healthy"
	case "warning":
		return "warning"
	case "degraded":
		return "degraded"
	case "disabled":
		return "disabled"
	case "error":
		return "error"
	case "dry run", "dry-run":
		return "dryrun"
	case "live", "live enabled":
		return "live"
	default:
		return "badge"
	}
}

func badgeText(item StatusItem) string {
	if strings.TrimSpace(item.Detail) != "" {
		return item.Detail
	}
	return strings.ToUpper(strings.TrimSpace(item.Level))
}

func toKeyValues(items []StatusItem) []keyValueRow {
	rows := make([]keyValueRow, 0, len(items))
	for _, item := range items {
		rows = append(rows, keyValueRow{Key: item.Label, Value: item.Detail + " (" + strings.ToUpper(item.Level) + ")"})
	}
	return rows
}

func keyValueRowsFromStrings(items []string) []keyValueRow {
	rows := make([]keyValueRow, 0, len(items))
	for _, item := range items {
		parts := strings.SplitN(item, ":", 2)
		if len(parts) == 2 {
			rows = append(rows, keyValueRow{Key: strings.TrimSpace(parts[0]), Value: strings.TrimSpace(parts[1])})
			continue
		}
		rows = append(rows, keyValueRow{Key: item, Value: "unknown"})
	}
	return rows
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func nonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func BuildInfoFromConfig(cfg *config.Config, providers []ProviderHealth, auditSink AuditSink) BuildInfoView {
	view := BuildInfoView{
		Version:   cfg.Version,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		FeatureStatus: []StatusItem{
			{Label: "UI mode", Level: boolStatus(cfg.UI.Enabled), Detail: boolDetail(cfg.UI.Enabled, "enabled", "disabled")},
			{Label: "UI mutations", Level: boolStatus(cfg.UI.MutationsEnabled), Detail: boolDetail(cfg.UI.MutationsEnabled, "enabled", "disabled")},
			{Label: "Cloudflare mutations", Level: boolStatus(cfg.Cloudflare.MutationsEnabled), Detail: boolDetail(cfg.Cloudflare.MutationsEnabled, "enabled", "disabled")},
			{Label: "Enrichment", Level: boolStatus(cfg.Enrichment.Enabled), Detail: boolDetail(cfg.Enrichment.Enabled, "enabled", "disabled")},
			{Label: "DNS enrichment", Level: boolStatus(cfg.Enrichment.DNSEnabled), Detail: boolDetail(cfg.Enrichment.DNSEnabled, "enabled", "disabled")},
			{Label: "ASN enrichment", Level: boolStatus(cfg.Enrichment.ASNEnabled), Detail: boolDetail(cfg.Enrichment.ASNEnabled, "enabled", "disabled")},
		},
	}
	if providers != nil {
		for _, p := range providers {
			view.ProviderStatus = append(view.ProviderStatus, fmt.Sprintf("%s: %s", p.Name, p.Status))
		}
	}
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range buildInfo.Settings {
			switch setting.Key {
			case "vcs.revision":
				view.GitCommit = setting.Value
			case "vcs.time":
				view.BuildDate = setting.Value
			}
		}
	}
	if metrics := repoMetrics(); metrics != nil {
		view.PackageCount = metrics.Packages
		view.GoFileCount = metrics.GoFiles
		view.ApproxLOC = metrics.LOC
	}
	view.AIAttribution = loadAIAttribution()
	return view
}

type repoStats struct {
	Packages string
	GoFiles  string
	LOC      string
}

func repoMetrics() *repoStats {
	root, err := findRepoRoot()
	if err != nil {
		return nil
	}
	stats := &repoStats{}
	pkgs := make(map[string]struct{})
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(name) != ".go" {
			return nil
		}
		stats.GoFiles = incrCount(stats.GoFiles)
		pkgs[filepath.Dir(path)] = struct{}{}
		count, err := countLines(path)
		if err == nil {
			stats.LOC = addCount(stats.LOC, count)
		}
		return nil
	})
	stats.Packages = strconv.Itoa(len(pkgs))
	return stats
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("repo root not found")
		}
		dir = parent
	}
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func incrCount(value string) string {
	if value == "" {
		return "1"
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return value
	}
	return strconv.Itoa(n + 1)
}

func addCount(value string, inc int) string {
	if value == "" {
		return strconv.Itoa(inc)
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return value
	}
	return strconv.Itoa(n + inc)
}

func loadAIAttribution() []string {
	candidates := []string{"docs/AI_ASSISTANCE.md", filepath.Join("..", "docs", "AI_ASSISTANCE.md")}
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(raw), "\n")
		var tools []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "- ") {
				continue
			}
			tools = append(tools, strings.TrimSpace(strings.TrimPrefix(line, "- ")))
		}
		if len(tools) > 0 {
			sort.Strings(tools)
			return tools
		}
	}
	return nil
}

func boolStatus(v bool) string {
	if v {
		return "healthy"
	}
	return "disabled"
}

func boolDetail(v bool, on, off string) string {
	if v {
		return on
	}
	return off
}
