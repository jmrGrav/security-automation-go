package ui

import (
	"fmt"
	"html"
	"strings"

	"github.com/jm/security-automation-go/internal/buildmeta"
)

// v2NavItem defines a sidebar navigation entry for the v2 UI.
type v2NavItem struct {
	href  string
	label string
	group string
	icon  string // inline SVG
}

var v2NavItems = []v2NavItem{
	{href: "/v2/", label: "Dashboard", group: "Observe",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3h7v7H3z"/><path d="M14 3h7v7h-7z"/><path d="M14 14h7v7h-7z"/><path d="M3 14h7v7H3z"/></svg>`},
	{href: "/v2/investigate", label: "Investigate", group: "Investigate",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>`},
	{href: "/v2/timeline", label: "Timeline", group: "Investigate",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>`},
	{href: "/v2/providers", label: "Providers", group: "Infrastructure",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 2 7l10 5 10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>`},
	{href: "/v2/health", label: "Health", group: "Infrastructure",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-5l-2 4-4-8-2 4H2"/></svg>`},
	{href: "/v2/cloudflare", label: "Cloudflare", group: "Infrastructure",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M17 18a4 4 0 0 0 0-8 6 6 0 0 0-11.7 1.5A3.5 3.5 0 0 0 6 18z"/></svg>`},
	{href: "/v2/notes", label: "Notes", group: "Operations",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3v5h5"/><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/></svg>`},
	{href: "/v2/audit", label: "Audit", group: "Operations",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6h11"/><path d="M9 12h11"/><path d="M9 18h11"/><path d="M4 6h.01"/><path d="M4 12h.01"/><path d="M4 18h.01"/></svg>`},
	{href: "/trusted-networks", label: "Trusted Networks", group: "Operations",
		icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V5z"/></svg>`},
}

// v2Page renders a full HTML page with the v2 dark shell (collapsible sidebar, Ctrl+K palette).
// activeHref should match one of the navItems hrefs exactly.
func v2Page(title, activeHref, mainContent string) string {
	build := buildmeta.Current()
	version := "v" + build.Version
	commit := build.Commit
	if len(commit) > 6 {
		commit = commit[:6]
	}

	var nav strings.Builder
	lastGroup := ""
	for _, item := range v2NavItems {
		if item.group != "" && item.group != lastGroup {
			lastGroup = item.group
			nav.WriteString(fmt.Sprintf(
				`<div class="v2-nav-group">%s</div>`,
				html.EscapeString(item.group),
			))
		}
		isActive := item.href == activeHref
		rowClass := "v2-nav-item"
		if isActive {
			rowClass += " active"
		}
		nav.WriteString(fmt.Sprintf(
			`<a href="%s" class="%s" title="%s"><span class="v2-nav-icon">%s</span><span class="v2-nav-label">%s</span></a>`,
			html.EscapeString(item.href),
			rowClass,
			html.EscapeString(item.label),
			item.icon,
			html.EscapeString(item.label),
		))
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(title) + ` · Operator Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0b10;color:#e8eaf1;font-family:'Hanken Grotesk',system-ui,sans-serif;min-height:100vh;display:flex;color-scheme:dark}
a{color:inherit}
@keyframes livepulse{0%,100%{opacity:1}50%{opacity:.35}}
@keyframes halopulse{0%{transform:scale(.7);opacity:.55}100%{transform:scale(2.4);opacity:0}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shimmer{0%{transform:translateX(-130%)}100%{transform:translateX(430%)}}
@keyframes skel{0%,100%{opacity:.5}50%{opacity:.85}}

/* ── Sidebar ── */
.v2-sidebar{width:218px;flex-shrink:0;background:#0d0f16;border-right:1px solid #181b25;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow:hidden;transition:width .2s ease;scrollbar-width:thin;scrollbar-color:#242838 transparent}
.v2-sidebar::-webkit-scrollbar{width:6px}
.v2-sidebar::-webkit-scrollbar-thumb{background:#242838;border-radius:99px}
.v2-sidebar.v2-sb-collapsed{width:66px}

/* Brand row */
.v2-sb-brand{display:flex;align-items:center;gap:10px;padding:17px 16px 15px;border-bottom:1px solid #14171f;flex-shrink:0;min-width:0}
.v2-sb-logo{width:13px;height:13px;border-radius:4px;background:linear-gradient(135deg,#9b8cff,#7c6cf2);box-shadow:0 0 11px rgba(124,108,242,.6);flex:none}
.v2-sb-meta{flex:1;min-width:0;line-height:1.15;overflow:hidden;transition:opacity .15s,width .2s}
.v2-sb-version{font:800 14px 'JetBrains Mono',monospace;color:#eef0f6;letter-spacing:.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.v2-sb-build{font:500 9px 'JetBrains Mono',monospace;color:#5a6072;letter-spacing:.04em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.v2-sb-toggle{display:grid;place-items:center;width:24px;height:24px;border-radius:7px;border:none;background:none;color:#6b7184;font:600 14px 'Hanken Grotesk',sans-serif;cursor:pointer;flex:none;transition:background .12s,color .12s}
.v2-sb-toggle:hover{background:#1a1e29;color:#c5cad8}
.v2-sidebar.v2-sb-collapsed .v2-sb-meta{opacity:0;width:0}
.v2-sidebar.v2-sb-collapsed .v2-sb-brand{justify-content:center;gap:8px;padding-inline:0}
.v2-sidebar.v2-sb-collapsed .v2-sb-toggle{margin:0}

/* Search */
.v2-sb-search{margin:12px 12px 8px;flex-shrink:0;transition:opacity .15s}
.v2-sb-search-btn{display:flex;align-items:center;gap:8px;width:100%;padding:7px 10px;border-radius:8px;background:#11131c;border:1px solid #1e2230;cursor:pointer;text-align:left}
.v2-sb-search-label{font:500 11px 'JetBrains Mono',monospace;color:#6b7184;flex:1}
.v2-sb-search-kbd{font:600 10px 'JetBrains Mono',monospace;color:#7b8196;background:#1a1e29;padding:1px 5px;border-radius:4px}
.v2-sidebar.v2-sb-collapsed .v2-sb-search{display:none}

/* Nav */
.v2-nav-scroll{flex:1;padding:6px 10px;display:flex;flex-direction:column;overflow-y:auto;min-height:0;gap:2px}
.v2-nav-group{font:700 9px 'Hanken Grotesk',sans-serif;letter-spacing:.1em;color:#5a6072;text-transform:uppercase;padding:10px 8px 4px;white-space:nowrap;overflow:hidden;transition:opacity .15s}
.v2-sidebar.v2-sb-collapsed .v2-nav-group{opacity:0;height:0;padding:0;pointer-events:none}
.v2-nav-item{display:flex;align-items:center;gap:10px;padding:8px 9px;border-radius:8px;text-decoration:none;border:1px solid transparent;transition:background .12s,border-color .12s,color .12s;font:600 12.5px 'Hanken Grotesk',sans-serif;color:#c5cad8;white-space:nowrap;overflow:hidden}
.v2-nav-item:hover{background:rgba(255,255,255,.04)}
.v2-nav-item.active{background:rgba(124,108,242,.13);border-color:rgba(124,108,242,.22);color:#eef0f6;font-weight:700}
.v2-nav-icon{flex-none;display:flex;align-items:center;justify-content:center;color:inherit;width:16px}
.v2-nav-item.active .v2-nav-icon{color:#9b8cff}
.v2-nav-label{transition:opacity .15s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.v2-sidebar.v2-sb-collapsed .v2-nav-item{justify-content:center;padding:9px 8px}
.v2-sidebar.v2-sb-collapsed .v2-nav-label{opacity:0;width:0;pointer-events:none}

/* Sign out */
.v2-sb-foot{border-top:1px solid #14171f;padding:11px 12px;flex-shrink:0}
.v2-sb-signout{display:flex;align-items:center;gap:11px;width:100%;padding:9px 10px;border-radius:9px;background:#10121a;border:1px solid #1e2230;cursor:pointer;transition:border-color .15s,background .15s}
.v2-sb-signout:hover{border-color:rgba(239,95,107,.4);background:rgba(239,95,107,.06)}
.v2-sb-signout-dot{position:relative;width:9px;height:9px;flex:none}
.v2-sb-signout-halo{position:absolute;inset:0;border-radius:50%;background:#ef5f6b;animation:halopulse 1.8s ease-out infinite}
.v2-sb-signout-core{position:absolute;inset:0;border-radius:50%;background:#ef5f6b;box-shadow:0 0 8px rgba(239,95,107,.8)}
.v2-sb-signout-text{flex:1;font:600 12.5px 'Hanken Grotesk',sans-serif;color:#d3d7e2;text-align:left;white-space:nowrap;overflow:hidden;transition:opacity .15s}
.v2-sb-signout-esc{font:600 11px 'JetBrains Mono',monospace;color:#6b7184;white-space:nowrap;transition:opacity .15s}
.v2-sb-signout-icon{display:none;align-items:center;justify-content:center;color:#ef5f6b;flex:none}
.v2-sidebar.v2-sb-collapsed .v2-sb-signout{justify-content:center}
.v2-sidebar.v2-sb-collapsed .v2-sb-signout-text,.v2-sidebar.v2-sb-collapsed .v2-sb-signout-esc{opacity:0;width:0;pointer-events:none}
.v2-sidebar.v2-sb-collapsed .v2-sb-signout-dot{display:none}
.v2-sidebar.v2-sb-collapsed .v2-sb-signout-icon{display:flex}

/* ── Main area ── */
.v2-main{flex:1;min-width:0;overflow-y:auto;padding:22px 32px 32px;scrollbar-width:thin;scrollbar-color:#242838 transparent;position:relative}
.v2-main::-webkit-scrollbar{width:6px}
.v2-main::-webkit-scrollbar-thumb{background:#242838;border-radius:99px}

/* ── Command palette ── */
.v2-palette-overlay{display:none;position:fixed;inset:0;background:rgba(5,7,12,.6);z-index:200;align-items:flex-start;justify-content:center;padding:14vh 1rem 1rem}
.v2-palette-overlay.open{display:flex}
.v2-palette-box{width:min(640px,calc(100vw - 2rem));background:#13151c;border:1px solid #2a2f42;border-radius:14px;box-shadow:0 24px 64px rgba(0,0,0,.5);overflow:hidden}
.v2-palette-input-row{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid #20242f}
.v2-palette-icon{font-size:16px;color:#6b7184;flex-shrink:0}
.v2-palette-input{flex:1;background:transparent;border:none;outline:none;font:500 16px 'JetBrains Mono',monospace;color:#eef0f6;caret-color:#7c6cf2}
.v2-palette-input::placeholder{color:#4a5168}
.v2-palette-hint{padding:10px 16px 12px;font:500 11px 'JetBrains Mono',monospace;color:#5b6070;display:flex;gap:12px;flex-wrap:wrap}
.v2-palette-hint kbd{background:#1a1e29;border:1px solid #2a2f42;border-radius:4px;padding:1px 6px;color:#9aa0b2}
.v2-palette-examples{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;padding:0 16px 14px}
.v2-palette-examples a{display:flex;align-items:center;justify-content:space-between;gap:8px;text-decoration:none;border:1px solid #20242f;background:#10121a;border-radius:8px;padding:7px 9px;font:600 11px 'JetBrains Mono',monospace;color:#aab0c2}
.v2-palette-examples span{color:#6b7184;font:500 10px 'Hanken Grotesk',sans-serif}

/* ── Design System tokens ── */
.v2-card{background:#13151c;border:1px solid #20242f;border-radius:14px;overflow:hidden;margin-bottom:20px;position:relative}
.v2-card-header{display:flex;align-items:center;gap:10px;padding:13px 18px;border-bottom:1px solid #20242f}
.v2-card-title{font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#7b8196;text-transform:uppercase}
.v2-card-body{padding:16px 18px}

.v2-kv{display:flex;flex-direction:column}
.v2-kv-row{display:flex;align-items:center;padding:9px 0;border-bottom:1px solid #181b25;gap:12px}
.v2-kv-row:last-child{border-bottom:none}
.v2-kv-key{font:500 12px 'JetBrains Mono',monospace;color:#6b7184;width:120px;flex-shrink:0}
.v2-kv-val{font:500 13px 'Hanken Grotesk',sans-serif;color:#c5cad8;flex:1}

.v2-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:6px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);font:500 11px 'JetBrains Mono',monospace;color:#cdd2e0;vertical-align:middle}
.v2-pill.green{background:rgba(76,199,154,.1);border-color:rgba(76,199,154,.2);color:#4cc79a}
.v2-pill.orange{background:rgba(245,146,30,.1);border-color:rgba(245,146,30,.2);color:#f5a443}
.v2-pill.red{background:rgba(239,95,107,.1);border-color:rgba(239,95,107,.22);color:#f08591}
.v2-pill.purple{background:rgba(124,108,242,.12);border-color:rgba(124,108,242,.22);color:#9b8cff}

.v2-table-wrap{overflow-x:auto}
.v2-table{width:100%;border-collapse:collapse;font:500 12px 'JetBrains Mono',monospace}
.v2-table th{padding:8px 10px;text-align:left;font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#6b7184;text-transform:uppercase;border-bottom:1px solid #1a1e29;white-space:nowrap}
.v2-table td{padding:8px 10px;border-bottom:1px solid #0f1118;color:#c5cad8;white-space:nowrap}
.v2-table tr:last-child td{border-bottom:none}
.v2-table tr:hover td{background:rgba(255,255,255,.025)}
.v2-table td a{color:#7c6cf2;text-decoration:none}
.v2-table td a:hover{text-decoration:underline}

/* Page topbar / header */
.v2-topbar{display:flex;align-items:center;gap:10px;margin-bottom:22px}
.v2-topbar-title{font:800 22px 'Hanken Grotesk',sans-serif;color:#eef0f6}
.v2-topbar-sub{font:500 12px 'JetBrains Mono',monospace;color:#6b7184}
.v2-kbd-trigger{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px;background:#1a1e29;border:1px solid #2a2f42;font:500 11px 'JetBrains Mono',monospace;color:#7b8196;cursor:pointer;user-select:none}
.v2-live-badge{display:inline-flex;align-items:center;gap:6px;font:600 11px 'JetBrains Mono',monospace;color:#4cc79a;background:rgba(76,199,154,.08);border:1px solid rgba(76,199,154,.18);padding:5px 10px;border-radius:7px}
.v2-live-dot{width:7px;height:7px;border-radius:50%;background:#4cc79a;animation:livepulse 1.8s infinite}

/* Empty state */
.v2-empty{padding:40px;text-align:center;color:#4a5168;font:500 13px 'Hanken Grotesk',sans-serif}
.v2-empty-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-top:14px;text-align:left}
.v2-empty-action{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 11px;border-radius:9px;border:1px solid #20242f;background:#10121a;color:#c5cad8;text-decoration:none;font:600 12px 'Hanken Grotesk',sans-serif}
.v2-empty-action:hover{border-color:rgba(124,108,242,.4);background:#141725}

/* KPI row */
.v2-kpi-row{display:flex;gap:16px;margin-bottom:20px}
.v2-kpi{flex:1;border:1px solid #20242f;border-radius:14px;background:#13151c;padding:16px 18px;min-width:0}
.v2-kpi-label{font:600 11px 'Hanken Grotesk',sans-serif;color:#9aa0b2;margin-bottom:9px}
.v2-kpi-value{font:700 32px 'Hanken Grotesk',sans-serif;color:#eef0f6;line-height:1}
.v2-kpi-sub{font:500 11px 'JetBrains Mono',monospace;color:#6b7184;margin-top:5px}

/* Status banner */
.v2-banner{display:flex;align-items:center;gap:14px;border-radius:14px;padding:16px 18px;margin-bottom:20px;border:1px solid}
.v2-banner-dot{width:12px;height:12px;border-radius:50%;flex:none}
.v2-banner-title{font:700 16px 'Hanken Grotesk',sans-serif;color:#eef0f6}
.v2-banner-sub{font:500 12px 'JetBrains Mono',monospace;color:#6b7184;margin-top:2px}

/* Panels side-by-side */
.v2-panel-row{display:flex;gap:16px;align-items:flex-start;margin-bottom:20px}
.v2-panel-row>.v2-card{margin-bottom:0}

/* Skeleton loading */
body.v2-loading .v2-card{animation:skel 1.2s ease-in-out infinite}
body.v2-loading .v2-card::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent 25%,rgba(255,255,255,.03) 50%,transparent 75%);animation:shimmer 1.5s infinite;pointer-events:none}

/* Progress bar slot (nav-progress.js writes here) */
#v2-nav-progress{position:fixed;top:0;left:0;right:0;height:2px;z-index:999;pointer-events:none}

/* Field */
.v2-field{background:#10121a;border:1px solid #20242f;border-radius:8px;padding:8px 10px;color:#c5cad8;font:500 12px 'JetBrains Mono',monospace;width:100%;outline:none}
.v2-field:focus{border-color:#7c6cf2;box-shadow:0 0 0 3px rgba(124,108,242,.16)}

@media(max-width:760px){
body{display:block}
.v2-sidebar{width:100%!important;height:auto;position:static;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));padding:10px;gap:4px;border-right:none;border-bottom:1px solid #181b25;overflow:visible}
.v2-sb-brand,.v2-sb-search,.v2-sb-foot{grid-column:1/-1}
.v2-nav-scroll{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:4px;overflow:visible;flex:none}
.v2-nav-group{grid-column:1/-1}
.v2-main{padding:14px;overflow:visible}
.v2-topbar{margin-bottom:14px;flex-wrap:wrap}
.v2-palette-examples{grid-template-columns:1fr}
.v2-kpi-row{flex-wrap:wrap}
.v2-panel-row{flex-direction:column}
}
</style>
</head>
<body data-theme="operations-dark">

<div id="v2-nav-progress"></div>

<nav class="v2-sidebar" id="v2-sidebar">

  <!-- Brand + collapse toggle -->
  <div class="v2-sb-brand">
    <span class="v2-sb-logo"></span>
    <div class="v2-sb-meta">
      <div class="v2-sb-version">` + html.EscapeString(version) + `</div>
      <div class="v2-sb-build">sag.arleo.eu · build ` + html.EscapeString(commit) + `</div>
    </div>
    <button class="v2-sb-toggle" id="v2-sb-toggle" title="Toggle sidebar">‹</button>
  </div>

  <!-- Search -->
  <div class="v2-sb-search">
    <button type="button" class="v2-sb-search-btn" data-palette-trigger>
      <span class="v2-sb-search-label">Search…</span>
      <span class="v2-sb-search-kbd">⌘K</span>
    </button>
  </div>

  <!-- Nav -->
  <div class="v2-nav-scroll">
    ` + nav.String() + `
  </div>

  <!-- Sign out -->
  <div class="v2-sb-foot">
    <form method="POST" action="/v2/logout" style="margin:0">
      <button type="submit" class="v2-sb-signout">
        <span class="v2-sb-signout-dot">
          <span class="v2-sb-signout-halo"></span>
          <span class="v2-sb-signout-core"></span>
        </span>
        <span class="v2-sb-signout-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg></span>
        <span class="v2-sb-signout-text">Sign out</span>
        <span class="v2-sb-signout-esc">⎋</span>
      </button>
    </form>
  </div>

</nav>

<main class="v2-main">
` + mainContent + `
</main>

<!-- Command palette -->
<div class="v2-palette-overlay" id="v2-palette">
  <div class="v2-palette-box">
    <form id="v2-palette-form" class="v2-palette-input-row">
      <span class="v2-palette-icon">⊕</span>
      <input class="v2-palette-input" id="v2-palette-input" type="text" placeholder="IP address or evidence ID…" autocomplete="off" autocorrect="off" spellcheck="false">
    </form>
    <div class="v2-palette-hint">
      <span><kbd>↵</kbd> Investigate</span>
      <span><kbd>Esc</kbd> Close</span>
      <span>IP · g+t timeline · g+i investigate · g+h health · g+c cloudflare</span>
    </div>
    <div class="v2-palette-examples">
      <a href="/v2/investigate"><strong>Search IP</strong><span>investigate</span></a>
      <a href="/v2/timeline"><strong>Timeline</strong><span>events</span></a>
      <a href="/v2/cloudflare"><strong>Cloudflare</strong><span>boundary</span></a>
      <a href="/v2/audit"><strong>Audit</strong><span>operator trail</span></a>
    </div>
  </div>
</div>

<script src="/v2/static/sidebar.js"></script>
<script src="/v2/static/freshness.js"></script>
<script src="/v2/static/nav-progress.js"></script>
<script src="/v2/static/palette.js"></script>
<script src="/static/ai-explain.js"></script>
</body>
</html>`
}
