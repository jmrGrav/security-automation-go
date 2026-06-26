package ui

import (
	"fmt"
	"html"
	"strings"
)

// v2NavItem defines a sidebar navigation entry for the v2 UI.
type v2NavItem struct {
	href   string
	label  string
	icon   string
	group  string
	active bool
}

var v2NavItems = []v2NavItem{
	{href: "/v2/", label: "Dashboard", icon: "◈", group: "Observe"},
	{href: "/v2/investigate", label: "Investigate", icon: "⊕", group: "Investigate"},
	{href: "/v2/timeline", label: "Timeline", icon: "⟳", group: "Investigate"},
	{href: "/v2/incident", label: "Focus Incident", icon: "◎", group: "Investigate"},
	{href: "/forensic", label: "Forensic", icon: "⌕", group: "Investigate"},
	{href: "/v2/providers", label: "Providers", icon: "⬡", group: "Infrastructure"},
	{href: "/v2/health", label: "Health", icon: "♥", group: "Infrastructure"},
	{href: "/v2/cloudflare", label: "Cloudflare", icon: "☁", group: "Infrastructure"},
	{href: "/v2/notes", label: "Notes", icon: "✎", group: "Operations"},
	{href: "/v2/audit", label: "Audit", icon: "◷", group: "Operations"},
	{href: "/trusted-networks", label: "Trusted Networks", icon: "◇", group: "Operations"},
	{href: "/", label: "Classic UI", icon: "↗", group: "Operations"},
}

// v2Page renders a full HTML page with the v2 dark shell (sidebar, topbar, Ctrl+K palette).
// activeHref should match one of the navItems hrefs exactly.
func v2Page(title, activeHref, mainContent string) string {
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
		className := "v2-nav-link"
		if isActive {
			className += " active"
		}
		nav.WriteString(fmt.Sprintf(
			`<a href="%s" class="%s"><span class="v2-nav-icon">%s</span><span>%s</span></a>`,
			html.EscapeString(item.href),
			className,
			item.icon,
			item.label,
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
body{background:#0d0f14;color:#e8eaf1;font-family:'Hanken Grotesk',system-ui,sans-serif;min-height:100vh;display:flex;color-scheme:dark}
a{color:inherit}
@keyframes livepulse{0%,100%{opacity:1}50%{opacity:.35}}

/* Sidebar */
.v2-sidebar{width:200px;flex-shrink:0;background:#0b0d12;border-right:1px solid #1a1e29;display:flex;flex-direction:column;padding:18px 10px;gap:2px;position:sticky;top:0;height:100vh;overflow-y:auto}
.v2-sidebar-logo{display:flex;align-items:center;gap:8px;padding:6px 12px 18px;border-bottom:1px solid #1a1e29;margin-bottom:10px}
.v2-sidebar-dot{width:8px;height:8px;border-radius:50%;background:#7c6cf2;box-shadow:0 0 8px #7c6cf2}
.v2-sidebar-text{font:700 12px 'JetBrains Mono',monospace;color:#c5cad8;letter-spacing:.04em}
.v2-nav-link{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:7px;text-decoration:none;color:#9aa0b2;font:500 13px 'Hanken Grotesk',sans-serif;border:1px solid transparent;transition:background .14s ease,color .14s ease,border-color .14s ease}
.v2-nav-link:hover{background:rgba(124,108,242,.08);color:#d9dceb}
.v2-nav-link.active{background:rgba(124,108,242,.15);border-color:rgba(124,108,242,.24);color:#eef0f6}
.v2-nav-icon{font-size:14px;width:18px;text-align:center;color:#7c6cf2}
.v2-nav-group{font:700 9px 'JetBrains Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:#52596d;padding:12px 12px 5px}
.v2-side-widget{border-top:1px solid #1a1e29;margin-top:12px;padding:10px 10px 0}
.v2-side-widget-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px;font:700 9px 'JetBrains Mono',monospace;letter-spacing:.12em;text-transform:uppercase;color:#666d82}
.v2-side-widget button{background:rgba(255,255,255,.04);border:1px solid #252a3a;color:#9aa0b2;border-radius:6px;padding:2px 6px;font:600 10px 'Hanken Grotesk',sans-serif;cursor:pointer}
.v2-side-widget .muted{font:500 11px 'Hanken Grotesk',sans-serif;color:#555d73}

/* Main area */
.v2-main{flex:1;overflow:auto;padding:24px}

/* Command palette */
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

/* Cards / sections */
.v2-card{background:#10121a;border:1px solid #20242f;border-radius:10px;overflow:hidden;margin-bottom:16px}
.v2-card-header{display:flex;align-items:center;gap:8px;padding:11px 14px;border-bottom:1px solid #1a1e29}
.v2-card-title{font:700 11px 'Hanken Grotesk',sans-serif;letter-spacing:.05em;color:#c5cad8;text-transform:uppercase}
.v2-card-body{padding:16px}

/* KV rows */
.v2-kv{display:flex;flex-direction:column;gap:0}
.v2-kv-row{display:flex;align-items:center;padding:9px 0;border-bottom:1px solid #1a1e29;gap:12px}
.v2-kv-row:last-child{border-bottom:none}
.v2-kv-key{font:500 12px 'JetBrains Mono',monospace;color:#6b7184;width:120px;flex-shrink:0}
.v2-kv-val{font:500 13px 'Hanken Grotesk',sans-serif;color:#c5cad8;flex:1}

/* Pills */
.v2-pill{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:5px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.07);font:500 11px 'JetBrains Mono',monospace;color:#cdd2e0;vertical-align:middle}
.v2-pill.green{background:rgba(76,199,154,.1);border-color:rgba(76,199,154,.2);color:#4cc79a}
.v2-pill.orange{background:rgba(245,146,30,.1);border-color:rgba(245,146,30,.2);color:#f5a443}
.v2-pill.red{background:rgba(239,95,107,.1);border-color:rgba(239,95,107,.22);color:#f08591}
.v2-pill.purple{background:rgba(124,108,242,.12);border-color:rgba(124,108,242,.22);color:#9b8cff}

/* Evidence table */
.v2-table-wrap{overflow-x:auto}
.v2-table{width:100%;border-collapse:collapse;font:500 12px 'JetBrains Mono',monospace}
.v2-table th{padding:8px 10px;text-align:left;font:600 10px 'Hanken Grotesk',sans-serif;letter-spacing:.06em;color:#6b7184;text-transform:uppercase;border-bottom:1px solid #1a1e29;white-space:nowrap}
.v2-table td{padding:8px 10px;border-bottom:1px solid #0f1118;color:#c5cad8;white-space:nowrap}
.v2-table tr:last-child td{border-bottom:none}
.v2-table tr:hover td{background:rgba(255,255,255,.025)}
.v2-table td a{color:#7c6cf2;text-decoration:none}
.v2-table td a:hover{text-decoration:underline}

/* Topbar */
.v2-topbar{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.v2-topbar-title{font:700 20px 'Hanken Grotesk',sans-serif;color:#eef0f6}
.v2-kbd-trigger{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px;background:#1a1e29;border:1px solid #2a2f42;font:500 11px 'JetBrains Mono',monospace;color:#7b8196;cursor:pointer;user-select:none}
.v2-live-badge{display:inline-flex;align-items:center;gap:6px;font:600 11px 'JetBrains Mono',monospace;color:#4cc79a}
.v2-live-dot{width:7px;height:7px;border-radius:50%;background:#4cc79a;animation:livepulse 1.8s infinite}

/* Empty state */
.v2-empty{padding:40px;text-align:center;color:#4a5168;font:500 13px 'Hanken Grotesk',sans-serif}
.v2-empty-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-top:14px;text-align:left}
.v2-empty-action{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 11px;border-radius:9px;border:1px solid #20242f;background:#10121a;color:#c5cad8;text-decoration:none;font:600 12px 'Hanken Grotesk',sans-serif}
.v2-empty-action:hover{border-color:rgba(124,108,242,.4);background:#141725}
@media(max-width:760px){
body{display:block}
.v2-sidebar{width:100%;height:auto;position:static;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));padding:12px;gap:6px;border-right:none;border-bottom:1px solid #1a1e29;overflow:visible}
.v2-sidebar-logo{grid-column:1/-1;padding:4px 8px 10px;margin-bottom:2px}
.v2-nav-group{grid-column:1/-1;padding:8px 8px 0}
.v2-nav-link{min-width:0;padding:8px 9px}
.v2-nav-link span:last-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.v2-side-widget{display:none}
.v2-main{padding:14px;overflow:visible}
.v2-topbar{margin-bottom:14px;flex-wrap:wrap}
.v2-palette-examples{grid-template-columns:1fr}
}
</style>
</head>
<body data-theme="operations-dark">

<nav class="v2-sidebar">
  <div class="v2-sidebar-logo">
    <span class="v2-sidebar-dot"></span>
    <span class="v2-sidebar-text">OPERATOR</span>
  </div>
  ` + nav.String() + `
  <div style="flex:1"></div>
  <div class="v2-side-widget" data-watchlist-widget="true" data-watchlist-key="security-automation:watchlist">
    <div class="v2-side-widget-head"><span>Watchlist</span><button type="button" data-watchlist-collapse-toggle="true" aria-expanded="false">Show</button></div>
    <div data-watchlist-list data-watchlist-body style="display:none"><p class="muted">No items watched.</p></div>
  </div>
  <div class="v2-side-widget" data-recents-widget="true" data-recents-key="security-automation:recents">
    <div class="v2-side-widget-head"><span>Recent</span></div>
    <div data-recents-list><p class="muted">No recent pages.</p></div>
  </div>
  <form method="POST" action="/v2/logout" style="margin:0"><button type="submit" style="display:flex;width:100%;align-items:center;gap:10px;padding:8px 12px;border-radius:7px;color:#3d4355;font:500 12px 'Hanken Grotesk',sans-serif;background:none;border:none;cursor:pointer;margin-top:8px"><span style="font-size:13px;width:18px;text-align:center">⏻</span>Sign out</button></form>
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
      <span>IP · AS13335 · Cloudflare · Timeline · Blocked</span>
    </div>
    <div class="v2-palette-examples">
      <a href="/v2/investigate"><strong>Search IP</strong><span>investigate</span></a>
      <a href="/v2/timeline"><strong>Timeline</strong><span>events</span></a>
      <a href="/v2/providers"><strong>Cloudflare</strong><span>provider</span></a>
      <a href="/v2/audit"><strong>Audit</strong><span>operator trail</span></a>
    </div>
  </div>
</div>

<script src="/v2/static/palette.js"></script>
</body>
</html>`
}
