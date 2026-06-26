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
	active bool
}

var v2NavItems = []v2NavItem{
	{href: "/v2/", label: "Dashboard", icon: "◈"},
	{href: "/v2/investigate", label: "Investigate", icon: "⊕"},
	{href: "/timeline", label: "Timeline", icon: "⟳"},
	{href: "/pipeline", label: "Pipeline", icon: "◐"},
	{href: "/providers", label: "Providers", icon: "⬡"},
	{href: "/notes", label: "Notes", icon: "✎"},
	{href: "/health", label: "Health", icon: "♥"},
	{href: "/", label: "Classic UI →", icon: "↗"},
}

// v2Page renders a full HTML page with the v2 dark shell (sidebar, topbar, Ctrl+K palette).
// activeHref should match one of the navItems hrefs exactly.
func v2Page(title, activeHref, mainContent string) string {
	var nav strings.Builder
	for _, item := range v2NavItems {
		isActive := item.href == activeHref
		bg := ""
		color := "#9aa0b2"
		if isActive {
			bg = "background:rgba(124,108,242,.15);"
			color = "#c5cad8"
		}
		nav.WriteString(fmt.Sprintf(
			`<a href="%s" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:7px;text-decoration:none;color:%s;font:500 13px 'Hanken Grotesk',sans-serif;%s" onmouseover="if(!this.style.background||this.style.background==='')this.style.background='rgba(124,108,242,.08)'" onmouseout="this.style.background='%s'"><span style="font-size:14px;width:18px;text-align:center">%s</span>%s</a>`,
			html.EscapeString(item.href),
			color,
			bg,
			func() string {
				if isActive {
					return "rgba(124,108,242,.15)"
				}
				return ""
			}(),
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
body{background:#0d0f14;color:#e8eaf1;font-family:'Hanken Grotesk',system-ui,sans-serif;min-height:100vh;display:flex}
a{color:inherit}
@keyframes livepulse{0%,100%{opacity:1}50%{opacity:.35}}

/* Sidebar */
.v2-sidebar{width:200px;flex-shrink:0;background:#0b0d12;border-right:1px solid #1a1e29;display:flex;flex-direction:column;padding:18px 10px;gap:2px;position:sticky;top:0;height:100vh;overflow-y:auto}
.v2-sidebar-logo{display:flex;align-items:center;gap:8px;padding:6px 12px 18px;border-bottom:1px solid #1a1e29;margin-bottom:10px}
.v2-sidebar-dot{width:8px;height:8px;border-radius:50%;background:#7c6cf2;box-shadow:0 0 8px #7c6cf2}
.v2-sidebar-text{font:700 12px 'JetBrains Mono',monospace;color:#c5cad8;letter-spacing:.04em}

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
</style>
</head>
<body>

<nav class="v2-sidebar">
  <div class="v2-sidebar-logo">
    <span class="v2-sidebar-dot"></span>
    <span class="v2-sidebar-text">OPERATOR</span>
  </div>
  ` + nav.String() + `
  <div style="flex:1"></div>
  <a href="/v2/login" style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:7px;text-decoration:none;color:#3d4355;font:500 12px 'Hanken Grotesk',sans-serif;margin-top:8px" onclick="fetch('/logout',{method:'POST'});return true"><span style="font-size:13px;width:18px;text-align:center">⏻</span>Sign out</a>
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
      <span>e.g. 203.0.113.1</span>
    </div>
  </div>
</div>

<script src="/v2/static/palette.js"></script>
</body>
</html>`
}
