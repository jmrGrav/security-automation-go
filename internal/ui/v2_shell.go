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
	icon  string
}

var v2NavItems = []v2NavItem{
	{href: "/v2/", label: "Dashboard", group: "Observe", icon: "◈"},
	{href: "/v2/investigate", label: "Investigate", group: "Investigate", icon: "⊕"},
	{href: "/v2/timeline", label: "Timeline", group: "Investigate", icon: "⟳"},
	{href: "/v2/providers", label: "Providers", group: "Infrastructure", icon: "⬡"},
	{href: "/v2/health", label: "Health", group: "Infrastructure", icon: "♥"},
	{href: "/v2/cloudflare", label: "Cloudflare", group: "Infrastructure", icon: "☁"},
	{href: "/v2/notes", label: "Notes", group: "Operations", icon: "✎"},
	{href: "/v2/audit", label: "Audit", group: "Operations", icon: "◷"},
	{href: "/trusted-networks", label: "Trusted Networks", group: "Operations", icon: "◇"},
}

// v2Page renders a full HTML page with the v2 dark shell (sidebar, Ctrl+K palette).
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
				`<div style="font:700 9px 'Hanken Grotesk',sans-serif;letter-spacing:.1em;color:#5a6072;text-transform:uppercase;padding:0 8px 5px;margin-top:10px">%s</div>`,
				html.EscapeString(item.group),
			))
		}
		isActive := item.href == activeHref
		linkStyle := "display:flex;align-items:center;gap:10px;padding:7px 9px;border-radius:7px;text-decoration:none;transition:background .15s;"
		dotColor := "#4a5266"
		fontWeight := "600"
		textColor := "#c5cad8"
		if isActive {
			linkStyle += "background:rgba(124,108,242,.13);border:1px solid rgba(124,108,242,.22);"
			dotColor = "#7c6cf2"
			fontWeight = "700"
			textColor = "#eef0f6"
		} else {
			linkStyle += "border:1px solid transparent;"
		}
		linkStyle += fmt.Sprintf("font:%s 12.5px 'Hanken Grotesk',sans-serif;color:%s;", fontWeight, textColor)
		nav.WriteString(fmt.Sprintf(
			`<a href="%s" style="%s"><span style="width:5px;height:5px;border-radius:50%%;flex:none;background:%s"></span><span style="font-size:13px;width:18px;text-align:center;color:#7c6cf2;flex:none">%s</span><span>%s</span></a>`,
			html.EscapeString(item.href),
			linkStyle,
			dotColor,
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

/* Sidebar */
.v2-sidebar{width:218px;flex-shrink:0;background:#0d0f16;border-right:1px solid #181b25;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#242838 transparent}
.v2-sidebar::-webkit-scrollbar{width:6px}
.v2-sidebar::-webkit-scrollbar-thumb{background:#242838;border-radius:99px}

/* Main area */
.v2-main{flex:1;min-width:0;overflow-y:auto;padding:20px 26px 28px;scrollbar-width:thin;scrollbar-color:#242838 transparent}
.v2-main::-webkit-scrollbar{width:6px}
.v2-main::-webkit-scrollbar-thumb{background:#242838;border-radius:99px}

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

/* Cards */
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
.v2-topbar{display:flex;align-items:center;gap:10px;margin-bottom:22px}
.v2-topbar-title{font:800 20px 'Hanken Grotesk',sans-serif;color:#eef0f6}
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
.v2-sidebar{width:100%;height:auto;position:static;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));padding:10px;gap:4px;border-right:none;border-bottom:1px solid #181b25;overflow:visible}
.v2-main{padding:14px;overflow:visible}
.v2-topbar{margin-bottom:14px;flex-wrap:wrap}
.v2-palette-examples{grid-template-columns:1fr}
}
</style>
</head>
<body data-theme="operations-dark">

<nav class="v2-sidebar">

  <!-- Brand -->
  <div style="display:flex;align-items:center;gap:10px;padding:17px 16px 15px;border-bottom:1px solid #14171f;flex-shrink:0">
    <span style="width:11px;height:11px;border-radius:3px;background:linear-gradient(135deg,#9b8cff,#7c6cf2);box-shadow:0 0 10px rgba(124,108,242,.6);flex:none"></span>
    <div style="line-height:1.15;min-width:0">
      <div style="font:800 14px 'JetBrains Mono',monospace;color:#eef0f6;letter-spacing:.02em">` + html.EscapeString(version) + `</div>
      <div style="font:500 9px 'JetBrains Mono',monospace;color:#5a6072;letter-spacing:.04em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">sag.arleo.eu · build ` + html.EscapeString(commit) + `</div>
    </div>
  </div>

  <!-- Search -->
  <div style="margin:12px 12px 10px;flex-shrink:0">
    <button type="button" data-palette-trigger
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 10px;border-radius:8px;background:#11131c;border:1px solid #1e2230;cursor:pointer;text-align:left">
      <span style="font:500 11px 'JetBrains Mono',monospace;color:#6b7184;flex:1">Search…</span>
      <span style="font:600 10px 'JetBrains Mono',monospace;color:#7b8196;background:#1a1e29;padding:1px 5px;border-radius:4px">⌘K</span>
    </button>
  </div>

  <!-- Nav -->
  <div style="flex:1;padding:2px 10px;display:flex;flex-direction:column;min-height:0;overflow-y:auto">
    ` + nav.String() + `
  </div>

  <!-- Sign out -->
  <div style="border-top:1px solid #14171f;padding:11px 12px;flex-shrink:0">
    <form method="POST" action="/v2/logout" style="margin:0">
      <button type="submit"
        style="display:flex;align-items:center;gap:11px;width:100%;padding:9px 10px;border-radius:9px;background:#10121a;border:1px solid #1e2230;cursor:pointer;transition:border-color .15s,background .15s"
        onmouseover="this.style.borderColor='rgba(239,95,107,.4)';this.style.background='rgba(239,95,107,.06)'"
        onmouseout="this.style.borderColor='#1e2230';this.style.background='#10121a'">
        <span style="position:relative;width:9px;height:9px;flex:none">
          <span style="position:absolute;inset:0;border-radius:50%;background:#ef5f6b;animation:halopulse 1.8s ease-out infinite"></span>
          <span style="position:absolute;inset:0;border-radius:50%;background:#ef5f6b;box-shadow:0 0 8px rgba(239,95,107,.8)"></span>
        </span>
        <span style="flex:1;font:600 12.5px 'Hanken Grotesk',sans-serif;color:#d3d7e2;text-align:left">Sign out</span>
        <span style="font:600 11px 'JetBrains Mono',monospace;color:#6b7184">⎋</span>
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
      <span>IP · timeline · cloudflare · audit</span>
    </div>
    <div class="v2-palette-examples">
      <a href="/v2/investigate"><strong>Search IP</strong><span>investigate</span></a>
      <a href="/v2/timeline"><strong>Timeline</strong><span>events</span></a>
      <a href="/v2/cloudflare"><strong>Cloudflare</strong><span>boundary</span></a>
      <a href="/v2/audit"><strong>Audit</strong><span>operator trail</span></a>
    </div>
  </div>
</div>

<script src="/v2/static/nav-progress.js"></script>
<script src="/v2/static/palette.js"></script>
</body>
</html>`
}
