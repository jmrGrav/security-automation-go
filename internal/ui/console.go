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
	"sort"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/jm/security-automation-go/internal/buildmeta"
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
			body.panel-open {
				overflow: hidden;
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
				display: flex;
				flex-direction: column;
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
			.sidebar-footer {
				margin-top: auto;
				padding-top: .9rem;
				border-top: 1px solid var(--sidebar-border);
				display: grid;
				gap: .45rem;
			}
			.density-toggle {
				width: 100%;
				justify-content: flex-start;
				min-height: 2.25rem;
				padding: .5rem .8rem;
				border-radius: 8px;
				border-color: rgba(255,255,255,.1);
				background: rgba(255,255,255,.06);
				color: var(--sidebar-text);
				box-shadow: none;
				font-size: .86rem;
			}
			.density-toggle:hover {
				background: rgba(255,255,255,.1);
				transform: none;
			}
			.density-toggle[aria-pressed="true"] {
				background: rgba(232,250,251,.14);
				color: #e8fafb;
			}
			.logout-link {
				display: flex;
				align-items: center;
				gap: .5rem;
				text-decoration: none;
				padding: .65rem .8rem;
				border-radius: 8px;
				color: rgba(220,232,255,.72);
				font-size: .88rem;
				transition: background .12s, color .12s;
			}
			.logout-link:hover {
				background: rgba(255,80,80,.15);
				color: #ffb3b3;
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
			.live-chip {
				display: inline-flex;
				align-items: center;
				gap: .35rem;
				font-size: .76rem;
				padding: .22rem .6rem;
				border-radius: 999px;
				background: #e8fafb;
				color: var(--live);
			}
				.live-chip::before {
					content: '';
					width: .55rem;
					height: .55rem;
				border-radius: 999px;
				background: currentColor;
				box-shadow: 0 0 0 0 rgba(10,107,117,.45);
				animation: livePulse 1.9s infinite;
			}
			@keyframes livePulse {
				0% { box-shadow: 0 0 0 0 rgba(10,107,117,.45); }
				70% { box-shadow: 0 0 0 10px rgba(10,107,117,0); }
					100% { box-shadow: 0 0 0 0 rgba(10,107,117,0); }
				}
				.shell-refreshing {
					opacity: .92;
					transition: opacity .16s ease;
				}
				.shell-updated {
					animation: shellFlash .3s ease;
				}
				@keyframes shellFlash {
					0% { filter: saturate(1) brightness(1); }
					45% { filter: saturate(1.05) brightness(1.03); }
					100% { filter: saturate(1) brightness(1); }
				}
				.dashboard-hero {
					position: relative;
					overflow: hidden;
					border: 1px solid rgba(107,146,214,.36);
					background:
						radial-gradient(circle at 15% 18%, rgba(122,196,255,.24), transparent 32%),
						radial-gradient(circle at 84% 14%, rgba(88,141,240,.22), transparent 26%),
						linear-gradient(140deg, #08101d 0%, #10243f 46%, #1d477d 100%);
					color: #f2f8ff;
					box-shadow: 0 22px 48px rgba(13,29,54,.18);
				}
				.dashboard-hero::after {
					content: '';
					position: absolute;
					inset: auto -8rem -8rem auto;
					width: 18rem;
					height: 18rem;
					background: radial-gradient(circle, rgba(111,189,255,.32), rgba(111,189,255,0) 68%);
					pointer-events: none;
				}
				.dashboard-hero .muted {
					color: rgba(233,241,255,.88);
				}
				.dashboard-hero h2,
				.dashboard-hero .label {
					color: #f7fbff;
				}
				.dashboard-hero .badge {
					border-color: rgba(255,255,255,.12);
					box-shadow: 0 1px 1px rgba(0,0,0,.06);
				}
				.dashboard-hero .badge.live {
					background: rgba(8,165,176,.16);
					color: #dffcff;
				}
				.dashboard-hero .badge.healthy {
					background: rgba(34,197,94,.16);
					color: #ddf9e6;
				}
				.dashboard-hero .badge.warning {
					background: rgba(245,158,11,.18);
					color: #fff0c9;
				}
				.dashboard-hero .badge.error {
					background: rgba(239,68,68,.16);
					color: #ffe1e1;
				}
				.dashboard-hero .badge.disabled {
					background: rgba(148,163,184,.18);
					color: #edf2f7;
				}
				.kpi-grid {
					display: grid;
					grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
					gap: .75rem;
					margin-top: 1rem;
				}
				.kpi {
					display: grid;
					gap: .3rem;
					padding: .9rem 1rem;
					border-radius: 14px;
					background: rgba(255,255,255,.08);
					border: 1px solid rgba(255,255,255,.12);
					backdrop-filter: blur(4px);
					transition: transform .16s ease, background .16s ease;
				}
				.kpi:hover { transform: translateY(-1px); background: rgba(255,255,255,.11); }
				.kpi .label {
					font-size: .72rem;
					text-transform: uppercase;
					letter-spacing: .08em;
					color: rgba(220,232,255,.72);
				}
				.kpi strong {
					font-size: 1.8rem;
					line-height: 1;
				}
				.kpi .sub {
					font-size: .82rem;
					color: rgba(220,232,255,.82);
				}
				.kpi-pop {
					animation: kpiPop .3s ease;
				}
				@keyframes kpiPop {
					0% { transform: scale(.98); opacity: .88; }
					100% { transform: scale(1); opacity: 1; }
				}
				.dashboard-hub {
					display: grid;
					grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));
					gap: .75rem;
				}
				.dashboard-hub .hub-card {
					display: grid;
					gap: .35rem;
					padding: .95rem 1rem;
					border-radius: 14px;
					background: linear-gradient(180deg, #ffffff, #f7f9fd);
					border: 1px solid rgba(196,208,226,.95);
					box-shadow: 0 1px 2px rgba(16,36,62,.05);
					text-decoration: none;
					color: inherit;
					transition: transform .15s ease, box-shadow .15s ease, border-color .15s ease;
				}
				.dashboard-hub .hub-card:hover {
					transform: translateY(-1px);
					box-shadow: 0 10px 24px rgba(16,36,62,.08);
					border-color: #c8d5ea;
				}
				.dashboard-hub .hub-card strong {
					font-size: 1.03rem;
				}
        				.dashboard-hub .hub-card span {
        					color: var(--muted);
        					font-size: .86rem;
        				}
				.command-center { border-color: #b7d6ff; background: linear-gradient(135deg, #f8fbff 0%, #eef6ff 100%); }
				.command-reasons { display:flex; gap:.45rem; flex-wrap:wrap; margin:.65rem 0; }
				.command-search { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:.55rem; margin: .8rem 0; align-items:end; }
				.command-search label { grid-column: 1 / -1; font-size: .82rem; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
				.command-search input { min-width:0; }
				.timebar { display:flex; gap:.4rem; flex-wrap:wrap; margin:.65rem 0; align-items:center; }
				.timebar a[aria-current="true"] { border-color:#2b6cb0; background:#e1efff; }
				.activity-feed { margin:0; padding-left:1.2rem; display:grid; gap:.4rem; }
				.activity-feed a { font-weight:700; }
				.activity-feed small { display:block; color:var(--muted); margin-top:.15rem; }
				.freshness-rail { display:flex; gap:.45rem; flex-wrap:wrap; margin:.7rem 0; }
				.command-kpis { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:.65rem; margin:.8rem 0; }
				.threat-viz { margin:.85rem 0; }
				.attack-map-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(18rem,1fr)); gap:.85rem; align-items:start; }
				.attack-map-svg { width:100%; min-height:170px; border:1px solid #d8e2f0; border-radius:16px; background:linear-gradient(135deg,#f8fbff,#edf5ff); }
				.attack-country-list, .campaign-list { list-style:none; padding:0; margin:.75rem 0 0; display:grid; gap:.45rem; }
				.attack-country-list li, .campaign-list li { display:flex; justify-content:space-between; gap:.75rem; align-items:center; border:1px solid var(--border); border-radius:12px; padding:.55rem .65rem; background:#fff; }
				.campaign-list li { align-items:flex-start; }
				.campaign-list small { display:block; color:var(--muted); margin-top:.15rem; }
				.mini-card { display:grid; gap:.25rem; padding:.75rem; border:1px solid var(--border); border-radius:12px; background:#fff; text-decoration:none; }
				.mini-card strong { font-size:1.2rem; }
				.mini-card small { color:var(--muted); }
				.command-palette { position:fixed; inset:0; display:none; align-items:flex-start; justify-content:center; padding:12vh 1rem 1rem; background:rgba(9,17,29,.45); z-index:80; }
				.command-palette.open { display:flex; }
				.command-palette form { width:min(680px, calc(100vw - 2rem)); background:#fff; border:1px solid #c8d8ef; border-radius:16px; padding:1rem; box-shadow:0 24px 80px rgba(10,25,50,.24); }
				.command-palette label { display:block; margin-bottom:.5rem; font-weight:700; }
				.command-palette input { width:100%; font-size:1.05rem; padding:.8rem .9rem; border:1px solid #b9c9df; border-radius:10px; }
            			.grid {
        				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(17.5rem, 1fr));
				gap: 1rem;
				align-items: start;
			}
			.section-heading {
				margin: 0 0 .25rem;
				font-size: .82rem;
				text-transform: uppercase;
				letter-spacing: .06em;
				color: var(--muted);
			}
			.panel {
				background: var(--panel);
				border: 1px solid var(--border);
				border-radius: 10px;
				padding: 1rem;
				box-shadow: 0 1px 2px rgba(16,36,62,.05);
				transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
			}
			.panel:hover { box-shadow: 0 8px 24px rgba(16,36,62,.08); }
			.panel h2, .panel h3 {
				margin: 0 0 .65rem;
				line-height: 1.15;
			}
			.collapsible-panel {
				display: grid;
				gap: .75rem;
			}
			.collapsible-head {
				display: flex;
				align-items: flex-start;
				justify-content: space-between;
				gap: .85rem;
			}
			.collapsible-head h2,
			.collapsible-head h3 {
				margin-bottom: .15rem;
			}
			.collapsible-panel[data-collapsed="true"] .collapsible-body {
				display: none;
			}
			.collapsible-panel[data-collapsed="true"] {
				padding-bottom: .75rem;
			}
			button, input, select, textarea {
				font: inherit;
			}
			button {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				gap: .35rem;
				padding: .78rem 1rem;
				min-height: 2.75rem;
				border: 1px solid #c9d4e4;
				border-radius: 10px;
				background: linear-gradient(180deg, #ffffff, #eef3f9);
				color: var(--text);
				box-shadow: 0 1px 1px rgba(16,36,62,.04);
				cursor: pointer;
				transition: transform .14s ease, box-shadow .14s ease, background .14s ease, opacity .14s ease;
			}
			button:hover {
				background: linear-gradient(180deg, #ffffff, #e7edf7);
				transform: translateY(-1px);
			}
			button:disabled {
				opacity: .65;
				cursor: progress;
				transform: none;
			}
			button:focus-visible,
			input:focus-visible,
			select:focus-visible,
			textarea:focus-visible {
				outline: 2px solid rgba(15,29,51,.28);
				outline-offset: 2px;
			}
			button.action-button {
				width: 100%;
			}
			button.action-button.primary {
				background: linear-gradient(180deg, #27436f, #1d3358);
				border-color: transparent;
				color: #fff;
			}
			button.action-button.primary:hover {
				background: linear-gradient(180deg, #2c4a79, #213a64);
			}
			button.action-button.secondary {
				background: linear-gradient(180deg, #f7f9fc, #eef3f9);
			}
			button.badge {
				min-height: auto;
				padding: .22rem .55rem;
				border-radius: 999px;
				box-shadow: none;
			}
			button.copy-button {
				padding: .3rem .55rem;
				min-height: auto;
				font-size: .78rem;
			}
			input[type="text"],
			input[type="password"],
			input[type="search"],
			input[type="url"] {
				width: 100%;
				padding: .72rem .85rem;
				border: 1px solid var(--border);
				border-radius: 10px;
				background: #fff;
				color: var(--text);
			}
			.table-wrap {
				overflow: auto;
				border: 1px solid var(--border);
				border-radius: 10px;
				background: var(--panel);
				box-shadow: 0 1px 2px rgba(16,36,62,.05);
				scrollbar-gutter: stable both-edges;
			}
			.table-wrap table {
				border: 0;
				border-radius: 0;
				box-shadow: none;
				min-width: 100%;
				table-layout: fixed;
			}
			.table-wrap thead th {
				position: sticky;
				top: 0;
				z-index: 1;
				white-space: nowrap;
			}
			.table-wrap tbody td {
				vertical-align: middle;
				padding-top: .55rem;
				padding-bottom: .55rem;
				line-height: 1.25;
				max-width: 0;
				overflow: hidden;
				text-overflow: ellipsis;
				white-space: nowrap;
			}
			.table-wrap table tbody tr {
				transition: background-color .15s ease, transform .15s ease;
			}
			.table-wrap table tbody tr:hover {
				background: #f8fbff;
			}
			.table-wrap td .cell-clip {
				display: inline-block;
				max-width: 100%;
				overflow: hidden;
				text-overflow: ellipsis;
				vertical-align: top;
				white-space: nowrap;
			}
			.table-wrap td .inline-copy-group {
				display: inline-flex;
				align-items: center;
				gap: .35rem;
				max-width: 100%;
			}
			.inline-copy {
				cursor: copy;
			}
			.inline-copy:hover {
				text-decoration: underline;
			}
			.inline-copy-button {
				flex: 0 0 auto;
			}
				.json-toolbar {
					display: flex;
					flex-wrap: wrap;
					gap: .5rem;
					align-items: center;
					margin-bottom: .55rem;
				}
				.provider-card {
					display: grid;
					gap: .85rem;
				will-change: transform;
			}
			.provider-card:hover {
				transform: translateY(-1px);
			}
			.provider-head {
				display: flex;
				align-items: flex-start;
				justify-content: space-between;
				gap: .9rem;
				flex-wrap: wrap;
			}
			.provider-head h2 {
				margin-bottom: .25rem;
			}
			.provider-head .muted {
				margin: 0;
			}
			.provider-summary {
				display: grid;
				gap: .25rem;
			}
			.provider-meta .row {
				grid-template-columns: minmax(7rem, 8.25rem) minmax(0, 1fr);
				padding: .38rem 0;
			}
			.provider-actions {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
				gap: .65rem;
				align-items: start;
			}
			.provider-key-form {
				display: grid;
				gap: .45rem;
				align-content: start;
			}
			.provider-key-form label {
				font-size: .76rem;
				font-weight: 700;
				letter-spacing: .05em;
				text-transform: uppercase;
				color: var(--muted);
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
			body[data-density="compact"] .main {
				padding: .72rem;
			}
			body[data-density="compact"] .page {
				gap: .62rem;
				max-width: 1500px;
			}
			body[data-density="compact"] .pagehead {
				gap: .6rem;
			}
			body[data-density="compact"] .pagehead p {
				margin-top: .2rem;
			}
			body[data-density="compact"] .panel {
				padding: .66rem .72rem;
				border-radius: 8px;
			}
			body[data-density="compact"] .stack,
			body[data-density="compact"] .grid {
				gap: .48rem;
			}
			body[data-density="compact"] .row {
				padding: .32rem 0;
				gap: .6rem;
			}
			body[data-density="compact"] button {
				min-height: 2.08rem;
				padding: .42rem .62rem;
				border-radius: 8px;
			}
			body[data-density="compact"] input[type="text"],
			body[data-density="compact"] input[type="password"],
			body[data-density="compact"] input[type="search"],
			body[data-density="compact"] input[type="url"],
			body[data-density="compact"] input[type="number"],
			body[data-density="compact"] select {
				padding: .46rem .62rem;
				border-radius: 8px;
			}
			body[data-density="compact"] thead th {
				padding: .42rem .52rem;
				font-size: .72rem;
			}
			body[data-density="compact"] tbody td,
			body[data-density="compact"] .table-wrap tbody td {
				padding: .34rem .52rem;
				line-height: 1.12;
			}
			body[data-density="compact"] .badge {
				padding: .16rem .42rem;
				font-size: .72rem;
			}
			body[data-density="compact"] .empty {
				padding: .64rem;
				border-radius: 8px;
			}
			body[data-density="compact"] .table-wrap td [data-ai-explain-result].empty {
				height: 0;
				margin: 0;
				padding: 0;
				border: 0;
				overflow: hidden;
				font-size: 0;
				line-height: 0;
				background: transparent;
			}
			.live-panel-root {
				position: fixed;
				inset: 0;
				pointer-events: none;
				z-index: 60;
			}
			.live-panel-root.open {
				pointer-events: auto;
			}
			.live-panel-backdrop {
				position: absolute;
				inset: 0;
				background: rgba(7,16,30,.28);
				opacity: 0;
				transition: opacity .18s ease;
			}
			.live-panel-root.open .live-panel-backdrop {
				opacity: 1;
			}
			.live-panel {
				position: absolute;
				top: .75rem;
				right: .75rem;
				bottom: .75rem;
				width: min(44rem, calc(100vw - 1.5rem));
				background: #fff;
				border: 1px solid rgba(255,255,255,.18);
				border-radius: 18px;
				box-shadow: 0 20px 54px rgba(16,36,62,.22);
				transform: translateX(106%);
				transition: transform .2s ease;
				display: flex;
				flex-direction: column;
				overflow: hidden;
			}
			.live-panel-root.open .live-panel {
				transform: translateX(0);
			}
			.live-panel-head {
				display: flex;
				align-items: center;
				justify-content: space-between;
				gap: 1rem;
				padding: 1rem 1rem .85rem;
				border-bottom: 1px solid var(--border);
				background: linear-gradient(180deg, #fff, #f7f9fd);
			}
			.live-panel-head strong { font-size: 1rem; }
			.live-panel-head .muted { margin: .2rem 0 0; }
			.live-panel-body {
				padding: 1rem;
				overflow: auto;
				flex: 1;
				scrollbar-gutter: stable;
			}
			.live-panel-body .panel { margin-bottom: 0; box-shadow: none; }
			.live-panel-body .panel + .panel { margin-top: 1rem; }
			.live-panel-skeleton {
				display: grid;
				gap: .7rem;
			}
			.skeleton-line {
				height: .95rem;
				border-radius: 999px;
				background: linear-gradient(90deg, #edf2f8 0%, #f7f9fc 50%, #edf2f8 100%);
				background-size: 220% 100%;
				animation: shimmer 1.6s infinite linear;
			}
			.skeleton-line.wide { width: 84%; height: 1.1rem; }
			.skeleton-line.narrow { width: 46%; }
			@keyframes shimmer {
				0% { background-position: 0% 0; }
				100% { background-position: 220% 0; }
			}
			.live-toast-region {
				position: fixed;
				right: 1rem;
				bottom: 1rem;
				display: grid;
				gap: .55rem;
				z-index: 70;
			}
			.toast {
				padding: .7rem .9rem;
				border-radius: 12px;
				color: #fff;
				background: #1f335c;
				box-shadow: 0 12px 28px rgba(16,36,62,.18);
				transition: opacity .2s ease, transform .2s ease;
				transform: translateY(0);
				max-width: min(24rem, calc(100vw - 2rem));
			}
			.toast.success { background: #0f8b4c; }
			.toast.warning { background: #8f5c00; }
			.toast.error { background: #9b1c1c; }
			.toast.dismissed {
				opacity: 0;
				transform: translateY(4px);
			}
			[data-live-panel-link="true"] { cursor: pointer; }
			.json-block {
				max-height: 40vh;
				overflow: auto;
				tab-size: 2;
			}
			.dashboard-mini {
				padding: .82rem .92rem;
				min-height: 8.75rem;
				display: flex;
				flex-direction: column;
				justify-content: space-between;
				align-self: start;
			}
			.dashboard-mini h2 {
				font-size: 1.05rem;
				margin-bottom: .45rem;
			}
			.dashboard-mini .badge {
				align-self: flex-start;
			}
			.about-grid .panel {
				min-height: 8rem;
			}
			@media (max-width: 900px) {
				.shell { grid-template-columns: 1fr; }
				.sidebar {
					position: static;
					height: auto;
					border-right: 0;
					border-bottom: 1px solid var(--sidebar-border);
				}
			}
		</style><script src="/static/ai-explain.js" defer></script><script src="/static/operator-live.js" defer></script></head><body><div class="shell">`); err != nil {
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
		if _, err := fmt.Fprint(w, `</nav><div class="sidebar-footer"><button type="button" class="density-toggle" data-density-toggle="true" aria-pressed="false">Compact mode</button><a href="/logout" class="logout-link">⏻ Sign out</a></div></aside><main class="main"><div class="`); err != nil {
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
		if _, err := fmt.Fprint(w, `</div></main><div class="live-panel-root" data-live-panel-root aria-hidden="true"><div class="live-panel-backdrop" data-live-panel-backdrop="true"></div><aside class="live-panel" role="dialog" aria-modal="true" aria-label="Live detail panel"><div class="live-panel-head"><div><strong data-live-panel-title>Select an item</strong><p class="muted">Open evidence, forensic, or event details without leaving the current page.</p></div><button type="button" class="action-button secondary copy-button" data-live-panel-close="true">Close</button></div><div class="live-panel-body" data-live-panel-body><div class="live-panel-skeleton"><div class="skeleton-line wide"></div><div class="skeleton-line"></div><div class="skeleton-line"></div><div class="skeleton-line narrow"></div><p class="muted" style="margin-top:.85rem">Select an item to inspect live details.</p></div></div></aside></div><div class="command-palette" data-command-palette-root="true" aria-hidden="true"><form method="get" action="/search" data-command-palette-form="true"><label for="command-palette-input">Universal Search</label><input id="command-palette-input" name="q" type="search" placeholder="IP, evidence id, provider, scenario" autocomplete="off"/><p class="muted">Press Escape to close. Search routes to read-only investigation pages.</p></form></div><div data-live-toast-region="true" class="live-toast-region"></div></div></body></html>`); err != nil {
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
		{Label: "WAF Events", Href: "/evidence"},
		{Label: "Pipeline Health", Href: "/pipeline"},
		{Label: "CF Ban Sync", Href: "/sync"},
		{Label: "Ban Lifecycle", Href: "/ban-lifecycle"},
		{Label: "Security Intelligence", Href: "/intelligence"},
		{Label: "Timeline", Href: "/timeline"},
		{Label: "Audit Trail", Href: "/audit"},
		{Label: "Trusted Networks", Href: "/trusted-networks"},
		{Label: "Cloudflare Diff", Href: "/cloudflare/diff"},
		{Label: "About/System", Href: "/about"},
	}
	for i := range items {
		items[i].Active = items[i].Href == active
	}
	return items
}

func renderCommandCenter(w io.Writer, view DashboardConsoleView) error {
	cc := view.CommandCenter
	if _, err := fmt.Fprintf(w, `<section class="panel command-center" aria-label="Security Command Center"><div class="pagehead"><div><p class="section-heading">Security Command Center</p><h2>Health Score <span class="badge %s">%d%%</span></h2><p class="muted">%s</p></div><button type="button" class="badge live" data-command-palette-trigger="true">Ctrl+K</button></div>`,
		html.EscapeString(statusClass(cc.Health.Level)),
		cc.Health.Score,
		html.EscapeString(cc.Health.Summary),
	); err != nil {
		return err
	}
	if err := renderCommandCenterReasons(w, cc.Health.Reasons); err != nil {
		return err
	}
	if err := renderGlobalTimeBar(w, cc.TimeWindow); err != nil {
		return err
	}
	if err := renderUniversalSearch(w, cc.Search); err != nil {
		return err
	}
	if err := renderCommandCenterKPIs(w, cc.KPIs); err != nil {
		return err
	}
	if err := renderThreatVisualization(w, cc.Threat); err != nil {
		return err
	}
	if err := renderFreshnessRail(w, cc.Freshness); err != nil {
		return err
	}
	if err := renderActivityFeed(w, cc.Activity); err != nil {
		return err
	}
	_, err := fmt.Fprint(w, `</section>`)
	return err
}

func renderCommandCenterReasons(w io.Writer, reasons []string) error {
	if _, err := fmt.Fprint(w, `<div class="command-reasons">`); err != nil {
		return err
	}
	for _, reason := range reasons {
		if _, err := fmt.Fprintf(w, `<span class="badge warning">%s</span>`, html.EscapeString(reason)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func renderGlobalTimeBar(w io.Writer, window DashboardTimeWindowView) error {
	if _, err := fmt.Fprint(w, `<nav class="timebar" aria-label="Global time bar"><span class="muted">Global time bar</span>`); err != nil {
		return err
	}
	for _, opt := range window.Options {
		current := "false"
		if opt.Active {
			current = "true"
		}
		if _, err := fmt.Fprintf(w, `<a class="badge" href="%s" aria-current="%s">%s</a>`, html.EscapeString(opt.Href), current, html.EscapeString(opt.Label)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</nav>`)
	return err
}

func renderUniversalSearch(w io.Writer, search DashboardSearchView) error {
	action := search.Action
	if action == "" {
		action = "/search"
	}
	placeholder := search.Placeholder
	if placeholder == "" {
		placeholder = "IP, evidence id, provider, scenario"
	}
	_, err := fmt.Fprintf(w, `<form method="get" action="%s" class="command-search" data-command-search="true"><label for="dashboard-command-search">Universal Search</label><input id="dashboard-command-search" name="q" type="search" value="%s" placeholder="%s" autocomplete="off"/><button type="submit">Search</button></form>`,
		html.EscapeString(action),
		html.EscapeString(search.Query),
		html.EscapeString(placeholder),
	)
	return err
}

func renderCommandCenterKPIs(w io.Writer, kpis []DashboardKPIView) error {
	if _, err := fmt.Fprint(w, `<div class="command-kpis">`); err != nil {
		return err
	}
	for _, kpi := range kpis {
		if _, err := fmt.Fprintf(w, `<a class="mini-card" href="%s"><span class="badge %s">%s</span><strong>%s</strong><small>%s</small></a>`,
			html.EscapeString(kpi.Href),
			html.EscapeString(statusClass(kpi.Level)),
			html.EscapeString(kpi.Label),
			html.EscapeString(kpi.Value),
			html.EscapeString(kpi.Detail),
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func renderThreatVisualization(w io.Writer, view DashboardThreatView) error {
	if _, err := fmt.Fprint(w, `<section class="panel threat-viz" aria-label="Threat Visualization"><div class="pagehead"><div><p class="section-heading">Threat Visualization</p><h2>Attack Map <span class="badge live">Read-only</span></h2><p class="muted">Server-aggregated evidence by country. Unknown geo data stays explicit.</p></div>`); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, `<div class="badge %s">%d events</div></div>`, html.EscapeString(statusClass(threatVisualizationLevel(view))), view.TotalEvents); err != nil {
		return err
	}
	if !view.Wired || view.TotalEvents == 0 {
		if _, err := fmt.Fprintf(w, `<p class="muted">%s</p></section>`, html.EscapeString(view.EmptyText)); err != nil {
			return err
		}
		return nil
	}
	if _, err := fmt.Fprint(w, `<div class="attack-map-grid"><div>`); err != nil {
		return err
	}
	if err := renderAttackMapSVG(w, view.Countries); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<ol class="attack-country-list">`); err != nil {
		return err
	}
	for _, country := range view.Countries {
		if _, err := fmt.Fprintf(w, `<li><span>%s</span><span class="badge %s">%d</span></li>`,
			html.EscapeString(country.Country),
			html.EscapeString(statusClass(country.Level)),
			country.Count,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, `</ol></div><div><h3>Top Campaigns</h3>`); err != nil {
		return err
	}
	if len(view.Campaigns) == 0 {
		if _, err := fmt.Fprint(w, `<p class="muted">No campaign groups available for this window.</p>`); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprint(w, `<ol class="campaign-list">`); err != nil {
			return err
		}
		for _, campaign := range view.Campaigns {
			if _, err := fmt.Fprintf(w, `<li><span><strong>%s</strong><small>%s · %s</small></span><span class="badge %s">%d</span></li>`,
				html.EscapeString(campaign.Scenario),
				html.EscapeString(campaign.Source),
				html.EscapeString(campaign.Country),
				html.EscapeString(statusClass(campaign.Level)),
				campaign.Count,
			); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(w, `</ol>`); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div></div></section>`)
	return err
}

func renderAttackMapSVG(w io.Writer, countries []DashboardThreatCountryView) error {
	maxCount := 1
	for _, country := range countries {
		if country.Count > maxCount {
			maxCount = country.Count
		}
	}
	if _, err := fmt.Fprint(w, `<svg class="attack-map-svg" viewBox="0 0 640 220" role="img" aria-label="Attack Map country distribution">`); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, `<rect x="0" y="0" width="640" height="220" fill="transparent"></rect>`); err != nil {
		return err
	}
	for i, country := range countries {
		if i >= 6 {
			break
		}
		y := 24 + i*30
		width := 60 + (country.Count * 430 / maxCount)
		if _, err := fmt.Fprintf(w, `<text x="24" y="%d" font-size="13" fill="#334155">%s</text><rect x="170" y="%d" width="%d" height="16" rx="8" fill="%s"></rect><text x="%d" y="%d" font-size="12" fill="#334155">%d</text>`,
			y,
			html.EscapeString(country.Country),
			y-13,
			width,
			html.EscapeString(threatSVGColor(country.Level)),
			180+width,
			y,
			country.Count,
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</svg>`)
	return err
}

func threatVisualizationLevel(view DashboardThreatView) string {
	if !view.Wired {
		return "unavailable"
	}
	if view.TotalEvents == 0 {
		return "warning"
	}
	for _, country := range view.Countries {
		if country.Level == "error" {
			return "error"
		}
	}
	return "live"
}

func threatSVGColor(level string) string {
	switch statusClass(level) {
	case "error":
		return "#dc2626"
	case "warning":
		return "#d97706"
	case "live":
		return "#2563eb"
	default:
		return "#16a34a"
	}
}

func renderFreshnessRail(w io.Writer, freshness []DashboardFreshnessView) error {
	if _, err := fmt.Fprint(w, `<div class="freshness-rail" aria-label="Widget freshness">`); err != nil {
		return err
	}
	for _, item := range freshness {
		if _, err := fmt.Fprintf(w, `<span class="badge %s">%s: %s</span>`,
			html.EscapeString(statusClass(item.Level)),
			html.EscapeString(item.Label),
			html.EscapeString(item.Detail),
		); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</div>`)
	return err
}

func renderActivityFeed(w io.Writer, feed DashboardActivityFeedView) error {
	if _, err := fmt.Fprint(w, `<section class="panel" aria-label="Live Activity Feed"><div class="section-heading">Live Activity Feed</div>`); err != nil {
		return err
	}
	if len(feed.Items) == 0 {
		if _, err := fmt.Fprintf(w, `<p class="muted">%s</p>`, html.EscapeString(feed.EmptyText)); err != nil {
			return err
		}
		_, err := fmt.Fprint(w, `</section>`)
		return err
	}
	if _, err := fmt.Fprint(w, `<ol class="activity-feed">`); err != nil {
		return err
	}
	for _, item := range feed.Items {
		if _, err := fmt.Fprintf(w, `<li><a href="%s">%s</a> <span class="badge %s">%s</span><small>%s</small></li>`,
			html.EscapeString(item.Href),
			html.EscapeString(item.Title),
			html.EscapeString(statusClass(item.Severity)),
			html.EscapeString(item.Severity),
			html.EscapeString(item.Detail),
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, `</ol>`); err != nil {
		return err
	}
	if feed.MoreHref != "" {
		if _, err := fmt.Fprintf(w, `<p><a href="%s">Open full timeline</a></p>`, html.EscapeString(feed.MoreHref)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, `</section>`)
	return err
}

func DashboardConsolePage(view DashboardConsoleView) templ.Component {
	return ConsoleLayout(shellView{
		Title:    "Operator Dashboard",
		Headline: "Security Command Center",
		Subtitle: "Runtime posture, feature switches, and the main safety rails for the local operator console.",
		Active:   "/",
		Body: templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
			if _, err := fmt.Fprint(w, `<div class="stack" data-live-shell="dashboard" data-live-refresh-url="/" data-live-refresh-interval="8000">`); err != nil {
				return err
			}
			if err := renderCommandCenter(w, view); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, `<div class="panel dashboard-hero"><div class="pagehead" style="align-items:flex-start"><div><p class="section-heading" style="color:rgba(220,232,255,.9)">Live overview</p><h2 style="margin:0">%s <span class="live-chip">Live</span></h2><p class="muted">%s · Updated <span data-live-relative-time="%s">just now</span>.</p></div><div class="badges"><span class="badge live">Runtime live</span><span class="badge healthy">%d healthy</span><span class="badge warning">%d warning</span><span class="badge error">%d error</span><span class="badge disabled">%d disabled</span></div></div><div class="kpi-grid"><div class="kpi"><span class="label">Components healthy</span><strong data-live-kpi>%d/%d</strong><span class="sub">Environment &amp; health</span></div><div class="kpi"><span class="label">AI providers</span><strong data-live-kpi>%d</strong><span class="sub">managed locally</span></div><div class="kpi"><span class="label">AbuseIPDB reports</span><strong data-live-kpi>%d</strong><span class="sub">all-time, evidence-backed</span></div><div class="kpi"><span class="label">Status cards</span><strong data-live-kpi>%d</strong><span class="sub">refresh in place</span></div></div></div><section class="grid">`,
				html.EscapeString("Security Command Center"),
				html.EscapeString("Runtime posture, feature switches, and the main safety rails for the local operator console"),
				html.EscapeString(view.UpdatedAt),
				view.HealthyCount, view.WarningCount, view.ErrorCount, view.DisabledCount,
				view.Environment.Healthy, view.Environment.Total,
				len(view.AIProviders),
				view.ReportedTotal,
				len(view.Statuses),
			); err != nil {
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="dashboard-hub">`+
				`<a class="hub-card" href="/providers"><strong>Providers</strong><span>Toggle, test, and rotate keys live.</span></a>`+
				`<a class="hub-card" href="/health"><strong>Health</strong><span>Runtime posture, checks, and runbooks.</span></a>`+
				`<a class="hub-card" href="/timeline"><strong>Timeline</strong><span>Compact forensic activity stream.</span></a>`+
				`<a class="hub-card" href="/evidence"><strong>WAF Events</strong><span>Reported and suppressed evidence.</span></a>`+
				`<a class="hub-card" href="/forensic"><strong>Forensic Lookup</strong><span>Open an IP and inspect all local signals.</span></a>`+
				`<a class="hub-card" href="/intelligence"><strong>Security Intelligence</strong><span>Read-only DNS, ASN, and signal review.</span></a>`+
				`<a class="hub-card" href="/cloudflare/diff"><strong>Cloudflare Diff</strong><span>Desired vs observed boundary state.</span></a>`+
				`<a class="hub-card" href="/about"><strong>About / System</strong><span>Build metadata and runtime posture.</span></a>`+
				`</div>`); err != nil {
				return err
			}
			for _, status := range view.Statuses {
				if _, err := fmt.Fprint(w, `<div class="panel dashboard-mini"><h2>`); err != nil {
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
				if _, err := fmt.Fprint(w, `<div class="panel dashboard-mini" style="grid-column:1/-1"><h2>AI Providers <span class="live-chip">Live</span></h2><p class="muted">OpenAI, Anthropic, and Gemini are managed locally through the encrypted SQLite credential store and redacted operator state.</p><div class="grid">`); err != nil {
					return err
				}
				for _, provider := range view.AIProviders {
					if _, err := fmt.Fprint(w, `<div class="panel dashboard-mini">`); err != nil {
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
				`<div class="panel dashboard-mini"><h2>Environment &amp; Health <span class="live-chip">Live</span></h2>`+
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
			// AbuseIPDB reported total — sourced from evidence store (persists across restarts)
			if view.EvidenceWired {
				if _, err := fmt.Fprintf(w,
					`<div class="panel dashboard-mini"><h2>AbuseIPDB Reported</h2>`+
						`<div class="badge error" style="font-size:1.4rem;padding:.4rem .9rem">%d</div>`+
						`<p class="muted">Total IPs reported to AbuseIPDB (all-time, from evidence store)</p>`+
						`<a href="/evidence?filter=reported">View reported events &#x2192;</a>`+
						`</div>`,
					view.ReportedTotal,
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</section></div>`)
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
			if _, err := fmt.Fprint(w, `<div class="table-wrap"><table><thead><tr><th>Provider</th><th>Status</th><th>Quota</th><th>Latency</th><th>Errors</th><th>Mask</th></tr></thead><tbody>`); err != nil {
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
			_, err := fmt.Fprint(w, `</tbody></table></div>`)
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
			if _, err := fmt.Fprintf(w, `<div class="stack" data-live-shell="audit" data-live-refresh-url="%s" data-live-refresh-interval="10000"><div class="panel"><p class="muted">Append-only UI and operator events are shown below. Secrets, tokens, cookies, and authorization values are redacted before persistence and rendering.</p></div>`, html.EscapeString(view.RefreshURL)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, `<div class="panel"><form method="get" action="/audit" class="stack" data-live-search-form="true"><div class="row" style="grid-template-columns: minmax(8rem, 9rem) minmax(0, 1fr)"><span>Search</span><span><input name="q" type="search" value="%s" placeholder="action, target, result, correlation id"/></span></div><div class="stack" style="flex-direction:row; flex-wrap:wrap"><button type="submit">Apply filters</button><a class="badge live" href="/audit">Reset</a></div></form></div>`, html.EscapeString(view.Query)); err != nil {
				return err
			}
			if len(view.Entries) == 0 {
				if err := writeEmptyState(w, "No audit events yet. UI lookups and operator actions will appear here when they are recorded."); err != nil {
					return err
				}
				_, err := fmt.Fprint(w, `</div>`)
				return err
			}
			if _, err := fmt.Fprint(w, `<div class="table-wrap"><table><thead><tr><th>timestamp</th><th>actor/source</th><th>action</th><th>target</th><th>result</th><th>correlation id</th><th>event id</th><th>ai</th></tr></thead><tbody>`); err != nil {
				return err
			}
			for _, entry := range view.Entries {
				if _, err := fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(valueOrUnknown(entry.Timestamp)),
					compactCopyHTML(auditDisplayValue(auditActorSource(entry)), 14, "Actor/source copied"),
					html.EscapeString(valueOrUnknown(entry.Action)),
					compactCopyHTML(auditDisplayValue(entry.Target), 16, "Target copied"),
					compactCopyHTML(auditDisplayValue(entry.Result), 16, "Result copied"),
					compactCopyHTML(auditDisplayValue(entry.Correlation), 14, "Correlation copied"),
					compactCopyHTML(auditDisplayValue(resolvedAuditEventID(entry)), 14, "Event ID copied"),
					auditAIButtonHTML(entry, csrfToken),
				); err != nil {
					return err
				}
			}
			_, err := fmt.Fprint(w, `</tbody></table></div></div>`)
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
			if _, err := fmt.Fprint(w, `<section class="grid about-grid">`); err != nil {
				return err
			}
			releaseRows := []keyValueRow{
				{Key: "Version", Value: view.Version},
				{Key: "Git commit", Value: view.GitCommit},
				{Key: "Build date", Value: view.BuildDate},
			}
			if err := renderKeyValuePanel(w, "Release", releaseRows); err != nil {
				return err
			}
			runtimeRows := []keyValueRow{
				{Key: "Go version", Value: view.GoVersion},
				{Key: "OS / arch", Value: view.GOOS + " / " + view.GOARCH},
			}
			if err := renderKeyValuePanel(w, "Runtime", runtimeRows); err != nil {
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

type keyValueRow struct {
	Key   string
	Value string
}

func renderKeyValuePanel(w io.Writer, title string, rows []keyValueRow) error {
	if _, err := fmt.Fprintf(w, `<div class="panel"><h2>%s</h2><div class="kv">`, html.EscapeString(title)); err != nil {
		return err
	}
	for _, row := range rows {
		value := valueOrUnknown(row.Value)
		if _, err := fmt.Fprintf(w, `<div class="row"><span>%s</span><span class="cell-clip" title="%s">%s</span></div>`, html.EscapeString(row.Key), html.EscapeString(value), html.EscapeString(value)); err != nil {
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
	build := buildmeta.Current()
	view := BuildInfoView{
		Version:   build.Version,
		GitCommit: build.Commit,
		BuildDate: build.BuildDate,
		GoVersion: build.GoVersion,
		GOOS:      build.GOOS,
		GOARCH:    build.GOARCH,
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
