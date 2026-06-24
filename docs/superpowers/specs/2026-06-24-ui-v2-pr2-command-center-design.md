# UI v2 PR2 Command Center Design

## Goal

Build the PR2 MVP for the SOC Command Center without starting PR3, PR4, PR5,
or PR6.

The dashboard becomes the primary operational entry point for operators while
remaining read-only, server-rendered, bounded, and safe.

## Scope

PR2 includes:

- Security Command Center header on the dashboard.
- Health Score derived from existing runtime, provider, system, and data-source
  health signals.
- Universal Search that routes operators to existing investigation surfaces.
- `Ctrl+K` command palette for lightweight navigation/search.
- Executive Overview with compact operator-critical state.
- Global time bar with bounded server-side time-window selection.
- Live Activity Feed backed by existing Timeline/evidence/runtime events.
- Widget freshness indicators.
- Offline-first degraded states when providers or data sources are unavailable.

## Explicit Non-Goals

PR2 does not include:

- Attack Map implementation.
- SVG, canvas, WebGL, or cartography library work.
- Dark Operations theme.
- Focus Incident mode.
- Split View.
- Watchlist.
- New mutation flows.
- New Cloudflare or CrowdSec mutations.
- Browser-owned business logic.
- Heavy frontend dependencies.

If a dashboard slot needs future map content, PR2 omits that slot. PR3 owns
threat visualization.

## UI Principles

This PR follows:

- `docs/ui-principles.md`
- `docs/audits/ui-ux-performance-audit.md`
- `docs/testing/UI_PERFORMANCE_BUDGETS.md`

Key constraints:

- Signal over spectacle.
- Server-first rendering.
- Observability and administration stay separate.
- Large datasets remain bounded.
- No secrets are rendered.
- Dashboard stays read-only.

## Information Architecture

The dashboard should be organized as:

```text
Security Command Center
  Health Score
  Runtime / CrowdSec / Cloudflare / WAF / DB / Sync status
  Global time bar

Executive Overview
  Operator-critical KPIs
  Degraded systems
  Freshness and stale data state

Universal Search
  Search input
  Ctrl+K command palette
  Fast links to investigation pages

Live Activity Feed
  Latest bounded events
  Severity
  Timestamp / freshness
  Links to Timeline, Evidence, or Forensic views

Provider / Runtime Summary
  Existing provider and health status, summarized not duplicated verbosely
```

## Search Behavior

Search is server-assisted navigation, not browser business logic.

Expected routing:

- IP address -> `/forensic?ip=<ip>`
- Evidence ID -> `/evidence/<id>` when a direct evidence pattern is detected
- ASN-like query -> `/security-intelligence?q=<query>` or Timeline fallback
- Provider keyword -> `/providers?q=<query>` if supported, otherwise provider page
- General forensic keyword -> `/timeline?q=<query>`

The command palette may help focus and submit these actions, but it must not
score, classify, mutate, or enrich data in the browser.

## Health Score

Health Score is a dashboard read-model derived from already available UI inputs:

- runtime status cards;
- provider health entries;
- environment/health widget status;
- SQLite/WAL status;
- CrowdSec, Cloudflare, WAF/OpenResty, and sync status where available;
- recent error or unavailable states already surfaced by existing UI code.

The score must expose the reason behind non-healthy states. A single percentage
without reasons is not acceptable.

## Live Activity Feed

The feed is a compact, bounded summary of recent activity.

Rules:

- Use existing Timeline/evidence/runtime event projections.
- Limit rows server-side.
- Link entries to existing detail pages where possible.
- Do not replace the Timeline.
- Do not load unbounded event history.
- If no source is available, render a degraded empty state instead of fake data.

## Freshness

Every major widget should expose one of:

- updated recently;
- stale with age;
- unavailable with reason;
- not configured when intentionally disabled.

Freshness text must be actionable enough for operators to distinguish stale data
from a disabled optional component.

## Accessibility And Ergonomics

PR2 should preserve PR1 ergonomics:

- compact mode support;
- collapsible panels where useful;
- keyboard-accessible `Ctrl+K`;
- visible focus state;
- no keyboard trap;
- dashboard usable at 1920x1080 and 1366x768.

## Data And Performance

All dashboard aggregations must be bounded.

Allowed:

- small count queries;
- limited recent-event reads;
- existing runtime/provider state;
- short server-side derived summaries.

Not allowed:

- full Timeline materialization for dashboard feed;
- unbounded evidence scans;
- client-side bulk datasets;
- browser-only scoring logic.

## Tests

Required test coverage:

- Dashboard renders Security Command Center.
- Health Score is derived from mixed status levels and includes reasons.
- Universal Search routes IPs to Forensic.
- Universal Search routes general keywords to Timeline.
- `Ctrl+K` markup/script is present and does not expose secrets.
- Live Activity Feed is bounded.
- Dashboard handles unavailable evidence/runtime/provider sources gracefully.
- Dashboard remains read-only and renders no Cloudflare/CrowdSec mutation forms.

## Playwright Reference Captures

PR2 should add or update reference captures for:

- dashboard command center default;
- dashboard command center compact mode;
- command palette open;
- degraded/offline provider state if safely reproducible.

Authenticated screenshots must run against a branch-local UI instance, not the
installed `cf-sync.service`.

## Acceptance Criteria

- Issue `#90` checklist can be updated honestly.
- Dashboard is the default operational landing page.
- Health Score derives from runtime/provider/system state and shows reasons.
- Search accepts IP and general forensic keywords.
- `Ctrl+K` works from major UI surfaces.
- Widgets show freshness or unavailable/degraded state.
- Dashboard degrades gracefully if external providers are unavailable.
- No secrets are exposed in rendered UI or screenshots.
- No Cloudflare/CrowdSec mutation is reachable from the dashboard.
- CI and smoke validation are green.
