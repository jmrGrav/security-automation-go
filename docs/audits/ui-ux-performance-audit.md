# UI/UX Performance Audit and UI v2 PRD

## Executive summary
- The UI shell is already reasonably operator-friendly for desktop use: the console has sticky navigation, table containers, sticky table headers, and a mobile breakpoint at 900px, so this is not a broken-responsive-layout audit.
- The main confirmed problem is performance on the Timeline page: each request rebuilds the full merged event stream in memory, loads up to 10,000 evidence rows, and sorts the combined set before pagination.
- The largest UX gains now are incremental: denser operator views, faster list rendering, better workflow shortcuts, and optional compact/dark presentation modes.
- Expected gain from the recommended sequence: lower time-to-first-use on large datasets, fewer operator scrolls, faster forensic navigation, and a better fit for long-running SOC-style sessions.
- The audit also includes a strategic SOC/NOC operator-experience layer: Attack Map, compact dark mode, collapsible panels, and a dashboard built for live incident supervision, even when those items are product improvements rather than bugs.

## Findings

| Title | Severity | Page | Symptom operator | Cause probable | Files concerned | Proposal | Regression risk | Effort |
|---|---|---|---|---|---|---|---|---|
| Timeline builds the full merged event stream on every request | High | Timeline / forensic workflow | Timeline gets slower as audit and evidence volume grows; repeated refreshes reprocess the same history and can feel laggy during incident triage | `timelineView()` always calls `allTimelineEvents()`, which loads all audit entries plus up to 10,000 evidence rows, merges them into one slice, sorts the full set, then paginates in memory | `[/home/jm/Documents/security-automation-go/internal/ui/timeline.go#L44]`, `[/home/jm/Documents/security-automation-go/internal/ui/timeline.go#L93]` | Move toward paginated or windowed retrieval, or cache a bounded merged feed per request window; keep the existing operator-visible behavior but avoid full-history recomputation on every render | Medium: timeline ordering and filter semantics must stay correct | Medium |

### Verified evidence
- `timelineView()` reads query parameters, then immediately materializes the whole dataset through `allTimelineEvents()` before filtering and pagination.
- `allTimelineEvents()` appends every audit entry, loads evidence with `Limit: 10000`, sorts the merged slice, and only then returns the result.
- `EvidencePage()` is already paginated, which confirms the timeline page is the outlier rather than a repo-wide “all tables are unpaginated” pattern.

### Failure scenario
- An operator opens `/timeline` repeatedly during an active incident while evidence volume is high.
- The handler rebuilds and sorts a large merged slice on each request.
- UI response time increases, refreshes feel stale, and the page becomes less useful for real-time investigation.

### Why this matters for security-automation-go
- This is an operator control plane, not a static dashboard.
- Timeline is a core forensic path and should remain responsive under sustained event volume.
- Slow forensic views increase triage time and make the UI feel unreliable when the system is under stress.

### Recommended fix
- Codex recommendation: preserve the current timeline semantics, but replace full-history recomputation with a bounded or windowed read path.
- Keep filtering and pagination server-side, but avoid loading and sorting everything on every request.
- If a new persistence/index path is required later, introduce it in a follow-up focused on timeline data access rather than UI markup.

### Tests Claude Code should add
- A regression test that verifies Timeline rendering does not require loading an unbounded evidence set for a small page.
- A test that keeps ordering stable when audit entries and evidence rows are interleaved.
- A performance-oriented test or benchmark around large event volumes, if the project accepts benchmarks in test scope.

### Validation commands used
- `GOTOOLCHAIN=go1.25.0 go test ./... -coverprofile=/tmp/security-automation-coverage.out`
- `GOTOOLCHAIN=go1.25.0 go tool cover -func=/tmp/security-automation-coverage.out`
- `GOTOOLCHAIN=go1.25.0 go test -tags=smoke ./internal/ui/...`
- `SECURITY_AUTOMATION_SMOKE_LIVE=1 npx playwright test --list`
- `rg -n "Limit:\\s*10000|sort\\.Slice\\(|paginate|table-wrap|render.*table|Search\\(ctx" internal/ui -g'*.go'`

## Priorities recommended

### P0: blocker opérateur
- Timeline request path recomputes the full merged event stream.

### P1: gros gain UX/perf
- Add faster, denser presentation to high-traffic operator pages such as Dashboard, Forensic, Evidence, Providers, and Health.
- Add compact layouts and a more SOC-oriented top-of-page summary to reduce scroll depth.
- Add quicker navigation shortcuts from dashboard tiles into the forensic detail path.

### P2: polish utile
- Improve badge wording for long CIDRs, IPs, and provider states.
- Add clearer empty states and loading states where long pages are refreshed frequently.
- Add copy-to-clipboard affordances for forensic identifiers and provider references.

### P3: dette visuelle
- Refine spacing, typography, and color hierarchy for a more operations-oriented shell.
- Consider a darker default palette for long viewing sessions, while keeping the current light theme available.
- Add optional collapsible secondary panels on dense pages.

## Plan de correction proposé

1. Responsive/layout
   - Keep the current breakpoint behavior, but reduce vertical waste on dense pages.
   - Introduce a compact mode that lowers padding, heading size, and panel spacing without changing data semantics.

2. Tables/pagination
   - Apply stricter server-side windowing to the Timeline path.
   - Keep tables dense and sticky, but avoid rebuilding large merged lists on every refresh.

3. Loading/empty/error states
   - Add explicit loading states for expensive operator pages.
   - Make empty states actionable and page-specific.

4. Dashboard quick actions
   - Promote direct links from dashboard cards to forensic and evidence views.
   - Surface operator-critical status in fewer clicks.

5. Provider/trusted networks polish
   - Tighten labels, status badges, and compact row density.
   - Prefer collapse/expand sections for secondary diagnostics.

## Tests recommended
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go build ./...`
- smoke UI live
- screenshots before/after
- viewport checks on desktop, tablet, and mobile
- verification that no secret is exposed in rendered UI

## Inspirations UX and propositions

### Attack Map
- Benefit operator: gives a fast geographic overview of active attack origin and volume, especially useful during live incident response.
- Complexity: High
- Performance impact: Medium if implemented as a read-only SVG/canvas summary with bounded sampling; High if it tries to render every event individually.
- Priority: P1
- Notes: should stay read-only, with pause/resume, time filters, and click-through to forensic detail. Build an enrichment layer so incomplete geo data degrades gracefully.

#### Suggested wireframe
```text
┌──────────────────────────────────────────────────────────────────────────┐
│ Attack Map  [15m] [1h] [24h] [7d]  Pause ⏸  Live ●  Top: US FR DE ...    │
├───────────────────────────────┬──────────────────────────────────────────┤
│    SVG world map              │  KPIs                                    │
│    • country heat             │  Attacks: 1284                            │
│    • animated source pulses   │  IPs: 312                                 │
│    • click country/IP         │  Top scenario: brute_force                │
│    • pause/resume             │  Top country: US                          │
├───────────────────────────────┴──────────────────────────────────────────┤
│ Selected country / IP → direct forensic link                              │
└──────────────────────────────────────────────────────────────────────────┘
```

### Dark Operations theme
- Benefit operator: improves comfort during long SOC sessions and increases contrast discipline on large displays.
- Complexity: Medium
- Performance impact: Low
- Priority: P2
- Notes: should remain compatible with a future light mode and avoid copying any external brand style.

#### Suggested wireframe
```text
bg: #09111d   panel: #0f1728   panel-alt: #111b31   border: #24344f
text: #e7eefc  muted: #8ea2c7  accent: #56a6ff  success: #46d39a

┌───────────────┬──────────────────────────────────────────────────────────┐
│ Sidebar       │  Dashboard / Forensic / Evidence / Timeline             │
│ compact nav   │  Dense cards, high-contrast tables, subdued separators   │
└───────────────┴──────────────────────────────────────────────────────────┘
```

### Compact mode
- Benefit operator: increases information density on laptop and desktop screens, reducing scroll and context switching.
- Complexity: Low
- Performance impact: Low
- Priority: P1
- Notes: best implemented as a CSS/class-level density toggle rather than a new page model.

#### Suggested wireframe
```text
Default:    [ card padding 1rem ] [ table row height 2.4rem ] [ larger gutters ]
Compact:    [ card padding .65rem ] [ table row height 1.9rem ] [ reduced gutters ]
```

### Collapsible panels
- Benefit operator: hides low-value secondary information so the primary workflow stays visible.
- Complexity: Low
- Performance impact: Low
- Priority: P1
- Notes: especially valuable on forensic, provider diagnostics, trusted networks, and dashboard secondary blocks.

#### Suggested wireframe
```text
▶ Provider diagnostics
▼ Forensic details
▼ Trusted networks
▶ Advanced info
```

### SOC-oriented dashboard
- Benefit operator: puts key security KPIs, top countries, top IPs, scenarios, and health in one glanceable surface.
- Complexity: Medium
- Performance impact: Medium
- Priority: P1
- Notes: keep widget data bounded and cheap; avoid replacing the current shell with a heavy client-side dashboard.

#### Suggested wireframe
```text
┌ KPI ┐ ┌ KPI ┐ ┌ KPI ┐ ┌ KPI ┐ ┌ KPI ┐
│ 24h │ │ IPs │ │ CS │ │ CF │ │ AIP │
├───────────────────────────────────────┤
│ Top countries │ Top IPs │ Top scen.   │
├───────────────────────────────────────┤
│ Mini attack map │ Event timeline      │
├───────────────────────────────────────┤
│ Provider health │ Runtime health      │
└───────────────────────────────────────┘
```

### Navigation and ergonomics
- Benefit operator: reduces friction for frequent page switching and repetitive incident workflows.
- Complexity: Low
- Performance impact: Low
- Priority: P1
- Notes: sidebar collapse, persistent search, keyboard shortcuts, and remembered panel state are all incremental wins.

### Tables and lists
- Benefit operator: improves scanability and reduces visual fatigue in data-heavy pages.
- Complexity: Medium
- Performance impact: Low to Medium
- Priority: P2
- Notes: pagination should be systematic; sticky headers, instant filters, and export actions are good quick wins, while multi-column sorting and resizable columns can be staged later.

### Ergonomic details
- Benefit operator: makes repetitive operator actions cheaper.
- Complexity: Low
- Performance impact: Low
- Priority: P3
- Notes: add copy buttons for IP/CIDR/IDs, clearer empty/loading states, and more explicit status badges.

## Notes
- The current UI already has a mobile breakpoint and a strong table shell, so the strongest opportunity is not a full redesign.
- The main value is in reducing repeated work on hot paths and tightening information hierarchy for operator workflows.

## UI v2 PRD

### Product vision
Build an operator console that feels fast, dense, and readable during long SOC/NOC sessions.
The UI should prioritize incident triage, forensic navigation, and provider visibility while staying lightweight, read-only where appropriate, and compatible with the existing security model.
The home experience should behave like a Security Command Center first, not a generic app dashboard.
The Attack Map should be a dashboard widget first, with a dedicated full-screen view available only as a secondary drill-down.

### Personas
- Operator SOC: daily use; Dashboard, Live Feed, Attack Map, search, Focus Incident.
- Forensic analyst: Timeline, Evidence, correlations, AI summary, export.
- Administrator: Providers, Trusted Networks, settings, maintenance.
- NOC supervisor: TV mode with KPIs and global health.

Each PR should state which persona it improves most.

### Non-goals
- No heavy client-side dashboard framework.
- No WebGL or other large browser dependencies for map visualizations.
- No mutation of Cloudflare/CrowdSec workflows as part of the UI redesign.
- No auth, CSRF, or secret-handling regressions.
- No backend redesign that changes runtime semantics for the sake of presentation alone.
- No direct mutation actions from the Attack Map or SOC dashboard; these views remain supervision and investigation surfaces only.

### Design system
- One card component style.
- One badge style per severity/state family.
- One icon set.
- Cohesive spacing and typography scale.
- Consistent read-only vs admin-action visual distinction.

### Accessibility
- Keyboard navigation first where possible.
- Visible focus states.
- Sufficient contrast.
- Explicit labels.
- Screen reader compatibility where practical.

### Device priorities
- Desktop: highest priority, especially 1920x1080 and above.
- Laptop: high priority, especially 1366x768 to 1600x900.
- Tablet: consultation supported.
- Phone: minimal support, consultation only.

### Roadmap

#### PR1: Quick Wins
**Target:** 1 to 2 days
**Impact:** Very high
**Complexity:** Low

- Fix the Timeline hot path already captured in issue [#69](https://github.com/jmrGrav/security-automation-go/issues/69).
- Add a global compact mode.
- Make secondary panels collapsible.
- Add copy buttons for IP, CIDR, IDs, and hashes.
- Reduce margins and card height on desktop screens.

**Expected result**
- More information visible above the fold.
- Faster operator scanning on dense pages.
- Less friction on repetitive forensic tasks.

**Acceptance criteria**
- Compact mode shows at least 25 percent more rows on a 1920x1080 screen.
- Collapsed panels keep their open/closed state after navigation.

#### PR2: Dashboard SOC
**Target:** 3 to 5 days
**Impact:** Very high
**Complexity:** Medium

Create a home page designed for a security operator:

```text
┌───────────────────────────────────────────────────────────────┐
│ Security Command Center                                       │
│ Runtime 🟢 CrowdSec 🟢 Cloudflare 🟢 WAF 🟢 DB 🟢 Sync 8s ago  │
├───────────────────────────────────────────────────────────────┤
│ KPI Cards (24h)                                               │
│ Attacks │ Blocked │ New IPs │ Repeat IPs │ Reports │ Health    │
├───────────────────────┬───────────────────────────────────────┤
│ 🌍 Attack Map         │ 📡 Live Activity Feed                │
├───────────────────────┼───────────────────────────────────────┤
│ 📊 Top Countries      │ 🎯 Top Scenarios                     │
├───────────────────────┼───────────────────────────────────────┤
│ ☁️ Provider Health    │ 🔒 Runtime Health                    │
└───────────────────────────────────────────────────────────────┘
```

- Widgets should be configurable.
- Refresh must stay light and bounded.
- Each widget should link directly into forensic or evidence views.
- The dashboard should expose meaningful KPIs, not just counters:
  - average time to block;
  - attacks blocked in the last 24h;
  - new vs repeat IPs;
  - Cloudflare sync success rate;
  - AbuseIPDB report volume;
  - 24h and 7d deltas where available.
- Add a global `Health Score` derived from CrowdSec, Cloudflare, WAF/OpenResty, SQLite, sync health, provider health, and recent errors.
- Each widget should show freshness, for example:
  - `updated 3s ago`
  - `data stale by 2m`
- The dashboard should be customizable:
  - hide widgets;
  - reorder widgets;
  - save multiple layouts;
  - choose the home page.
- The Attack Map must remain a widget on this dashboard, not the entire home surface.

**Expected result**
- Operators can assess system state in one glance.
- Faster navigation from anomaly detection to investigation.
- Better fit for live incident monitoring.
- The dashboard becomes the default operational landing page rather than a generic summary page.

**Acceptance criteria**
- The dashboard loads in under 500 ms on a local reference instance.
- Every widget shows freshness text such as `updated 3s ago`.

**Success metrics**
- Time to open the forensic view for an IP.
- Number of clicks needed to reach a critical status.
- Dashboard render time.
- Time to first meaningful operator signal.

#### PR3: Attack Map
**Target:** 4 to 7 days
**Impact:** Very high
**Complexity:** Medium to high

Design a lightweight attack map as the differentiating UI element.

- Use SVG, with optional lightweight canvas support for motion effects only.
- Aggregate by country.
- Show discrete pulses for active attacks.
- Support pause/resume.
- Support time filters.
- Click a country or IP to open the IP forensic page or Timeline.
- Keep the map as a dashboard widget first, with a larger dedicated view available on demand.
- Keep the implementation server-assisted:
  - aggregate on the backend;
  - sample intelligently;
  - avoid sending every raw event to the browser.

Potential data sources:
- CrowdSec
- Local WAF
- Cloudflare
- Evidence
- Forensic views

**Expected result**
- A fast visual overview of attack distribution.
- Stronger SOC-style situational awareness.
- A feature that is useful both in dashboards and in standalone analysis mode.
- No heavy browser dependency and no direct mutation path from this surface.

**Acceptance criteria**
- The map remains fluid with 10,000 aggregated events.
- No heavy cartographic library is loaded.

**Success metrics**
- Time to understand top source countries.
- Time to drill from map to forensic detail.

#### PR4: Operations Dark Theme
**Target:** 2 to 4 days
**Impact:** High
**Complexity:** Medium

Create a dark “Operations” theme with its own identity:

- blue-night background;
- dark gray panels;
- high but comfortable contrast;
- subdued badges;
- optimized for prolonged viewing;
- fully compatible with a light theme.
- Two display profiles:
  - `Operations Compact` for large screens;
  - `Comfort` for slightly more breathing room.

**Expected result**
- Better long-session comfort.
- Better density perception on large displays.
- More SOC-like presentation without copying third-party branding.

**Acceptance criteria**
- The theme preserves a usable light-mode equivalent.
- Contrast remains readable across status colors and tables.

#### PR5: Modern Navigation
**Target:** 2 to 4 days
**Impact:** High
**Complexity:** Low to medium

- Collapsible sidebar.
- Global persistent search.
- Keyboard shortcuts.
- Persistent panel state.
- Favorites or recently viewed pages.
- A command palette, opened with `Ctrl+K`, for actions such as:
  - search an IP;
  - open Timeline;
  - go to Trusted Networks;
  - view Provider Health;
  - open Evidence.
- A universal search input should accept raw and typed queries without module selection, for example:
  - `194.126.177.82`
  - `XSS`
  - `Cloudflare`
  - `asn:13335`
  - `country:DE`

**Expected result**
- Lower navigation friction.
- Faster return to frequent workflows.
- Better support for operators who bounce between the same pages all day.
- A single search box should also accept direct operator queries such as IPs, scenario names, provider names, and forensic keywords.

**Acceptance criteria**
- Universal search returns a first result in under 200 ms for common cases.
- `Ctrl+K` opens the command palette from any major surface.

**Success metrics**
- Time to reach a target page or object.
- Number of clicks avoided per session.
- Search latency for common operator queries.

#### PR6: Tables and Ergonomics
**Target:** 2 to 5 days
**Impact:** Medium
**Complexity:** Medium

- Systematic pagination.
- Resizable columns where useful.
- Multi-column sorting.
- Instant filters.
- JSON/CSV exports.
- Sticky headers.
- Live timeline grouping by minute where the feed is expanded into a full investigation view.
- Color by event type for faster scanning.

**Expected result**
- Cleaner scanability.
- Better handling of large datasets.
- Less manual copy/paste work for operators.

**Acceptance criteria**
- Tables keep sticky headers.
- Table views remain usable at laptop and desktop widths.
- Focus Incident can centralize IP, Timeline, Evidence, WAF, Cloudflare, CrowdSec, AbuseIPDB, and AI summary in one investigation view.
- TV/NOC mode can display oversized KPIs and the map without requiring interaction.

### Additional concepts

#### Security Command Center
Permanent top bar showing current system health at a glance.

```text
Runtime: 🟢  CrowdSec: 🟢  Cloudflare: 🟢  OpenResty: 🟢  AbuseIPDB: 🟡  Last sync: 12s ago
```

**Benefit**
- The operator immediately knows whether the system is healthy and synchronized.
- The header doubles as a freshness indicator for the whole console.

**Complexity**
- Low

**Priority**
- High, as a supporting element for PR2 and PR5

**Acceptance criteria**
- The command center is visible on the default dashboard and stays read-only.
- It clearly distinguishes observability state from admin mutation workflows.

#### Live Activity Feed
Compact stream of the latest security events.

```text
[10:42:11] 🚫 IP 1.2.3.4 blocked
[10:42:09] 🛡️ XSS detected
[10:41:58] ☁️ Cloudflare rule created
[10:41:40] 📤 AbuseIPDB report sent
```

**Behavior**
- Click any entry to open the related forensic detail.
- Keep the feed compact and bounded.
- Do not make it a noisy full event log.
- Allow the feed to expand into the full Timeline investigation view.
- Group compact rows by minute when the operator opens the expanded form.
- Expose severity levels and filters:
  - Critical
  - High
  - Medium
  - Information

**Benefit**
- Gives operators a fast sense of live system activity.
- Supports rapid movement from signal to investigation.
- Acts as the lightweight front door to the Timeline, without replacing it.

#### Additional views

##### TV / NOC mode
- Purpose: always-on display for wallboards and operations rooms.
- Characteristics:
  - automatic refresh;
  - oversized KPIs;
  - enlarged attack map widget;
  - no interactive controls required.
- Priority: High
- Complexity: Medium

##### Focus Incident mode
- Purpose: center the UI on one selected IP or incident.
- Layout:
  - Timeline;
  - Evidence;
  - WAF events;
  - Cloudflare actions;
  - CrowdSec decisions;
  - AbuseIPDB history;
  - AI summary.
- Behavior:
  - preserve read-only investigation semantics;
  - filter all related views around the selected subject;
  - allow deep drill-down without changing provider state from the view itself.
- Priority: High
- Complexity: Medium

**Complexity**
- Low to medium

**Priority**
- High, as a supporting element for PR2 and PR3

**Acceptance criteria**
- The feed supports severity filtering.
- The feed can expand into a minute-grouped Timeline view.

### Recommended order
1. PR1 Quick Wins
2. PR2 Dashboard SOC
3. PR3 Attack Map
4. PR4 Operations Dark Theme
5. PR5 Modern Navigation
6. PR6 Tables and Ergonomics

### Overall recommendation
- The three highest-value changes are:
  - Attack Map interactive;
  - Dark Operations theme;
  - SOC Dashboard with Command Center and Live Activity Feed.
- These changes are coherent with the current product direction and give the biggest visible leap in operator experience without compromising the current security and runtime model.
- Keep all of them read-only and investigation-focused; any mutation workflow should remain in the existing controlled provider/admin flows.
- The Attack Map should start as a dashboard widget, not a standalone homepage, so critical KPIs stay visible at all times.

### Test strategy
- Go tests remain the primary regression net for backend and server-rendered UI behavior.
- Add Playwright reference captures for:
  - default dashboard;
  - dark theme;
  - compact mode;
  - `Ctrl+K`;
  - Focus Incident;
  - TV/NOC mode.
- Add viewport checks for:
  - desktop;
  - laptop;
  - tablet;
  - phone consultation.
- Add a no-secrets-in-UI check for rendered pages and screenshots.

### Release success criteria
- Operators can reach the forensic target in fewer clicks.
- The dashboard becomes the default operational landing page.
- The console remains responsive under sustained event volume.
- The UI is visibly denser and more readable on large monitors.

## Implementation backlog

The PRD is mature enough to stop expanding. The next step is a backlog of small, independent PRs with Playwright reference captures to prevent visual regressions.

### Backlog principles
- Keep PRs small and independent.
- Preserve strict observability vs action separation.
- Use Playwright screenshots as a baseline for the important surfaces.
- Prefer server-assisted rendering and bounded datasets.
- Keep every new control read-only unless it belongs to an existing admin workflow.
- Apply progressive disclosure: show summaries first, then Focus Incident, then Timeline, then Evidence.
- AI summarizes, but never replaces primary evidence.
- The dashboard must continue to function in offline-first degradation mode when external providers are unavailable.
- Avoid heavy browser dependencies and keep behavior independent from any external vendor UI.
- The UI is only a projection of system state; all business decisions, security logic, and mutations stay on the server.
- Keep the UI sober: signal over spectacle, no unnecessary motion, no aggressive colors, no blinking.

### Final recommendations

#### 1. Saved dashboard views
- Allow operators to save multiple layouts:
  - SOC Monitoring
  - Incident Response
  - Threat Intelligence
  - Administration
- Benefit: one layout never needs to satisfy every workflow.
- Priority: P1
- Complexity: Medium

#### 2. Pinned incidents
- Rename this concept to `Watchlist`.
- Allow operators to track a small set of important IPs, ASNs, countries, campaigns, WAF rules, or custom indicators.
- Benefit: faster retrieval of the items the operator cares about right now, with more flexible scope.
- Priority: P1
- Complexity: Low to medium

#### 3. Executive Overview
- Add a very concise overview for managers or quick consultations.
- Content:
  - global Health Score;
  - attacks in 24h;
  - top 3 campaigns;
  - CrowdSec / Cloudflare / WAF status;
  - last sync;
  - any critical alert.
- Benefit: immediate situational awareness without replacing the full dashboard.
- Priority: P2
- Complexity: Low to medium

#### 4. Correlated multi-source timeline
- Merge WAF, CrowdSec, Cloudflare, AbuseIPDB, and AI summary into one chronological incident stream.
- Benefit: the operator follows one incident without changing pages.
- Priority: P1
- Complexity: Medium to high

#### 5. Top Campaigns view
- Add a campaign-oriented view for brute force, distributed scans, XSS, SQLi, and known bots.
- Benefit: more context than a raw IP list.
- Priority: P2
- Complexity: Medium

#### 6. Conservative animation policy
- Keep Attack Map motion discreet.
- No permanent blinking.
- Animation must be disableable.
- Priority: P1
- Complexity: Low

#### 7. Local operator notes
- Allow per-IP or per-incident local notes such as confirmation, triage status, or ignore rationale.
- Store locally without mutating CrowdSec or Cloudflare decisions.
- Priority: P2
- Complexity: Low to medium

#### 8. Demo mode
- Provide a safe demonstration mode with anonymized data, simulated metrics, and no secrets.
- Useful for product demos and screenshots.
- Priority: P2
- Complexity: Medium

#### 9. Single severity palette
- Use one severity palette everywhere:
  - Critical: red
  - High: orange
  - Medium: yellow
  - Information: blue
- Apply it consistently across Timeline, Feed, Dashboard, Attack Map, and tables.
- Priority: P1
- Complexity: Low

#### 10. Global time bar
- Add a shared time selector used by Dashboard, Attack Map, Timeline, and Top Campaigns.
- Presets:
  - Last 15 min
  - 1 h
  - 6 h
  - 24 h
  - 7 d
  - 30 d
- Benefit: all widgets update coherently when the time window changes.
- Priority: P1
- Complexity: Low to medium

#### 11. Split View
- Offer a split-screen investigation mode:
  - Timeline on one side;
  - Focus Incident on the other.
- Benefit: better incident triage without page switching.
- Priority: P1
- Complexity: Medium

#### 12. UI performance budgets
- Dashboard: under 500 ms
- Search: under 200 ms
- Page transition: under 300 ms
- Focus Incident: under 400 ms
- Timeline first render: under 500 ms on a reference volume
- Verify these budgets regularly.
- Any new UI feature must meet these budgets or explicitly justify why it exceeds them.
- Priority: P0
- Complexity: Low to medium

#### 13. Strict observability / action separation
- Dashboard, Attack Map, Timeline, Live Feed, and Focus Incident stay read-only.
- Cloudflare, CrowdSec, Trusted Networks, and Providers mutations stay in dedicated admin flows with existing protections.
- This is the most important product rule.
- Priority: P0
- Complexity: Architectural rule, not a feature

### Roadmap constraints
- Do not show everything at once; use progressive disclosure from summary to detail.
- AI summaries must always link back to raw evidence and source events.
- Dashboard widgets must degrade gracefully if Cloudflare, AbuseIPDB, VirusTotal, or similar sources are unavailable.
- Unavailable widgets should show last successful update time instead of blocking the dashboard.
- Very large volumes must stay usable through server-side pagination, incremental loading, smart aggregation, and list virtualization if needed.
- Performance budgets are continuous quality gates, not one-time goals.
- Any notable regression against the budgets should be treated as a bug.
- The front-end dependency budget is strict: do not add a heavy JavaScript library without a clear benefit over its maintenance and performance cost.
- Prefer native HTML, CSS, and JavaScript plus server-side rendering by default.
- Major features should be independently feature-flagged to support gradual rollout and easy rollback.

### Never do
- No 3D charts or heavy WebGL.
- No permanent animations.
- No full page refresh as a primary interaction model.
- No heavy cartography libraries.
- No business logic in the browser.
- No UI that depends on an external vendor service to render.

### Suggested PR sequence
1. Performance & ergonomics baseline: Timeline, compact mode, collapsible panels, performance budgets.
2. Command Center: Dashboard SOC, Health Score, universal search, `Ctrl+K`, Executive Overview, global time bar.
3. Threat visualization: Attack Map, Top Campaigns, enriched Live Feed.
4. Visual identity: Dark Operations theme, Design System, demo mode.
5. Operator productivity: Split View, Watchlist, navigation refinements.
6. Advanced investigation: Correlated multi-source timeline, local notes.

### Large-volume handling
- Timeline, search, and tables must stay usable as data volume grows.
- Prefer server-side pagination over client-side bulk rendering.
- Use incremental loading where it reduces the initial wait without losing clarity.
- Use smarter aggregation instead of sending raw event floods to the browser.
- Virtualize long lists only when it is the simplest safe option.

### MVP / V2 / V3 split

#### MVP
- Performance & ergonomics baseline
- Dashboard / Command Center
- Search universelle + `Ctrl+K`
- Health Score
- Live Activity Feed
- Budgets de performance
- Progressive disclosure
- Séparation observabilité / actions

#### V2
- Attack Map
- Top Campaigns
- Focus Incident enriched
- Timeline corrélée multi-sources
- Split View
- Watchlist
- Executive Overview
- Mode TV / NOC

#### V3
- Notes opérateur
- Mode démo avancé
- Comfort / personalization improvements

### Definition of done
- Respect performance budgets.
- Automated tests are green.
- No secrets are exposed.
- Design System compliance is maintained.
- Degraded / offline-first behavior works as expected.
- Observability vs actions separation remains intact.

### User-impact metrics
- Time to find an IP.
- Average clicks to reach Focus Incident.
- Time to identify the dominant campaign.
- Time to verify the global platform state.
- These metrics should be tracked alongside technical budgets so UX improvements are validated by operator outcomes.

### Reference capture plan
- Capture default dashboard.
- Capture compact mode.
- Capture dark mode.
- Capture `Ctrl+K`.
- Capture Focus Incident.
- Capture Split View.
- Capture TV / NOC mode.
- Capture demo mode.

### Final stance
- The dashboard should remain the center of command.
- The Attack Map is a context widget first, not a replacement for the dashboard.
- The UI should feel professional, calm, and information-dense.
- All action paths remain controlled and separate from observability surfaces.
- The Dashboard SOC remains the core of the application with four pillars:
  - KPIs and Health Score;
  - Attack Map;
  - Live Activity Feed;
  - Universal Search and Focus Incident.
- Performance budgets are a first-class contract, not a late optimization task.

### GitHub tracking
- [UI v2 PR1: Performance & Ergonomics Baseline](https://github.com/jmrGrav/security-automation-go/issues/91)
- [UI v2 PR2: SOC Command Center](https://github.com/jmrGrav/security-automation-go/issues/90)
- [UI v2 PR3: Threat Visualization](https://github.com/jmrGrav/security-automation-go/issues/97)
- [UI v2 PR4: Visual Identity & Design System](https://github.com/jmrGrav/security-automation-go/issues/101)
- [UI v2 PR5: Operator Productivity](https://github.com/jmrGrav/security-automation-go/issues/99)
- [UI v2 PR6: Advanced Investigation](https://github.com/jmrGrav/security-automation-go/issues/93)
- [Release gate: v1.7.5 UI v2 readiness](https://github.com/jmrGrav/security-automation-go/issues/98)
