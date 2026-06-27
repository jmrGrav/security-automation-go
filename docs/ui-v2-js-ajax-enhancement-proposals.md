# UI v2 JS/AJAX Enhancement Proposals

## Method

- Target: `https://sag.arleo.eu/v2/login` and the live `/v2/` surfaces behind it.
- Access: authenticated using the provided v2 password in a local Playwright session only.
- Tools:
  - Playwright via `./tests/smoke/node_modules/playwright`
  - live DOM inspection
  - viewport screenshots
  - navigation/perf timing from the browser Performance API
- Viewports:
  - desktop: `1440x1200`
  - mobile: `390x844`
- Pages inspected:
  - `/v2/`
  - `/v2/providers`
  - `/v2/timeline`
  - `/v2/investigate`
  - `/v2/incident`
  - `/v2/notes`
  - `/v2/audit`
  - `/v2/health`
  - `/v2/cloudflare`
- Route note:
  - live canonical route is `/v2/cloudflare`
  - `/v2/cloudflare-diff` is not exposed on this instance
- Screenshots generated:
  - `/tmp/sag-v2-audit/screens/*.png`

## Short Summary

What works well:

- The dark theme is coherent and operational.
- Provider state is legible, including enabled/disabled/attention distinctions.
- The dashboard already tells a real story: posture, threats, activity, components.
- Timeline and incident pages are clearly wired into the investigation workflow.

What still slows the operator:

- Mobile keeps the full sidebar visible above the fold, which steals too much vertical space.
- Empty states are still too thin on the investigation pages.
- Some surfaces are information-dense but not yet action-dense.
- Timeline is the heaviest page by far and is the best place to reduce DOM cost and add progressive loading.

What should stay unchanged:

- Server-rendered first.
- Dark-only operator theme.
- No SPA.
- No heavy client framework.
- No secret exposure in DOM or screenshots.

## Evidence Snapshot

Measured desktop timings and DOM sizes:

| Route | DCL | Nodes | Text length | Notes |
| --- | ---: | ---: | ---: | --- |
| `/v2/` | 2845 ms | 322 | 2041 | Good hero density, but still mostly read-only |
| `/v2/providers` | 116 ms | 515 | 1674 | Fast and readable |
| `/v2/timeline` | 5477 ms | 5159 | 34902 | Dominant DOM cost and best optimization target |
| `/v2/incident` | 61 ms | 116 | 445 | Empty-state UX needs more operator actions |
| `/v2/notes` | 67 ms | 145 | 599 | Empty-state UX needs more operator actions |
| `/v2/audit` | 53 ms | 216 | 1502 | Readable, but still linear and sparse |
| `/v2/health` | 4527 ms | 309 | 1234 | Strong readout, but expensive for a mostly static page |
| `/v2/cloudflare` | 894 ms | 185 | 1165 | Good operational summary |

Secret check:

- The provided password was not present in the rendered DOM on any inspected page.

## Prioritized Proposals

### P0

#### 1) Collapse the sidebar on mobile and turn it into a compact nav drawer
- Page: all `/v2/*`
- Problem observed: on mobile, the sidebar occupies a large fraction of the viewport before the main page content appears.
- Screenshot: `/tmp/sag-v2-audit/screens/dashboard-mobile.png`, `/tmp/sag-v2-audit/screens/providers-mobile.png`
- Improvement: render a compact top bar with a menu button on small screens; keep the full sidebar on desktop.
- Type: HTML + CSS + JS
- Risk: low
- Complexity: medium
- Why this respects v2: it keeps the same shell, just changes the presentation on narrow screens.
- Why it helps an operator: it restores above-the-fold content and reduces scrolling before the first useful signal.

#### 2) Replace empty pages with operator-oriented empty states
- Pages: `/v2/incident`, `/v2/notes`, `/v2/audit` and any similar no-data surface
- Problem observed: empty states are functional but still too sparse for SOC work.
- Screenshot: `/tmp/sag-v2-audit/screens/incident-mobile.png`, `/tmp/sag-v2-audit/screens/notes-mobile.png`
- Improvement: add quick actions, recent items, pinned items, and suggested pivots in the empty state.
- Type: HTML
- Risk: low
- Complexity: low
- Why this respects v2: it stays in the same visual language and only changes the empty branch.
- Why it helps an operator: every page remains useful even before data arrives.

### P1

#### 3) Make dashboard cards clickable and more informative
- Page: `/v2/`
- Problem observed: dashboard hero cards are informative, but some still feel like read-only widgets.
- Screenshot: `/tmp/sag-v2-audit/screens/dashboard-desktop.png`
- Improvement: make the major cards open the most relevant drill-down, and add more operator data inside the same footprint: uptime, last reload, runtime version, SQLite schema, worker count.
- Type: HTML + light JS
- Risk: low
- Complexity: medium
- Why this respects v2: same card system, better routing and denser content.
- Why it helps an operator: fewer clicks from posture to action.

#### 4) Add lightweight partial refresh for provider status and test actions
- Page: `/v2/providers`
- Problem observed: provider actions are already good server-rendered forms, but the page still reloads more than it needs to.
- Screenshot: `/tmp/sag-v2-audit/screens/providers-desktop.png`
- Improvement: after test/update/enable/disable, refresh only the touched provider card and the top summary chips; show a small confirmation toast or inline status line.
- Type: JS + AJAX fragments
- Risk: medium
- Complexity: medium
- Why this respects v2: it keeps forms server-side and only enhances the success path.
- Why it helps an operator: less context loss after a test or key update.

#### 5) Add expandable timeline rows and reduce always-on DOM
- Page: `/v2/timeline`
- Problem observed: this is the heaviest surface by far and the row details are too linear.
- Screenshot: `/tmp/sag-v2-audit/screens/timeline-desktop.png`, `/tmp/sag-v2-audit/screens/timeline-mobile.png`
- Improvement: keep the current summary rows, but lazy-load or collapse row details, and expand only on demand. Add icons and color by event category.
- Type: HTML + JS + optional AJAX fragment
- Risk: medium
- Complexity: medium to high
- Why this respects v2: the page stays a server-rendered timeline; only the detail reveal changes.
- Why it helps an operator: faster triage, less scrolling, lower DOM cost.

### P2

#### 6) Improve cross-page pivots from IPs and incidents
- Pages: `/v2/timeline`, `/v2/investigate`, `/v2/incident`, `/v2/audit`
- Problem observed: the workflow is visible, but the inter-page jumps can still be denser.
- Screenshot: `/tmp/sag-v2-audit/screens/incident-desktop.png`
- Improvement: from IP, evidence, or event rows, offer direct actions like open incident, open evidence, open filtered timeline, open forensic, open provider context.
- Type: HTML + JS
- Risk: low
- Complexity: low to medium
- Why this respects v2: it only wires existing routes together.
- Why it helps an operator: it turns pages into a workflow.

#### 7) Add a small universal search model with ranked suggestions
- Pages: global shell, `Ctrl+K`
- Problem observed: universal search is already present, but it can still become more action-oriented.
- Screenshot: `/tmp/sag-v2-audit/screens/dashboard-desktop.png`
- Improvement: rank suggestions into IP, ASN, provider, page, event, and recent items; keep the result list small and keyboard-first.
- Type: JS + optional JSON endpoint
- Risk: low
- Complexity: medium
- Why this respects v2: it stays lightweight and progressive.
- Why it helps an operator: fewer route jumps and faster pivots under load.

#### 8) Add a refreshable "updated just now" status line on live pages
- Pages: `/v2/`, `/v2/providers`, `/v2/health`, `/v2/cloudflare`
- Problem observed: live pages already show freshness, but the update cadence is mostly implicit.
- Screenshot: `/tmp/sag-v2-audit/screens/health-desktop.png`
- Improvement: add a small status stamp that can refresh via fragment or polling without a full reload.
- Type: JS + AJAX
- Risk: low
- Complexity: low
- Why this respects v2: it is a thin live-status enhancement.
- Why it helps an operator: it reassures the operator that the console is not stale.

### P3

#### 9) Add copyable diagnostic JSON for provider cards and evidence rows
- Pages: `/v2/providers`, `/v2/timeline`, `/v2/investigate`
- Problem observed: diagnostics are visible, but copying them still takes extra effort.
- Screenshot: `/tmp/sag-v2-audit/screens/providers-desktop.png`
- Improvement: one-click copy of redacted diagnostic JSON and row metadata.
- Type: JS
- Risk: low
- Complexity: low
- Why this respects v2: it is utility-only and does not alter runtime behavior.
- Why it helps an operator: it speeds up incident handoff.

#### 10) Add subtle hover and focus states to reinforce clickable cards
- Pages: card-heavy surfaces across `/v2/*`
- Problem observed: the design is already dark and legible, but some cards still read as static blocks.
- Screenshot: `/tmp/sag-v2-audit/screens/dashboard-desktop.png`
- Improvement: stronger hover/focus affordance, especially for drill-down cards and row actions.
- Type: CSS
- Risk: low
- Complexity: low
- Why this respects v2: it preserves the theme and only clarifies affordances.
- Why it helps an operator: it reduces hesitation and improves scan speed.

## Interaction Architecture Recommendation

| Option | Gain UX | Complexity | Risk | Dependency | Recommendation |
| --- | ---: | ---: | ---: | ---: | --- |
| HTML server-rendered only | Medium | Low | Low | None | Keep as the fallback baseline |
| JS vanilla + AJAX fragments | High | Medium | Low | None | **Primary recommendation** |
| REST JSON endpoints | Medium | Medium | Medium | None | Use only where shared data is reused |
| SSE live updates | Medium | Medium | Medium | None | Optional later, not core now |
| HTMX minimal | Medium | Low-Medium | Low-Medium | Small | Acceptable, but not required |
| Alpine.js minimal | Low-Medium | Low | Low | Small | Only for tiny local UI state |
| No framework | High | Lowest | Lowest | None | Best fit for this codebase |

Recommendation:

- Keep the current server-rendered shell as the source of truth.
- Add vanilla JS for progressive enhancement.
- Use fragment fetches for provider refresh, timeline expansion, live stamps, and search suggestions.
- Keep JSON narrow and shared only where multiple surfaces need the same data.
- Defer SSE until there is a real live-feed need that polling cannot cover cleanly.
- Do not introduce React, Vue, or Svelte.

Why this is the right fit:

- The existing UI is already server-first and template-driven.
- The pages are operational, not app-like.
- The current JS surface is small enough that adding a framework would mostly add weight and indirection.
- Fragment-based enhancement keeps fallback behavior intact if JS fails.

## Do Not Do

- No SPA.
- No heavy client framework.
- No gadget animation.
- No visual noise that competes with the data.
- No client-side security logic.
- No secret material in DOM, URLs, or screenshots.
- No mutation without server-side POST and CSRF.

## Final Recommendation

Top 5 next changes, in order:

1. Mobile sidebar collapse / drawer.
2. Stronger empty states on incident and notes.
3. Clickable dashboard hero cards with more data in the same footprint.
4. Partial-refresh provider actions with inline confirmation.
5. Expandable / lazy-loaded timeline rows.

Complexity estimate:

- P0 items: low to medium
- P1 items: medium
- P2 items: low to medium

Go / No-Go:

- **GO** for the next v1.7.5 follow-up iteration.
- The UI is already solid enough to keep, but the operator workflow still benefits from a small interaction pass focused on mobile density, empty states, and partial refresh.
