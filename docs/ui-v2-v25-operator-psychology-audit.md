# UI v2.5 Operator Psychology and Focus Model Audit

**Date:** 2026-06-27  
**Method:** Full static analysis of all v2 Go render files; cross-referenced with live service at `127.0.0.1:9091`. Pages audited: `/v2/`, `/v2/timeline`, `/v2/investigate`, `/v2/providers`, `/v2/health`, `/v2/cloudflare`, `/v2/notes`, `/v2/audit`.

---

## Method

Pages were audited by reading all Go render functions and tracing the generated HTML structure. Hierarchy, information budget, focus flow, and consistency were evaluated against operator psychology principles: triage readiness, zero-wait feedback, confidence signaling, and progressive disclosure.

---

## Score Summary

| Dimension | Score | Notes |
|---|---|---|
| Story flow | 4/10 | Dashboard reads as counters, not narrative |
| Focus modes | 3/10 | No collapse, no lock-on-IP, no triage mode |
| Eye guidance | 5/10 | Good on Health/Investigate; poor on Dashboard |
| Information budget | 4/10 | Dashboard has 6 competing sections |
| Progressive disclosure | 6/10 | `<details>` used well in timeline; not elsewhere |
| Keyboard-first usability | 5/10 | Ctrl+K palette on dashboard; missing on most pages |
| Split-second updates | 6/10 | Live badges everywhere; actual push limited to providers |
| Zero-wait feedback | 6/10 | Server-rendered fast; no skeleton states |
| Confidence signaling | 7/10 | Verdict badge on Investigate is strong; dashboard lacks |
| Explainability | 5/10 | Investigate explains score; Timeline/Dashboard don't |
| Incident workspace feel | 3/10 | No workspace — pages are views, not a case file |
| Product identity | 7/10 | Gradient brand, dot nav, dark shell — consistent on all pages except Dashboard |
| Commercial polish | 5/10 | Good surface-level finish; structural gaps underneath |

---

## Five Operator Questions

Does the UI answer these for each page?

| Question | Dashboard | Timeline | Investigate | Providers | Health |
|---|---|---|---|---|---|
| Current situation? | ✗ (counters, no narrative) | ~ (events exist, no posture) | ✓ (verdict badge) | ✓ (posture strip) | ✓ (all-green vs issues) |
| What changed? | ~ (live tail exists) | ✓ (real-time feed) | ✗ | ✗ | ✗ |
| Why it matters? | ✗ | ✗ | ✓ (score, geo) | ~ (advisory if needed) | ~ (advisory if needed) |
| What should I do? | ✗ | ✗ | ~ (verdict badge suggests) | ~ (advisory) | ~ (remediation) |
| Can I ignore it? | ✗ | ✗ | ✓ (PROTECTED badge) | ✓ (disabled by operator) | ✓ (all-green state) |

---

## Forces

**What works well:**
- `v2Page()` shell is consistent across all pages *except the Dashboard*.
- Investigate page (PR #152) is the strongest page — verdict badge, signal tiles, two-column forensic/history layout answer all five operator questions.
- Health page funnel is excellent — classified → suppressed → pending → reported is a real pipeline narrative.
- Providers page posture strip (dot + headline + chips) is clean and readable.
- Typography hierarchy (Hanken Grotesk for labels, JetBrains Mono for values/timestamps) is well-applied and consistent.

**What works against operators:**
- Dashboard is a full standalone HTML page with its own sidebar, bypassing `v2Page()`. The sidebar contains stale links (`/v2/incident`, `/forensic`, `/cloudflare/diff`, Classic UI) and Watchlist/Recent widgets that the shell redesign (PR #153) removed. An operator switching from the Dashboard to any other page sees a completely different shell.
- No situation banner above the fold on the Dashboard. The operator must visually scan three equal-weight stat cards to reconstruct current posture. There is no single "what is happening right now" line.
- Timeline rows default to showing full pill sets inline. Six action links appear on every row with a target IP. For a 200-event feed, this is 1,200 possible action links. The operator cannot scan; they must read.
- Timeline row details include `/forensic?ip=` — a link to the old v1 forensic page. Clicking it drops the operator out of v2.
- Providers boundary strip links to `/cloudflare/diff` — the old v1 CloudFlare diff page. `/v2/cloudflare` exists but is not used here.
- Notes page pinned section is hardcoded to "No pinned notes yet." Pinning is not implemented; the section creates false affordance.

---

## Gaps

### P0: Dashboard sidebar is a stale fork of the shell

**File:** `internal/ui/v2_dashboard.go:385–451`

The dashboard renders its own complete `<html>` document with its own `<nav>` sidebar. This nav still contains `/v2/incident`, `/forensic`, `/cloudflare/diff`, `Classic UI`, Watchlist widget, and Recent widget — all removed in PR #153. The operator sees two different UIs depending on whether they are on the dashboard or any other v2 page.

**Fix:** Migrate the dashboard to use `v2Page()`. The dashboard's main content block is self-contained and can be dropped into `v2Page("Dashboard", "/v2/", mainContent)` without changing any data or rendering logic.

### P0: Stale outbound links to v1 pages

**Files:**
- `internal/ui/v2_timeline.go:319` → `"/forensic?ip=%s"` (should be `"/v2/investigate?q=%s"`)
- `internal/ui/v2_providers.go:324` → boundary strip `href="/cloudflare/diff"` (should be `"/v2/cloudflare"`)
- `internal/ui/v2_providers.go:395–405` → `infraProviderHref("cloudflare")` returns `"/cloudflare/diff"`
- `internal/ui/v2_dashboard.go:314` → sidebar nav `{href: "/cloudflare/diff", ...}` and `{href: "/forensic", ...}`

### P1: Dashboard missing situation banner

The dashboard's topbar shows "Dashboard" as a title and three equal-weight stat cards (Platform health, Active threats, Blocked). There is no line that says "HEALTHY · last attack 3m ago" or "INCIDENT ACTIVE · 14 origins from CN/RU." An operator arriving on the dashboard cannot determine current posture without reading all three cards.

### P1: Timeline rows are too verbose by default

Every timeline row renders: timestamp + source pill + action pill + ip pill + result pill + summary text + correlation pill + evidence pill + `<details>` with 6 action links. For dense feeds, this produces a wall of pills. The operator cannot scan; they scan by source color and recency instead.

The `<details>` expansion mechanism already exists but is used for the *wrong level* — the row body is already full; details adds even more. The compact row should show: time + source + action + ip. Details should reveal: result, summary, correlation, evidence, and action links.

### P2: Notes pinned section creates false affordance

`v2_notes.go:66` renders a "Pinned notes" card that always says "No pinned notes yet." Pinning is not implemented. This creates a false expectation of a feature that doesn't exist.

### P2: Keyboard navigation is incomplete

Ctrl+K palette exists on the Dashboard and (via `data-palette-trigger`) on most pages. But the palette only searches for IPs and evidence IDs — there is no way to navigate to a page (e.g., type "health" → go to `/v2/health`). Timeline has a filter bar with full keyboard support. Investigate has a search hero. But the shell sidebar has no keyboard shortcut for direct page navigation.

### P3: Timeline row details link to v1 forensic

The "Open Forensic" action in timeline row details takes the operator to `/forensic?ip=X` — the v1 forensic page. The v2 equivalent is `/v2/investigate?q=X`. This is a jarring v1 drop-out mid-investigation.

### P3: No cross-page context carry

When an operator clicks an IP in the timeline, they land on `/v2/investigate?q=X`. When they click back, they are returned to the top of the timeline — their filter and scroll position are lost. No page carries forward the "current investigation" context (e.g., which IP is under investigation).

---

## Top 10 Recommendations

1. **Migrate Dashboard to `v2Page()`** — eliminates the stale sidebar, ensures consistent shell across all pages, and removes Watchlist/Recent widgets that are no longer part of the shell.

2. **Add a situation banner to the Dashboard** — one line above the stat cards: current posture (HEALTHY / INCIDENT ACTIVE / DEGRADED), last event time, and one primary CTA. Replace "Current posture" section label with an actual machine-readable posture line.

3. **Fix all stale v1 outbound links** — replace `/forensic?ip=X` with `/v2/investigate?q=X` and `/cloudflare/diff` with `/v2/cloudflare` everywhere in the v2 codebase.

4. **Compress timeline rows** — show only timestamp + source + action + ip by default. Move result, summary, correlation, evidence, and action links into the `<details>` expansion. This cuts row height by 40% and makes the feed scannable again.

5. **Make the Ctrl+K palette page-aware** — add page navigation commands: typing "timeline" or "providers" should offer a direct navigation link. Add `g t` (go to timeline), `g i` (go to investigate), `g h` (go to health) keyboard shortcuts via the live script.

6. **Remove or implement the pinned notes section** — either implement actual note pinning (toggle a `pinned` flag on the Note entity) or remove the "Pinned notes" card entirely until it can be wired up.

7. **Add a top situation line to the Dashboard** — derive it from `health.Score`, `threat.TotalEvents`, and `activity.Items[0]`. If score ≥ 95 and no active threats: "HEALTHY". If threats > 0: "ACTIVE — N origins." This one line replaces three stat cards as the primary communication.

8. **Make the timeline histogram interactive** — clicking a bar should filter the timeline to that time bucket. This turns a decorative visual into a navigation affordance. The time bucket calculation is already in `renderV2TimelineHistogram`.

9. **Add freshness timestamps to the live tail** — the dashboard live tail shows HH:MM:SS but no relative age ("3s ago", "2m ago"). Operators reading the tail during an incident need to know if the feed is current. A relative stamp (updated every 30s via JS) is sufficient.

10. **Fix the Cloudflare boundary strip** — the "View diff" link in the Providers boundary strip and the `infraProviderHref` function should point to `/v2/cloudflare`, not `/cloudflare/diff`.

---

## Do-Not-Do List

- Do not add a v1-style watchlist or recents sidebar widget. The shell redesign deliberately removed these.
- Do not make the Dashboard a SPA. The current server-rendered model is correct. JavaScript is appropriate only for the attack map canvas, palette, and live refresh.
- Do not add a "Focus Incident" page as a new route. The Investigate page (PR #152) covers this use case. Two parallel investigation pages add cognitive load.
- Do not add new page-level navigation tabs. The sidebar dot nav is sufficient. Tabs inside pages (like Cloudflare's boundary/sync/lifecycle) are appropriate; top-level nav tabs are not.
- Do not add animations to the sidebar navigation items. The current dot active state is clear without motion.

---

## Interaction Architecture Recommendation

**Recommendation: Keep server-rendered + targeted vanilla JS. Do not introduce a framework.**

| Option | Verdict | Rationale |
|---|---|---|
| Go templates + JS vanilla | ✅ Recommended | Current architecture; low latency, no hydration cost, testable in Go |
| HTML fragments AJAX | ✅ Useful selectively | Already used in providers live refresh; appropriate for row expansion |
| REST JSON minimal | ⚠️ Only for data endpoints | Already used for attack map origins JSON |
| SSE optional | ⚠️ Only if poll becomes painful | Current poll on providers page is sufficient |
| HTMX minimal | ✗ Not needed | The existing vanilla JS is smaller and less opaque |
| Alpine.js minimal | ✗ Not needed | The existing JS handles the same cases without a dependency |
| No framework | ✅ Current state | Preserve |

The palette, live tail auto-refresh, and providers partial refresh are the three pieces that benefit from JS. All three are already implemented as small focused scripts. There is no case for a framework.

---

## Implementation Plan Suggestion

### PR A — Shell consistency and stale link fixes (2 hours)
- Migrate `v2_dashboard.go` to use `v2Page()`
- Fix all stale `/forensic?ip=X` → `/v2/investigate?q=X` links in timeline
- Fix `/cloudflare/diff` → `/v2/cloudflare` in providers boundary strip and `infraProviderHref`
- Update `renderV2BoundaryStrip` to use the correct route

### PR B — Dashboard situation banner + timeline compression (3 hours)
- Add a situation banner above the stat cards on the dashboard
- Compress timeline rows: default compact, `<details>` for full detail + action links
- Add relative freshness timestamps to the live tail

### PR C — Palette enhancement + notes cleanup (2 hours)
- Add page navigation commands to the Ctrl+K palette
- Remove the "Pinned notes" card (or implement actual pinning)
- Make the timeline histogram bars clickable filters
