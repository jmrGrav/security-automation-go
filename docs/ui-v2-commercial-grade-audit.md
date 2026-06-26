# UI v2 Commercial-Grade Product UX Audit

**Date:** 2026-06-27  
**Method:** Full static analysis of all v2 Go render files; evaluated against commercial security product standards (Datadog, Grafana, Chronicle, Elastic Security). Pages audited: `/v2/`, `/v2/timeline`, `/v2/investigate`, `/v2/providers`, `/v2/health`, `/v2/cloudflare`, `/v2/notes`, `/v2/audit`.

---

## Method

All v2 render functions were read and evaluated against commercial security product UX standards. Criteria: three-second comprehension, visual hierarchy clarity, consistent shell identity, density-to-readability ratio, empty state quality, cross-page flow, and micro-interaction completeness.

---

## Score Summary

| Dimension | Score | Notes |
|---|---|---|
| Product identity | 7/10 | Gradient brand, dot nav, dark shell — strong on most pages; broken on Dashboard |
| Three-second comprehension | 4/10 | Dashboard requires scanning 6 sections; others are faster |
| Visual hierarchy | 6/10 | Good on Health/Investigate; flat on Dashboard/Timeline |
| Dashboard command-center quality | 4/10 | Good components but missing situation narrative and uses stale sidebar |
| Timeline investigation density | 6/10 | Good structure; rows too verbose for dense feeds |
| Focus incident / case-file quality | 8/10 | Investigate (PR #152) is excellent |
| Provider experience | 7/10 | Posture strip + row density is solid; stale boundary link is a defect |
| Empty states | 7/10 | Most pages have useful empty state copy and quick actions |
| Cross-page flow | 4/10 | Stale sidebar on Dashboard breaks nav identity; v1 links break flow |
| Micro-interactions | 5/10 | `<details>` expansion, hover states present; no skeleton, no partial refresh outside providers |
| Time awareness | 5/10 | Timestamps on timeline rows; no relative age on live tail |
| Priority/severity signaling | 7/10 | Color system consistent; red=ban/error, orange=warning, green=healthy |
| Commercial polish | 5/10 | Strong surface detail; structural gaps (stale dashboard, false affordances) visible on second look |

---

## Strengths

**Strong product identity on all pages except Dashboard.** The gradient brand square, dot navigation, Hanken Grotesk / JetBrains Mono type pairing, and `#0a0b10` background create a coherent dark security console feel. The animated sign-out button and `⌘K` search shortcut feel intentional and product-quality.

**Investigate page is the strongest page in the product.** Verdict badge (THREAT / PROTECTED / SUSPICIOUS / UNKNOWN), four signal tiles (AbuseIPDB score, confidence, reports, recent events), and two-column forensic/history layout answer the five operator questions and feel like a case file rather than a raw data dump. This is the design direction the rest of the product should move toward.

**Health page pipeline funnel is commercially strong.** Classified → Suppressed → Pending → Reported with proportion bar and percentage breakdowns is exactly how a commercial observability product presents a data pipeline. The "By source" mini-bars underneath are dense but readable.

**Providers posture strip is clean.** The dot + headline + meta line + chip row pattern is production-quality. The provider row grid (status dot, name, model/category, latency, state, actions) matches commercial SaaS standards.

**Color system is consistent and meaningful.** `#4cc79a` = healthy/green, `#f5921e`/`#f5a443` = warning/orange, `#ef5f6b`/`#f08591` = error/red, `#7c6cf2`/`#9b8cff` = system/purple. This is applied correctly across all pages.

---

## Gaps

### P0: Dashboard is not using the v2 shell

**File:** `internal/ui/v2_dashboard.go:385–591`

The dashboard renders a complete standalone `<html>` document with its own sidebar. This sidebar has:
- Old nav entries: `/v2/incident`, `/forensic`, `/cloudflare/diff`, `Classic UI`
- Watchlist widget (removed in PR #153)
- Recent widget (removed in PR #153)
- Old sidebar width (200px instead of 218px)
- No gradient brand area
- No dot navigation style (uses icon + text format instead of dot + text)
- Different body background (#0d0f14 instead of #0a0b10)

An operator on the Dashboard sees a completely different product than on any other page. This breaks product identity at the highest-traffic page.

**Also:** The dashboard sidebar has duplicate nav with hardcoded active state for `/v2/` — so clicking Dashboard always makes the Dashboard link appear active, which is correct, but the implementation is isolated from the shared `v2NavItems` list.

### P0: Stale v1 links embedded in v2 pages

- `internal/ui/v2_timeline.go:319` — `"/forensic?ip=%s"` drops operator into v1
- `internal/ui/v2_providers.go:324` — boundary strip "View diff" links to `/cloudflare/diff`  
- `internal/ui/v2_providers.go:395–405` — `infraProviderHref("cloudflare")` returns `/cloudflare/diff`
- `internal/ui/v2_dashboard.go:311–318` — sidebar nav contains `/forensic`, `/cloudflare/diff`, Classic UI

These are v2-to-v1 leakage points. A commercial product would never link backward to a legacy interface from within the new product.

### P1: Dashboard missing the "command center" moment

The dashboard has all the ingredients (health score, threat count, blocked count, attack map, campaigns, live tail) but no single "command center" moment — no sentence that tells the operator: "right now, you are in situation X."

A commercial command center (Chronicle, Elastic Security, Datadog Security) always has:
1. One large situation line at the top
2. One current signal
3. One primary action

The current dashboard shows three equal-weight stat cards with no hierarchy. The operator must mentally aggregate health% + threat count + blocked count to reconstruct the situation.

**Fix:** Add a situation banner above the stat cards:

```
● HEALTHY  ·  14 origins blocked in the last hour  ·  no active incidents
```
or:
```
● ACTIVE  ·  burst_malicious from CN (7 IPs)  ·  Open Investigation →
```

### P1: Timeline rows degrade at scale

At 200 events (the page limit), each row renders up to 7 pills + a `<details>` expander with 6 action links. The visual density is correct for a 10-event tail but breaks for a 200-event incident investigation. Commercial timeline products (Datadog, Chronicle) use single-line compact rows by default with expand-on-click for details.

The `<details>` HTML element is already used — the fix is moving pills from the always-visible row into the details panel, not adding a new mechanism.

### P2: Notes page has a non-functional "pinned" section

`internal/ui/v2_notes.go:66` renders a "Pinned notes" card that always shows "No pinned notes yet." The `sqlite.Note` type has no `pinned` field and there is no UI affordance to pin a note. A commercial product would not ship a section that cannot be populated. This creates a false affordance and signals an unfinished feature.

**Decision point:** Either implement pinning (add `pinned bool` to the Note type, `TOGGLE pin` endpoint, and UI affordance) or remove the section.

### P2: Missing skeleton/loading states

When a slow database query delays the providers or health page render, the browser shows a blank page until the full server response arrives. Commercial products show skeleton cards (shimmer effect) while content loads. The `skel` and `shimmer` CSS animations are already defined in `v2_shell.go` — they are not yet used.

**Note:** Since the server renders the full page, true skeleton loading requires either a two-phase render (shell → fragment) or a loading overlay. The simplest approach for now is a `<noscript>` + JS-injected loading spinner while the initial page load completes.

### P2: Audit page is unknown — not read

`/v2/audit` was listed in the navigation but was not audited in this report (the file was not read during this audit session). It should be audited in a follow-up pass.

### P3: Command palette is IP-only, not page-aware

The `⌘K` / `Ctrl+K` palette accepts an IP address or evidence ID and routes to `/v2/investigate`. A commercial command palette (Linear, Vercel) also accepts page names, actions, and shortcuts. Adding page navigation (type "health" → go to `/v2/health`) and recent IPs to the palette would make it a true command center control surface.

### P3: No transition or state carry between pages

When an operator clicks an IP from the timeline into Investigate, then presses back, they return to the top of the timeline with no filter or scroll position preserved. Commercial investigation products maintain "breadcrumb context" so an operator can return to their previous state. This is achievable with a `?from=timeline` query parameter and a back-navigation banner.

### P3: Time awareness on live tail is absolute, not relative

The dashboard live tail shows `HH:MM:SS` timestamps. During an incident at 03:00, the operator cannot quickly tell if a `02:58:30` event is 90 seconds ago or 90 minutes ago without mentally calculating. Commercial feeds show relative time ("2m ago", "just now") with the absolute time in a tooltip.

---

## Top 10 Recommendations

1. **Migrate Dashboard to `v2Page()`** — highest-impact, lowest-risk change. Moves the most-visited page into the shared shell, eliminating all sidebar divergence. The dashboard's main content block requires no structural changes.

2. **Fix all stale v1 links** — replace `/forensic?ip=X` with `/v2/investigate?q=X` and `/cloudflare/diff` with `/v2/cloudflare` across all v2 render files. Four call sites. Estimated: 30 minutes.

3. **Add a top situation line to the Dashboard** — derive posture from existing data (`health.Score`, `threat.TotalEvents`, `activity.Items`). Render one sentence above the stat cards. No new data fetching required.

4. **Compress timeline rows to single-line compact** — move result, summary, correlation, and evidence pills into `<details>`. Keep visible: timestamp + source dot + action + ip. This is the standard used by Datadog, Chronicle, and Elastic Security for event feeds.

5. **Remove or implement the pinned notes section** — this is a feature debt marker in plain view of every user. Either ship it or cut it.

6. **Add relative timestamps to the live tail** — add a `data-ts` attribute to each live tail row and a small JS snippet that updates the display to "Xm ago" every 30 seconds. The `palette.js` script can be extended to handle this.

7. **Wire the timeline histogram bars to filter the feed** — each bar already has a `title` attribute with the event count. Adding an `onclick` that sets `?from=EPOCH&to=EPOCH` on the page URL turns a decorative chart into a navigation tool.

8. **Expand the Ctrl+K palette to page navigation** — add 9 entries (one per nav item) that navigate to the corresponding page when selected. Add recent IPs from localStorage as quick-access entries.

9. **Use skeleton animation classes on first render** — apply `.skel` and `.shimmer` CSS classes (already defined) to placeholder content in the dashboard stat cards while the real data loads. Requires a two-step render: shell first, then fragment injection via a lightweight AJAX call.

10. **Fix the Cloudflare boundary strip link** — `infraProviderHref("cloudflare")` and the boundary strip "View diff" button should point to `/v2/cloudflare`. This is a one-line fix in `renderV2BoundaryStrip` and `infraProviderHref`.

---

## Do-Not-Do List

- Do not add a client-side SPA router. The server-rendered model is correct and fast.
- Do not add a "v2 watchlist" sidebar widget. The shell redesign deliberately removed it.
- Do not add animations to nav items. The dot active state is sufficient.
- Do not duplicate the Investigate and Focus Incident as separate pages. One well-designed investigation page (Investigate, PR #152) is better than two overlapping surfaces.
- Do not add a loading spinner that requires JavaScript to dismiss — users without JS or with slow JS parse times should see the rendered page, not a spinner.
- Do not replace the color system. The current color tokens are correct and consistently applied.
- Do not add a v3 dashboard or a "new dashboard" toggle. Fix the existing one.

---

## Interaction Architecture Recommendation

**Recommendation: Server-rendered Go + targeted vanilla JS. No new dependencies.**

The existing architecture is commercially correct:
- Go server renders full pages → fast, secure, testable
- `<details>` for progressive disclosure → no JS required for basic interaction
- Small focused JS files for: attack map canvas (`attack-map.js`), command palette (`palette.js`), providers live refresh (`providers-live.js`), operator timeline (`operator-live.js`)

The only addition needed is a lightweight `freshness.js` (~20 lines) to update relative timestamps on live tail rows.

| Option | Verdict |
|---|---|
| Go templates + vanilla JS | ✅ Keep |
| HTML fragment AJAX | ✅ Selective use (providers already does this correctly) |
| HTMX | ✗ Not needed — providers-live.js is already smaller |
| Alpine.js | ✗ Not needed |
| React/Vue/Svelte | ✗ No |
| SSE | ⚠️ Only if polling becomes visibly slow during incidents |

---

## Implementation Plan Suggestion

### PR A — Shell consistency and link defects (1–2 hours)
- Migrate `v2_dashboard.go` to `v2Page()`
- Fix `/forensic?ip=X` → `/v2/investigate?q=X` in timeline
- Fix `/cloudflare/diff` → `/v2/cloudflare` in providers boundary strip and `infraProviderHref`

### PR B — Dashboard situation banner + timeline density (2–3 hours)
- Add situation banner above stat cards in dashboard
- Compress timeline rows (compact by default, details on expand)
- Add relative timestamps to live tail
- Wire histogram bars to time-range filter

### PR C — Notes cleanup + palette enhancement (1–2 hours)
- Remove pinned notes section (or implement pinning)
- Add page navigation to Ctrl+K palette
- Add recent IPs from localStorage to palette quick-access
