# UI Performance Budgets

This document records the PR1 baseline budgets for the operator UI. The UI is a
server-rendered projection of runtime state; browser code may store presentation
preferences, but must not own business decisions or mutations.

## Timeline

- First page reads must remain windowed by page and limit.
- Unfiltered `/timeline` evidence reads are bounded to `page * limit + 5 * limit`,
  with a minimum of 100 rows and a hard cap of 1000 rows.
- Filtered and exported Timeline projections must not silently miss older
  matching evidence; they read evidence in bounded pages until the persisted
  evidence stream is exhausted.
- Timeline merge results are cached for short refresh bursts only:
  `timelineCacheTTL = 3s`.
- The reference benchmark is `BenchmarkTimelineViewLargeEvidence` in
  `internal/ui/timeline_test.go`.

## Ergonomics

- Compact mode must reduce visible row height enough to show at least 25 percent
  more table rows on a 1920x1080 viewport when rows are present.
- Collapsible panels must preserve state across navigation using local UI
  preference storage only.
- Reference screenshots are produced by
  `tests/smoke/specs/10-ui-v2-pr1.spec.ts`.

## Browser Boundary

- No heavy frontend dependency is allowed for PR1 ergonomics.
- No runtime scoring, enforcement, Cloudflare, CrowdSec, or provider business
  logic may move into browser code.
- Browser code may only manage presentation state such as compact density,
  collapsed panels, copy buttons, live-detail panel display, and refresh wiring.
