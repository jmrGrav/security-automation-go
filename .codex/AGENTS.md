# Codex Review Instructions

This file complements the repository root `AGENTS.md`.
Read both before starting a review.

## Mandatory Skills

For architecture and code review work, use the installed Brooks skillset:

- `brooks-review` for PR-style findings
- `brooks-audit` for structure and dependency review
- `brooks-health` for broad read-only quality assessment
- `brooks-test` for test-suite quality review

Do not fall back to generic CRUD-oriented review heuristics.

## System Context

Treat this repository as a production-grade distributed security control-plane with:

- event-sourced runtime behavior
- deterministic replay
- SQLite WAL persistence
- HA coordination
- fencing tokens
- rollback orchestration
- forensic replay and audit lineage
- OPA/policy governance
- multi-worker scheduling
- checkpoint-aware recovery

## Priority Review Targets

Focus review effort on:

- replay determinism
- race conditions
- goroutine lifecycle leaks
- WAL consistency
- checkpoint lineage
- rollback ancestry
- split-brain risks
- fencing monotonicity and correctness
- event ordering
- recovery correctness
- append-only guarantees
- corruption handling

## Review Constraints

Do not recommend:

- microservice decomposition
- ORM rewrites
- Kubernetes migration
- cosmetic refactors detached from correctness

Bias toward:

- correctness
- determinism
- recovery safety
- HA safety
- auditability

## Suggested Commands

Broad review:

```bash
codex review . --agent .codex/AGENTS.md
```

Targeted runtime review:

```bash
codex review internal/runtime internal/storage/sqlite internal/policy \
  --agent .codex/AGENTS.md
```

Forensic runtime review:

```bash
codex review . \
  --agent .codex/AGENTS.md \
  --context .codex/FORENSIC_REVIEW.md
```
