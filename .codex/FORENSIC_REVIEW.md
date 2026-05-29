# Forensic Review Context

Review only for:

- replay divergence
- checkpoint consistency
- WAL durability
- corruption recovery
- event ordering
- fencing token monotonicity
- rollback lineage
- recovery determinism
- goroutine leaks
- scheduler starvation
- HA split-brain risks

Assume:

- production-grade distributed control-plane
- failures are partial, concurrent, and stateful
- audit history must remain append-only
- replay and recovery behavior must be deterministic

Ignore:

- generic style-only suggestions
- architecture churn that does not improve correctness
- framework migration advice unrelated to runtime safety
