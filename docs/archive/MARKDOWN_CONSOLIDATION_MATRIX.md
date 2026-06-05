# Markdown Consolidation Matrix

This matrix categorizes all markdown files in the repository to reduce sprawl and prepare for the v1.1.1 release.

| File | Category | Justification |
| :--- | :--- | :--- |
| `ARCHITECTURE.md` | KEEP | Core architectural documentation. |
| `CONTRIBUTING.md` | KEEP | Standard project file. |
| `SECURITY.md` | KEEP | Critical security policy. |
| `README.md` | KEEP | Main project entry point. |
| `CUTOVER_RUNBOOK.md` | KEEP | Primary operational document for upcoming cutover. |
| `ACCURACY_POLICY.md` | KEEP | Reference for system behavior expectations. |
| `TESTING.md` | KEEP | Guide for running and writing tests. |
| `SHADOW_MODE_REPORT.md` | ARCHIVE | Historical evidence of shadow campaign success. |
| `GO_NO_GO_ASSESSMENT.md` | ARCHIVE | Snapshot of release readiness at a point in time. |
| `NOTIFIER_REPLACEMENT_AUDIT.md` | ARCHIVE | Historical context on parity with the Python notifier. |
| `RUNTIME_WIRING_AUDIT.md` | ARCHIVE | Verification of dependency injection and component wiring. |
| `REPOSITORY_INTEGRITY_REPORT.md` | ARCHIVE | Historical check of repo structure and hygiene. |
| `TEST_GAP_REPORT.md` | ARCHIVE | Historical analysis of test coverage gaps. |
| `CUTOVER_READINESS_REPORT.md` | ARCHIVE | Assessment of readiness for cutover. |
| `RISK_ANALYSIS.md` | ARCHIVE | Historical risk assessment. |
| `SESSION_STATUS.md` | DELETE | Ephemeral session tracking; no longer operationally useful. |
| `TEST_COVERAGE_AUDIT.md` | ARCHIVE | Detailed audit of test coverage. |
| `DECISIONS.md` | ARCHIVE | Log of architectural decisions; valuable for history. |
| `MIGRATION_PROGRESS.md` | ARCHIVE | Tracking of the migration from Python to Go. |
| `ARCHITECTURE_TARGET_AUDIT.md` | ARCHIVE | Historical audit against target architecture. |
| `SECURITY_NOTES.md` | ARCHIVE | Historical security posture notes. |
| `COMPATIBILITY_CHECKLIST.md` | ARCHIVE | Check of compatibility with legacy environment. |
| `DEPLOYMENT_PLAN.md` | ARCHIVE | Early deployment strategy; superseded by runbooks. |
| `PYTHON_PARITY_REPORT.md` | ARCHIVE | Parity analysis between Python and Go implementations. |
| `MIGRATION_PLAN.md` | ARCHIVE | Original migration strategy. |
| `GO_LIVE_CHECKLIST.md` | MERGE | Merge into `docs/runbooks/CUTOVER_RUNBOOK.md`. |
| `PYTHON_FEATURE_MATRIX.md` | ARCHIVE | Comparison matrix of features. |
| `docs/hardening/final-status-and-roadmap.md` | KEEP | Future engineering direction. |
| `docs/AI_PROVIDER_CONFIGURATION.md` | KEEP | Setup instructions for AI features. |
| `docs/TEST_HARDENING_REPORT.md` | ARCHIVE | Evidence of test suite improvements. |
| `docs/TEST_COVERAGE_AUDIT.md` | ARCHIVE | Duplicate audit. |
| `docs/AI_ASSISTANCE.md` | KEEP | Guide for AI-assisted development. |
| `docs/security/ENRICHMENT_PROVIDERS.md` | KEEP | Security detail on enrichment. |
| `docs/security/AI_EXPLAIN_GATEWAY.md` | KEEP | Security detail on AI gateway. |
| `docs/security/TRUSTED_NETWORKS.md` | KEEP | Security detail on trusted networks. |
| `docs/AI_PROVIDER_ACTIVATION_REPORT.md` | ARCHIVE | Report on initial AI feature launch. |
| `docs/migration/python36-gap-analysis.md` | ARCHIVE | Technical analysis of environment constraints. |
| `docs/INVARIANTS.md` | KEEP | Fundamental system invariants. |
| `docs/AI_PROVIDER_ACTIVATION.md` | KEEP | High-level activation guide. |
| `docs/COVERAGE_POLICY.md` | KEEP | Standard for testing requirements. |
| `docs/operations/AUTHENTICATION.md` | KEEP | UI auth documentation. |
| `docs/operations/SHADOW_RUNBOOK.md` | KEEP | Maintenance of shadow mode. |
| `docs/operations/RUNBOOK.md` | KEEP | Daily operations guide. |
| `docs/operations/PRE_SHADOW_AI_ACCEPTANCE.md` | ARCHIVE | Acceptance evidence. |
| `docs/operations/FIRST_BOOT.md` | KEEP | Initialization instructions. |
| `docs/operations/RELEASE_CUTOVER_CHECKLIST.md` | KEEP | Checklist for final cutover. |
| `docs/operations/PRE_SHADOW_ACCEPTANCE.md` | ARCHIVE | Acceptance evidence. |
| `docs/operations/UI_CONFIGURATION.md` | KEEP | UI setup. |
| `docs/operations/UI_SECURITY.md` | KEEP | UI security implementation detail. |
| `docs/operations/SHADOW_LAUNCH_CHECKLIST.md` | ARCHIVE | Pre-launch checklist. |
| `docs/operations/AI_PROVIDER_OPERATOR.md` | KEEP | AI feature operations. |
| `docs/operations/UI_FEATURES.md` | KEEP | User guide for UI. |

## Proposed Directory Structure

```
docs/
├── architecture/
│   ├── ARCHITECTURE.md
│   └── INVARIANTS.md
├── security/
│   ├── SECURITY.md
│   ├── ENRICHMENT_PROVIDERS.md
│   ├── AI_EXPLAIN_GATEWAY.md
│   ├── TRUSTED_NETWORKS.md
│   └── docs/operations/UI_SECURITY.md (move)
├── runbooks/
│   ├── CUTOVER_RUNBOOK.md
│   ├── SHADOW_RUNBOOK.md
│   ├── RUNBOOK.md
│   ├── FIRST_BOOT.md
│   └── RELEASE_CUTOVER_CHECKLIST.md
├── audits/
├── releases/
├── testing/
│   ├── TESTING.md
│   ├── COVERAGE_POLICY.md
│   └── ACCURACY_POLICY.md
├── migration/
├── configuration/
│   ├── AI_PROVIDER_CONFIGURATION.md
│   ├── AI_PROVIDER_ACTIVATION.md
│   ├── UI_CONFIGURATION.md
│   └── AI_PROVIDER_OPERATOR.md
└── archive/
```
