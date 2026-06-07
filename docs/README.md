# Documentation Index — security-automation-go

Entry point for operators and contributors. Find any document in under 2 minutes.

---

## Architecture

| Document | What it covers |
|----------|---------------|
| [ARCHITECTURE.md](architecture/ARCHITECTURE.md) | System design, components, data flow |
| [INVARIANTS.md](architecture/INVARIANTS.md) | Runtime invariants and safety guarantees |
| [RECOVERY_MODEL.md](architecture/RECOVERY_MODEL.md) | Failure modes and recovery strategies |
| [roadmap.md](architecture/roadmap.md) | Feature roadmap |
| [AGENTS.md](architecture/AGENTS.md) | Agentic workflow guidelines |

---

## Installation & First Boot

| Document | What it covers |
|----------|---------------|
| [INSTALL_LAYOUT.md](INSTALL_LAYOUT.md) | Directory layout, file locations, permissions |
| [FIRST_BOOT.md](FIRST_BOOT.md) | First-run setup wizard walkthrough |
| [SETUP_WIZARD.md](SETUP_WIZARD.md) | Setup wizard reference |

---

## Configuration

| Document | What it covers |
|----------|---------------|
| [AI_PROVIDER_CONFIGURATION.md](configuration/AI_PROVIDER_CONFIGURATION.md) | AI provider setup (OpenAI, Anthropic, Gemini) |
| [AI_PROVIDER_ACTIVATION.md](configuration/AI_PROVIDER_ACTIVATION.md) | Activating AI providers at runtime |
| [AI_PROVIDER_OPERATOR.md](configuration/AI_PROVIDER_OPERATOR.md) | Operator guide for AI providers |
| [AUTHENTICATION.md](configuration/AUTHENTICATION.md) | UI authentication and password management |
| [UI_CONFIGURATION.md](configuration/UI_CONFIGURATION.md) | UI configuration reference |
| [UI_FEATURES.md](configuration/UI_FEATURES.md) | UI feature overview |

---

## Security

| Document | What it covers |
|----------|---------------|
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | Overall security model |
| [SECRET_LOADING_MODEL.md](security/SECRET_LOADING_MODEL.md) | **Canonical secret paths and loading chain** |
| [SECURITY.md](security/SECURITY.md) | Security policy and disclosures |
| [TRUSTED_NETWORKS.md](security/TRUSTED_NETWORKS.md) | Protected ASN/CIDR classification |
| [UI_SECURITY.md](security/UI_SECURITY.md) | UI authentication security |
| [AI_EXPLAIN_GATEWAY.md](security/AI_EXPLAIN_GATEWAY.md) | AI gateway security controls |
| [ENRICHMENT_PROVIDERS.md](security/ENRICHMENT_PROVIDERS.md) | External provider security model |

---

## Operations

| Document | What it covers |
|----------|---------------|
| [STARTUP_WARNINGS.md](operations/STARTUP_WARNINGS.md) | Startup diagnostic messages |
| [PACKAGING_FOUNDATION.md](operations/PACKAGING_FOUNDATION.md) | .deb packaging and systemd deployment |
| [AI_ASSISTANCE.md](AI_ASSISTANCE.md) | AI-assisted operations guide |

---

## Runbooks

| Document | What it covers |
|----------|---------------|
| [RUNBOOK.md](runbooks/RUNBOOK.md) | Day-to-day operations |
| [FIRST_BOOT.md](runbooks/FIRST_BOOT.md) | First boot startup procedure |
| [CUTOVER_RUNBOOK.md](runbooks/CUTOVER_RUNBOOK.md) | Production cutover procedure |
| [SHADOW_RUNBOOK.md](runbooks/SHADOW_RUNBOOK.md) | Shadow mode operation |
| [RELEASE_CUTOVER_CHECKLIST.md](runbooks/RELEASE_CUTOVER_CHECKLIST.md) | Release cutover checklist |

---

## Releases

| Document | What it covers |
|----------|---------------|
| [RELEASE_CHECKLIST.md](releases/RELEASE_CHECKLIST.md) | **Pre-release gate checklist** |
| [V1_5_RELEASE_VALIDATION_PIPELINE_REPORT.md](releases/V1_5_RELEASE_VALIDATION_PIPELINE_REPORT.md) | V1.5 validation report (current release) |
| [V1_4_BREAKING_CHANGES.md](releases/V1_4_BREAKING_CHANGES.md) | V1.4 breaking changes and migration guide |
| [UPGRADE_COMPATIBILITY_REPORT.md](releases/UPGRADE_COMPATIBILITY_REPORT.md) | Cross-version compatibility |
| [RELEASE_NOTES_V1_2_0_RC1.md](releases/RELEASE_NOTES_V1_2_0_RC1.md) | V1.2.0-rc1 release notes |
| [RELEASE_NOTES_v1.1.1.md](releases/RELEASE_NOTES_v1.1.1.md) | V1.1.1 release notes |
| [V1_1_1_HARDENING_REPORT.md](releases/V1_1_1_HARDENING_REPORT.md) | V1.1.1 hardening report |
| [POST_AUDIT_DOCUMENTATION_CLEANUP_REPORT.md](releases/POST_AUDIT_DOCUMENTATION_CLEANUP_REPORT.md) | Post-audit cleanup record |

---

## Audits

| Document | What it covers |
|----------|---------------|
| [ADMIN_TOKEN_FINAL_VERDICT.md](audits/ADMIN_TOKEN_FINAL_VERDICT.md) | Admin token security verdict |
| [SHADOW_FINAL_ASSESSMENT.md](audits/SHADOW_FINAL_ASSESSMENT.md) | Shadow mode final assessment |
| [PRODUCTION_SAFETY_AUDIT.md](audits/PRODUCTION_SAFETY_AUDIT.md) | Production safety audit |

---

## Testing

| Document | What it covers |
|----------|---------------|
| [TESTING.md](testing/TESTING.md) | Test strategy and coverage |
| [COVERAGE_POLICY.md](testing/COVERAGE_POLICY.md) | Coverage requirements |
| [ACCURACY_POLICY.md](testing/ACCURACY_POLICY.md) | Detection accuracy policy |

---

## Archive

Historical reports, superseded documents, and completed sprints.
These are frozen records — do not edit.

> [`docs/archive/`](archive/) — 30+ historical reports

Notable archive entries:
- [LIVE_CONFIGURATION_AUDIT.md](archive/LIVE_CONFIGURATION_AUDIT.md) — live runtime state snapshot (2026-06-06)
- [ARCHITECTURE_CONSISTENCY_AUDIT.md](archive/ARCHITECTURE_CONSISTENCY_AUDIT.md) — path consistency audit
- [SECRET_LOADING_MODEL.md](security/SECRET_LOADING_MODEL.md) — **moved to security/ (still active reference)**

---

## Secret Path Quick Reference

**Canonical install root: `/etc/security-automation-go/`**

| Secret | Path | Format |
|--------|------|--------|
| Cloudflare API token | `/etc/security-automation-go/secrets/cloudflare_api_token` | `CF_API_TOKEN=<value>` |
| AbuseIPDB key | `/etc/security-automation-go/secrets/abuseipdb_api_key` | `ABUSEIPDB_KEY=<value>` |
| BetterStack token | `/etc/security-automation-go/secrets/betterstack_source_token` | `BETTERSTACK_SOURCE_TOKEN=<value>` |
| OpenAI key | `/etc/security-automation-go/secrets/openai_api_key` | raw value |
| Anthropic key | `/etc/security-automation-go/secrets/anthropic_api_key` | raw value |
| Gemini key | `/etc/security-automation-go/secrets/gemini_api_key` | raw value |
| Admin password | `/etc/security-automation-go/secrets/admin_password` | bcrypt hash |
| Initial password | `/etc/security-automation-go/runtime/initial-admin-password` | plaintext (one-time) |

All secret files: `root:root 0600`. See [SECRET_LOADING_MODEL.md](security/SECRET_LOADING_MODEL.md) for the full loading chain.

> **Note:** The directory `/etc/security-automation/` (without `-go`) exists on disk as a legacy path
> from a pre-V1.4 deployment. The code does not read from it. Operator migration required.
