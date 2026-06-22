# Documentation — security-automation-go

## Architecture

| Document | What it covers |
|----------|---------------|
| [ARCHITECTURE.md](architecture/ARCHITECTURE.md) | System design, components, data flow |
| [INVARIANTS.md](architecture/INVARIANTS.md) | Runtime invariants and safety guarantees |
| [RECOVERY_MODEL.md](architecture/RECOVERY_MODEL.md) | Failure modes and recovery strategies |

## Installation

| Document | What it covers |
|----------|---------------|
| [INSTALL.md](installation/INSTALL.md) | Directory layout, file locations, manual install |
| [FIRST_BOOT.md](installation/FIRST_BOOT.md) | First-run setup wizard walkthrough |
| [PACKAGING.md](installation/PACKAGING.md) | .deb packaging and systemd deployment |

## Configuration

| Document | What it covers |
|----------|---------------|
| [CONFIGURATION.md](configuration/CONFIGURATION.md) | Bootstrap file, authentication, secrets layout |
| [AI_PROVIDERS.md](configuration/AI_PROVIDERS.md) | AI provider setup (OpenAI, Anthropic, Gemini) |
| [UI_CONFIGURATION.md](configuration/UI_CONFIGURATION.md) | UI configuration reference and routes |

## Operations

| Document | What it covers |
|----------|---------------|
| [RUNBOOK.md](operations/RUNBOOK.md) | Day-to-day operations |
| [CUTOVER.md](operations/CUTOVER.md) | Production cutover procedure (historical; cf-shadow since decommissioned) |

## Security

| Document | What it covers |
|----------|---------------|
| [SECURITY_MODEL.md](security/SECURITY_MODEL.md) | Overall security model |
| [SECRET_LOADING_MODEL.md](security/SECRET_LOADING_MODEL.md) | Canonical secret paths and loading chain |
| [TRUSTED_NETWORKS.md](security/TRUSTED_NETWORKS.md) | Protected ASN/CIDR classification |
| [UI_SECURITY.md](security/UI_SECURITY.md) | UI authentication security |

## Testing

| Document | What it covers |
|----------|---------------|
| [TESTING.md](testing/TESTING.md) | Test strategy and coverage |
| [COVERAGE_POLICY.md](testing/COVERAGE_POLICY.md) | Coverage requirements |

## Releases

| Document | What it covers |
|----------|---------------|
| [RELEASE_CHECKLIST.md](releases/RELEASE_CHECKLIST.md) | Pre-release gate checklist |

## Archive

| Document | What it covers |
|----------|---------------|
| [PYTHON_LEGACY_SUMMARY.md](archive/PYTHON_LEGACY_SUMMARY.md) | Python legacy summary and migration notes |
