# Runtime Invariants

Runtime profiles make startup assumptions explicit. `single-node` preserves the existing local behavior. `strict-ha` fails startup when critical coordination, safety wiring, or explicit component intent is absent.

## Profile matrix

| Runtime Component | single-node | strict-ha | Reason |
| --- | --- | --- | --- |
| Fencing | Required | Required | Refuse stale mutation and rollback writers. |
| Lease | Required | Required | Bind mutation epochs to an owned runtime lease. |
| Leader coordination | Optional | Required | Prevent split-brain HA execution. |
| Audit | Required | Required | Preserve append-only evidence and replay inputs. |
| Telemetry | Required | Required | Surface guard and runtime refusals. |
| Ownership | Required | Required | Keep domain authority checks in the mutation path. |
| Policy Engine | Required | Required | Keep admission policy in the mutation path. |
| OPA | Required | Required | Keep policy bundle evaluation active. |
| Governor | Required | Required | Keep provider rate and mutation limits active. |
| AbuseIPDB reporting intent | Optional | Required | Avoid guessing whether reporting retries are part of HA runtime. |
| Outbox worker | Optional | Required only when `abuseipdb.reporting_enabled=true` | Retry processing must be explicit when reporting is enabled. |
| Outbox lease guard | Optional | Required only when `abuseipdb.reporting_enabled=true` | Retry processing must stop after lease loss. |

## Config semantics

`single-node` keeps the current local runtime semantics. Missing `abuseipdb.reporting_enabled` does not make startup fail.

`strict-ha` requires explicit reporting intent:

| Config | Meaning | Outbox required |
| --- | --- | --- |
| `abuseipdb.reporting_enabled=true` | AbuseIPDB reporting is enabled. | Yes, with lease guard. |
| `abuseipdb.reporting_enabled=false` | AbuseIPDB reporting is explicitly disabled. | No. |
| unset | Intent is unknown. | Startup fails closed. |

## Fail-closed conditions

`strict-ha` startup fails when:

- core safety wiring is missing: fencing, lease, leader coordination, audit, telemetry, ownership, policy engine, OPA, or governor.
- `abuseipdb.reporting_enabled` is unset.
- `abuseipdb.reporting_enabled=true` and the outbox worker is missing.
- `abuseipdb.reporting_enabled=true` and the outbox lease guard is missing.

Startup errors name the missing component, why it is required, and the config that activated the requirement. The automated startup validator is covered by `TestRuntimeWiringInvariants`, `TestStrictHAStartupSuccess`, `TestStrictHAStartupFailsIfAbuseIPDBEnabledAndWorkerMissing`, `TestStrictHAStartupAllowsMissingWorkerWhenAbuseIPDBDisabled`, `TestStrictHAStartupFailsIfWorkerPresentButLeaseGuardMissing`, `TestSingleNodeStartupAllowsMissingWorker`, and `TestStrictHAStartupFailsIfAbuseIPDBReportingIntentMissing`.
