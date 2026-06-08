# Enrichment Providers

## Current slice

This repository slice adds the local enrichment engine, provider configuration,
and operator visibility for UI work. The engine is fail-neutral by default and
keeps all provider lookups behind explicit toggles and short timeouts.

## Provider posture

- DNS/rDNS and ASN enrichment are local providers with fail-neutral behavior.
- AbuseIPDB, Spamhaus, and VirusTotal are represented in config/UI and may be
  enabled or disabled explicitly.
- `/intelligence` performs read-only lookup orchestration and records an audit
  trail event for each inspection.
- `/providers` and `/intelligence` must never render raw API keys, tokens, or
  authorization headers.
- GreyNoise is intentionally omitted per operator direction.
- Provider lookups must stay fail-neutral: a timeout or lookup error contributes
  no hard-ban signal by itself.

## Secrets

- Provider keys are stored in the encrypted SQLite credential store.
- The legacy `/etc/security-automation-go/secrets/` layout is import-only and
  is not used at runtime.
- UI rendering must mask any configured key.
- Logs, evidence, and docs must never contain full keys.

## Ban safety

- No external signal alone may produce a hard ban.
- VirusTotal is for manual forensic review only in this slice.
- Spamhaus report/submission flows must remain separate from lookup.
- Protected networks and trusted forward-confirmed DNS results are allowed to
  reduce score or suppress hard-ban escalation.
- External provider signals alone never hard-ban. Provider failure stays
  neutral, and registry-based trusted network status remains read-only.
