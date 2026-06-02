# AI Explain Gateway

This repository reserves an AI explain gateway for operator-only, read-only explanations.

## Scope

The future gateway will explain existing operator evidence only:

- timeline events
- audit events
- provider health
- security intelligence results
- trusted network entries
- Cloudflare diff findings
- replay checkpoints
- recovery status
- drift findings

It will not execute commands, edit files, mutate SQLite, invoke systemd, call sudo, or trigger provider mutations.

## Future providers

The gateway is expected to support these read-only explain providers later:

- OpenAI
- Anthropic Claude
- Google Gemini

The current repository only reserves the package layout and security boundaries. No provider calls are implemented yet, and no API keys are required for the scaffolding.

The companion `security-automation-mcp` entrypoint is also read-only and stdio-first:

- it exposes read-only projections only
- it must redact sensitive values before returning JSON
- it must not depend on mutation, execution, rollback, or SQLite writer paths
- every tool call should be audited as a read-only event

## Security boundary

Any future provider integration must remain explain-only:

- no shell execution
- no host mutation
- no provider mutation
- no file writes
- no SQLite writes
- no direct UI-to-provider calls

Redaction, context building, caching, and provider routing stay server-side and must be audited before activation.
Request-controlled prompt limits are capped by server policy, cache keys are hashed, and provider routing must remain read-only even when a provider is selected.
Quota posture is expiry-aware: providers that were marked exhausted or cooling down can re-enter rotation after their recorded reset window elapses.
Context building is cancellation-aware so request aborts and deadlines can stop the read-only audit scan early instead of continuing work after the caller is gone.
