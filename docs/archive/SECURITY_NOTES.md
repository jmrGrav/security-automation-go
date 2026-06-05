# Security Notes

## 2026-05-27 - False Positive Resilience

The control-plane now treats false positives as a first-class safety risk.
This follows an operator-facing incident where a misleading AppSec/CrowdSec
signal contributed to complex debugging and loss of confidence.

Immediate structural rules:

- low-confidence detections must bias toward review, quarantine, observe-only, or dry-run
- protected resources must never be auto-banned or propagated broadly
- RFC1918, loopback, management-plane, monitoring, and control-plane targets are protected by default
- cross-scope and tenant-wide propagation require stronger confidence than local soft mitigation
- the system prefers under-blocking over catastrophic over-blocking

## Secret handling

The current Python scripts contain hardcoded Cloudflare secrets in at least two files. The Go migration removes that pattern and requires environment variables instead.

Required practice:

- inject secrets via systemd environment files
- set restrictive permissions on those files
- never commit real tokens
- keep per-service credentials separated when possible

## Transport controls

All outbound HTTP in the Go implementation should use:

- explicit request timeouts
- bounded retries with backoff
- context cancellation
- TLS defaults from the Go standard library

## Command execution

The Python daemon currently shells out to `cscli`. The Go migration should keep that boundary explicit and constrained:

- use `exec.CommandContext`
- bound command runtime with timeouts
- capture stdout/stderr separately
- validate and normalize arguments before execution

## Filesystem access

Several Python features depend on local log and state files under `/var/log`. The Go services should:

- use least-privilege file permissions
- create state directories intentionally
- avoid partial JSON writes by using atomic replace patterns
- document ownership expectations for systemd deployment

## Structured logs

Structured logs improve incident response, but they also create leakage risk. Avoid logging:

- API tokens
- full request bodies when they contain secrets
- unredacted environment dumps

## Compatibility risk

The biggest security risk in this migration is behavioral drift:

- missing allowlist exclusions
- malformed IPv6 normalization
- duplicate or missing Cloudflare bans
- incorrect retention of recidivist or AbuseIPDB state
- over-broad cleanup deletions

For that reason, parity validation matters more than early optimization.
