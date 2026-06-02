# Trusted Networks

## Scope

The Trusted Networks Explorer is a read-only operator view over the protected
network registry used by security intelligence and operator review.

## Current behavior

- Route: `/trusted-networks`
- Read-only registry rendering only
- Refresh, diff, and export are dry-run or read-only flows
- No auto-allowlist is performed
- No CrowdSec mutation is performed
- No Cloudflare mutation is performed
- `NoHardBan=true` is the default posture for trusted protected networks
- `HardBanAllowed=false` is rendered explicitly to prevent operator ambiguity

## Registry sources

The registry uses official sources only. Examples currently rendered by the UI:

- Cloudflare
- Google
- Microsoft/Bing
- BetterStack
- UptimeRobot/Pingdom
- OpenAI GPTBot
- OpenAI SearchBot
- GitHub Copilot
- Anthropic

## Safety rules

- ChatGPT-User remains manual review required and too volatile for automatic
  allowlisting.
- Source URLs are rendered for operator verification.
- Allowlist status is shown as not synced unless an explicit sync path exists.
- Export is read-only and must not mutate the registry.
