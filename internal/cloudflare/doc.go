// Package cloudflare contains typed interfaces and models for the Cloudflare
// APIs used by the current Python stack.
//
// The package exists because Cloudflare is the main integration point shared by
// all three Python scripts: access rules, account lists, and GraphQL firewall
// events. Centralizing these contracts now reduces migration risk and keeps
// retry/pagination behavior consistent later.
package cloudflare
