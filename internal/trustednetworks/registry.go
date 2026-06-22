package trustednetworks

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
)

// CrowdSecSpoke is the narrow write/read boundary the registry uses to push
// to a CrowdSec allowlist. Satisfied structurally by *crowdsec.Client.
type CrowdSecSpoke interface {
	ListAllowlist(ctx context.Context, name string) ([]csmodels.AllowlistEntry, error)
	AddAllowlistEntry(ctx context.Context, name string, entry csmodels.AllowlistEntry) error
}

// CloudflareSpoke is the narrow write/read boundary the registry uses to
// push whitelist-mode access rules to Cloudflare. Satisfied structurally by
// *cloudflare.Client.
type CloudflareSpoke interface {
	ListIPAccessRulesByNotePrefix(ctx context.Context, zoneID, prefix string) ([]cfmodels.IPAccessRule, error)
	AddIPAccessRuleWithMode(ctx context.Context, zoneID, value, notes, target, mode string) (string, error)
}

// AuditSink records one audit-trail entry per registry action (push, skip,
// drift detection) so every decision is replayable.
type AuditSink interface {
	RecordTrustedNetworkAction(ctx context.Context, action, target, value, detail string) error
}

// SpokeResult summarizes one spoke's reconcile pass.
type SpokeResult struct {
	Enabled       bool
	Pushed        []string // values newly pushed this pass (enforce mode only)
	AlreadySynced []string
	Drift         []string // values present remotely, tagged as ours, but absent from the registry
	Errors        []string
}

// SyncReport summarizes one full registry reconcile pass across both spokes.
type SyncReport struct {
	Mode          string // "shadow" or "enforce", echoes Registry.Mode at run time
	RegistryCount int
	CrowdSec      SpokeResult
	Cloudflare    SpokeResult
}

// Registry is the hub: it owns the trusted-networks Store and pushes
// additively to each configured spoke. It never lets one spoke's state
// influence the other — both are driven solely from Store.
type Registry struct {
	Store Store

	CrowdSec              CrowdSecSpoke
	CrowdSecAllowlistName string

	Cloudflare       CloudflareSpoke
	CloudflareZoneID string

	// Mode is "shadow" (detect + report only, never mutate a spoke) or
	// "enforce" (additionally push missing entries). Regardless of Mode,
	// the registry NEVER removes a remote entry automatically — the
	// remote-has-it/registry-lacks-it direction is always flag-only, since
	// removing allowlist entries fails toward *more* blocking and an
	// empty/errored registry load must never be read as "remove everything".
	Mode string

	Audit AuditSink

	Logger *slog.Logger

	// Cache, if set, receives the most recent SyncReport so read-only
	// consumers (the UI) can show live status without re-running Sync.
	Cache *ReportCache
}

// EffectiveMode mirrors the ReputationPolicyConfig safety invariant: only
// the literal string "enforce" enables mutation; everything else is shadow.
func (r *Registry) EffectiveMode() string {
	if r.Mode == "enforce" {
		return "enforce"
	}
	return "shadow"
}

// Sync runs one reconcile pass: load the registry, then push additively to
// each enabled spoke and detect (but never remediate) drift in the
// remote-has-it/registry-lacks-it direction.
func (r *Registry) Sync(ctx context.Context) (SyncReport, error) {
	report := SyncReport{Mode: r.EffectiveMode()}
	if r.Store == nil {
		return report, fmt.Errorf("trustednetworks.Registry.Sync: no Store configured")
	}

	entries, err := r.Store.List(ctx)
	if err != nil {
		// Safety guard: a failed registry load must never be treated as an
		// empty registry. Abort the whole pass rather than risk any spoke
		// mutation against a "registry" that is actually just an error.
		return report, fmt.Errorf("trustednetworks.Registry.Sync: list registry: %w", err)
	}
	report.RegistryCount = len(entries)

	if r.CrowdSec != nil && r.CrowdSecAllowlistName != "" {
		report.CrowdSec = r.syncCrowdSec(ctx, entries)
	}
	if r.Cloudflare != nil && r.CloudflareZoneID != "" {
		report.Cloudflare = r.syncCloudflare(ctx, entries)
	}
	if r.Cache != nil {
		r.Cache.Set(report)
	}
	return report, nil
}

func (r *Registry) syncCrowdSec(ctx context.Context, entries []Entry) SpokeResult {
	res := SpokeResult{Enabled: true}
	remote, err := r.CrowdSec.ListAllowlist(ctx, r.CrowdSecAllowlistName)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		r.logWarn("crowdsec allowlist list failed", "allowlist", r.CrowdSecAllowlistName, "error", err)
		return res
	}
	remoteSet := make(map[string]bool, len(remote))
	for _, e := range remote {
		remoteSet[e.Value] = true
	}
	registrySet := make(map[string]bool, len(entries))
	for _, e := range entries {
		registrySet[e.Value] = true
	}

	for _, e := range entries {
		if remoteSet[e.Value] {
			res.AlreadySynced = append(res.AlreadySynced, e.Value)
			continue
		}
		if r.EffectiveMode() != "enforce" {
			continue // shadow mode: detect-only, never push
		}
		comment := r.tagComment(e)
		if err := r.CrowdSec.AddAllowlistEntry(ctx, r.CrowdSecAllowlistName, csmodels.AllowlistEntry{Value: e.Value, Comment: comment}); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", e.Value, err))
			r.logWarn("crowdsec allowlist push failed", "value", e.Value, "error", err)
			continue
		}
		res.Pushed = append(res.Pushed, e.Value)
		r.audit(ctx, "crowdsec_push", r.CrowdSecAllowlistName, e.Value, comment)
	}

	for value, comment := range ownedComments(remote) {
		if !registrySet[value] {
			res.Drift = append(res.Drift, value)
			r.audit(ctx, "crowdsec_drift_detected", r.CrowdSecAllowlistName, value, comment)
		}
	}
	return res
}

func (r *Registry) syncCloudflare(ctx context.Context, entries []Entry) SpokeResult {
	res := SpokeResult{Enabled: true}
	remote, err := r.Cloudflare.ListIPAccessRulesByNotePrefix(ctx, r.CloudflareZoneID, NotePrefix)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		r.logWarn("cloudflare whitelist list failed", "zone", r.CloudflareZoneID, "error", err)
		return res
	}
	remoteSet := make(map[string]bool, len(remote))
	for _, rule := range remote {
		remoteSet[rule.Configuration.Value] = true
	}
	registrySet := make(map[string]bool, len(entries))
	for _, e := range entries {
		registrySet[e.Value] = true
	}

	for _, e := range entries {
		if remoteSet[e.Value] {
			res.AlreadySynced = append(res.AlreadySynced, e.Value)
			continue
		}
		if r.EffectiveMode() != "enforce" {
			continue // shadow mode: detect-only, never push
		}
		notes := r.tagComment(e)
		target := "ip"
		if strings.Contains(e.Value, "/") {
			target = "ip_range"
		}
		if _, err := r.Cloudflare.AddIPAccessRuleWithMode(ctx, r.CloudflareZoneID, e.Value, notes, target, "whitelist"); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", e.Value, err))
			r.logWarn("cloudflare whitelist push failed", "value", e.Value, "error", err)
			continue
		}
		res.Pushed = append(res.Pushed, e.Value)
		r.audit(ctx, "cloudflare_push", r.CloudflareZoneID, e.Value, notes)
	}

	for _, rule := range remote {
		if !registrySet[rule.Configuration.Value] {
			res.Drift = append(res.Drift, rule.Configuration.Value)
			r.audit(ctx, "cloudflare_drift_detected", r.CloudflareZoneID, rule.Configuration.Value, rule.Notes)
		}
	}
	return res
}

func (r *Registry) tagComment(e Entry) string {
	label := e.Label
	if label == "" {
		label = e.Value
	}
	return NotePrefix + label
}

func ownedComments(remote []csmodels.AllowlistEntry) map[string]string {
	owned := make(map[string]string)
	for _, e := range remote {
		if strings.HasPrefix(e.Comment, NotePrefix) {
			owned[e.Value] = e.Comment
		}
	}
	return owned
}

func (r *Registry) audit(ctx context.Context, action, target, value, detail string) {
	if r.Audit == nil {
		return
	}
	if err := r.Audit.RecordTrustedNetworkAction(ctx, action, target, value, detail); err != nil {
		r.logWarn("trusted networks audit record failed", "action", action, "value", value, "error", err)
	}
}

func (r *Registry) logWarn(msg string, args ...any) {
	if r.Logger == nil {
		return
	}
	r.Logger.Warn(msg, args...)
}
