package mutate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/execution"
)

type FirewallListMutator struct {
	transport *transport.Transport
	accountID string
}

func NewFirewallListMutator(t *transport.Transport, accountID string) *FirewallListMutator {
	return &FirewallListMutator{transport: t, accountID: accountID}
}

func (m *FirewallListMutator) Execute(op execution.MutationOperation) (string, error) {
	return m.ExecuteContext(context.Background(), op)
}

func (m *FirewallListMutator) ExecuteContext(ctx context.Context, op execution.MutationOperation) (string, error) {
	const fn = "cloudflare.mutate.FirewallListMutator.ExecuteContext"

	switch op.Type {
	case "create":
		path := fmt.Sprintf("/accounts/%s/rules/lists", m.accountID)
		payload, _ := json.Marshal(op.Payload)
		res, _, err := transport.MutateAndDecode[models.FirewallList](ctx, m.transport, http.MethodPost, path, bytes.NewReader(payload), "")
		if err != nil {
			return "", apperr.Wrap(fn, err)
		}
		return res.ID, nil
	case "delete":
		if op.ProviderObjectID == "" {
			return "", apperr.New(fn, "missing ProviderObjectID")
		}
		path := fmt.Sprintf("/accounts/%s/rules/lists/%s", m.accountID, op.ProviderObjectID)
		_, _, err := m.transport.Request(ctx, http.MethodDelete, path, nil, nil, "")
		return op.ProviderObjectID, apperr.Wrap(fn, err)
	default:
		return "", apperr.Newf(fn, "unsupported type: %s", op.Type)
	}
}

func (m *FirewallListMutator) DryRun(op execution.MutationOperation) string {
	return fmt.Sprintf("Cloudflare: %s Firewall List %s", op.Type, op.StableIdentityKey)
}

type RulesetMutator struct {
	transport *transport.Transport
	zoneID    string
}

func NewRulesetMutator(t *transport.Transport, zoneID string) *RulesetMutator {
	return &RulesetMutator{transport: t, zoneID: zoneID}
}

func (m *RulesetMutator) Execute(op execution.MutationOperation) (string, error) {
	return m.ExecuteContext(context.Background(), op)
}

func (m *RulesetMutator) ExecuteContext(ctx context.Context, op execution.MutationOperation) (string, error) {
	const fn = "cloudflare.mutate.RulesetMutator.ExecuteContext"

	// Rulesets are often patched or updated via PUT to manage the full list of rules.
	// For "safe phase-aware updates", we might be updating the rules list of a phase-ruleset.

	if op.ProviderObjectID == "" {
		return "", apperr.New(fn, "missing Ruleset ProviderObjectID")
	}

	path := fmt.Sprintf("/zones/%s/rulesets/%s", m.zoneID, op.ProviderObjectID)

	switch op.Type {
	case "update":
		payload, _ := json.Marshal(op.Payload)
		res, _, err := transport.MutateAndDecode[models.Ruleset](ctx, m.transport, http.MethodPatch, path, bytes.NewReader(payload), op.ExpectedETag)
		if err != nil {
			return "", apperr.Wrap(fn, err)
		}
		return res.ID, nil
	default:
		return "", apperr.Newf(fn, "unsupported ruleset operation: %s", op.Type)
	}
}

func (m *RulesetMutator) DryRun(op execution.MutationOperation) string {
	return fmt.Sprintf("Cloudflare: %s Ruleset/Rule %s", op.Type, op.StableIdentityKey)
}

type FirewallListItemMutator struct {
	transport *transport.Transport
	accountID string
}

func NewFirewallListItemMutator(t *transport.Transport, accountID string) *FirewallListItemMutator {
	return &FirewallListItemMutator{transport: t, accountID: accountID}
}

func (m *FirewallListItemMutator) Execute(op execution.MutationOperation) (string, error) {
	return m.ExecuteContext(context.Background(), op)
}

func (m *FirewallListItemMutator) ExecuteContext(ctx context.Context, op execution.MutationOperation) (string, error) {
	const fn = "cloudflare.mutate.FirewallListItemMutator.ExecuteContext"

	// We expect the parent list ID to be in metadata or part of SIK
	// For now, let's assume it's passed or we derive it.
	listID := "" // TODO: Extract parent ListID

	switch op.Type {
	case "create":
		path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", m.accountID, listID)
		payload, _ := json.Marshal([]any{op.Payload}) // Cloudflare expects an array of items
		_, _, err := m.transport.Request(ctx, http.MethodPost, path, nil, bytes.NewReader(payload), "")
		return op.StableIdentityKey, apperr.Wrap(fn, err)
	case "delete":
		path := fmt.Sprintf("/accounts/%s/rules/lists/%s/items", m.accountID, listID)
		// Cloudflare DELETE items usually takes a body with IDs/IPs
		payload, _ := json.Marshal(map[string]any{"items": []any{map[string]any{"id": op.ProviderObjectID}}})
		_, _, err := m.transport.Request(ctx, http.MethodDelete, path, nil, bytes.NewReader(payload), "")
		return op.ProviderObjectID, apperr.Wrap(fn, err)
	default:
		return "", apperr.Newf(fn, "unsupported type: %s", op.Type)
	}
}

func (m *FirewallListItemMutator) DryRun(op execution.MutationOperation) string {
	return fmt.Sprintf("Cloudflare: %s Firewall List Item %s", op.Type, op.StableIdentityKey)
}
