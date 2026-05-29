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

// IPAccessRuleMutator handles mutations for Cloudflare IP Access Rules.
type IPAccessRuleMutator struct {
	transport *transport.Transport
	zoneID    string
}

func NewIPAccessRuleMutator(t *transport.Transport, zoneID string) *IPAccessRuleMutator {
	return &IPAccessRuleMutator{
		transport: t,
		zoneID:    zoneID,
	}
}

func (m *IPAccessRuleMutator) Execute(op execution.MutationOperation) (string, error) {
	return m.ExecuteContext(context.Background(), op)
}

func (m *IPAccessRuleMutator) ExecuteContext(ctx context.Context, op execution.MutationOperation) (string, error) {
	const fn = "cloudflare.mutate.IPAccessRuleMutator.ExecuteContext"

	switch op.Type {
	case "create":
		return m.create(ctx, op)
	case "delete":
		return m.delete(ctx, op)
	default:
		return "", apperr.Newf(fn, "unsupported operation type: %s", op.Type)
	}
}

func (m *IPAccessRuleMutator) create(ctx context.Context, op execution.MutationOperation) (string, error) {
	const fn = "cloudflare.mutate.IPAccessRuleMutator.create"

	path := fmt.Sprintf("/zones/%s/firewall/access_rules/rules", m.zoneID)

	payload, err := json.Marshal(op.Payload)
	if err != nil {
		return "", apperr.Wrap(fn, err)
	}

	res, _, err := transport.MutateAndDecode[models.IPAccessRule](ctx, m.transport, http.MethodPost, path, bytes.NewReader(payload), "")
	if err != nil {
		return "", apperr.Wrap(fn, err)
	}

	return res.ID, nil
}

func (m *IPAccessRuleMutator) delete(ctx context.Context, op execution.MutationOperation) (string, error) {
	const fn = "cloudflare.mutate.IPAccessRuleMutator.delete"

	if op.ProviderObjectID == "" {
		return "", apperr.New(fn, "missing Cloudflare ProviderObjectID for deletion")
	}

	path := fmt.Sprintf("/zones/%s/firewall/access_rules/rules/%s", m.zoneID, op.ProviderObjectID)

	_, _, err := m.transport.Request(ctx, http.MethodDelete, path, nil, nil, "")
	if err != nil {
		return "", apperr.Wrap(fn, err)
	}

	return op.ProviderObjectID, nil
}

func (m *IPAccessRuleMutator) DryRun(op execution.MutationOperation) string {
	return fmt.Sprintf("Cloudflare: %s IP Access Rule %s", op.Type, op.StableIdentityKey)
}
