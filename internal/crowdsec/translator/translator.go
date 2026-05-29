package translator

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Translator converts generic reconciliation operations into CrowdSec-specific actions.
type Translator struct{}

func New() *Translator {
	return &Translator{}
}

// Translate converts a generic Plan into a list of CrowdSec executable operations.
func (t *Translator) Translate(plan *reconciliation.Plan, provenance snapshot.ProvenanceMetadata) ([]models.ExecutableOperation, error) {
	const op = "crowdsec.translator.Translate"

	if plan == nil {
		return nil, apperr.New(op, "plan is required")
	}

	actions := make([]models.ExecutableOperation, 0, len(plan.Operations))
	for _, genOp := range plan.Operations {
		action, err := t.translateOperation(genOp, provenance)
		if err != nil {
			return nil, apperr.Wrapf(op, err, "failed to translate operation %s", genOp.OperationID)
		}
		actions = append(actions, action)
	}

	// Deterministic ordering for execution and dry-run
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].Type != actions[j].Type {
			return actions[i].Type < actions[j].Type
		}
		return actions[i].StableIdentityKey < actions[j].StableIdentityKey
	})

	return actions, nil
}

func (t *Translator) translateOperation(genOp reconciliation.Operation, provenance snapshot.ProvenanceMetadata) (models.ExecutableOperation, error) {
	const op = "crowdsec.translator.translateOperation"

	action := models.ExecutableOperation{
		OriginatingOpID:   genOp.OperationID,
		StableIdentityKey: genOp.TargetID, // We use StableIdentityKey as TargetID in planner
		Provenance:        provenance,
		CreatedAt:         time.Now().UTC(),
	}

	switch genOp.Type {
	case reconciliation.OpCreate:
		action.Type = models.ActionAddDecision
		if err := t.mapPayload(genOp, &action); err != nil {
			return action, apperr.Wrap(op, err)
		}
	case reconciliation.OpDelete:
		action.Type = models.ActionDeleteDecision
		if err := t.mapIdentity(genOp, &action); err != nil {
			return action, apperr.Wrap(op, err)
		}
	case reconciliation.OpUpdate:
		// CrowdSec updates are usually Delete + Create, but for now we might
		// not support direct updates or map them to a specific strategy.
		return action, apperr.New(op, "update operations not yet supported for CrowdSec")
	default:
		return action, apperr.Newf(op, "unsupported operation type: %s", genOp.Type)
	}

	action.ExecutionID = t.deriveExecutionID(action)
	return action, nil
}

func (t *Translator) mapPayload(genOp reconciliation.Operation, action *models.ExecutableOperation) error {
	const op = "crowdsec.translator.mapPayload"

	payload, ok := genOp.Payload.(map[string]any)
	if !ok {
		return apperr.New(op, "payload is not a map")
	}

	// Logic depends on ResourceType
	switch genOp.ResourceType {
	case string(snapshot.ResourceIPAccessRules):
		config, _ := payload["configuration"].(map[string]any)
		action.Scope, _ = config["target"].(string)
		action.Value, _ = config["value"].(string)
		action.Reason = "synchronized from Cloudflare access rule"
		action.Scenario = "manual-sync"
		action.Duration = "24h" // Default duration if not specified
	default:
		return apperr.Newf(op, "unsupported resource type: %s", genOp.ResourceType)
	}

	return nil
}

func (t *Translator) mapIdentity(genOp reconciliation.Operation, action *models.ExecutableOperation) error {
	const op = "crowdsec.translator.mapIdentity"

	// For deletion, we need to extract scope/value from the StableIdentityKey or stored metadata
	// SIK format for IP rules: ip:target:value:mode
	// For now, simple parsing or metadata lookup.

	// TODO: Use a proper SIK parser
	action.Value = genOp.TargetID // Placeholder

	return nil
}

func (t *Translator) deriveExecutionID(a models.ExecutableOperation) string {
	sum := sha256.Sum256([]byte(string(a.Type) + ":" + a.StableIdentityKey + ":" + a.OriginatingOpID))
	return "exec-" + hex.EncodeToString(sum[:8])
}
