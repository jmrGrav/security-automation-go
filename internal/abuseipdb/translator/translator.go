package translator

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Translator converts reconciliation operations into AbuseIPDB reports.
type Translator struct{}

func New() *Translator {
	return &Translator{}
}

// Translate maps generic reconciliation creations to AbuseIPDB executable reports.
func (t *Translator) Translate(plan *reconciliation.Plan) ([]models.ExecutableReport, error) {
	const op = "abuseipdb.translator.Translate"

	if plan == nil {
		return nil, apperr.New(op, "plan is required")
	}

	var actions []models.ExecutableReport
	for _, genOp := range plan.Operations {
		// Only creations represent new detections to report
		if genOp.Type != reconciliation.OpCreate {
			continue
		}

		action, err := t.translateOperation(genOp)
		if err != nil {
			// In reporting, we might want to skip malformed ones instead of failing the batch
			continue
		}
		actions = append(actions, action)
	}

	return actions, nil
}

func (t *Translator) translateOperation(genOp reconciliation.Operation) (models.ExecutableReport, error) {
	const op = "abuseipdb.translator.translateOperation"

	payload, ok := genOp.Payload.(map[string]any)
	if !ok {
		return models.ExecutableReport{}, apperr.New(op, "payload is not a map")
	}

	// We only report IP-based rules
	if genOp.ResourceType != string(snapshot.ResourceIPAccessRules) {
		return models.ExecutableReport{}, apperr.Newf(op, "unsupported resource type: %s", genOp.ResourceType)
	}

	config, _ := payload["configuration"].(map[string]any)
	target, _ := config["target"].(string)
	if target != "ip" {
		return models.ExecutableReport{}, apperr.Newf(op, "unsupported target type: %s", target)
	}

	ip, _ := config["value"].(string)
	notes, _ := payload["notes"].(string)

	action := models.ExecutableReport{
		OriginatingOpID:   genOp.OperationID,
		StableIdentityKey: genOp.TargetID,
		IP:                ip,
		Categories:        t.mapCategories(notes),
		Comment:           t.buildCanonicalComment(notes, genOp.OperationID),
		CreatedAt:         time.Now().UTC(),
	}

	action.ExecutionID = t.deriveExecutionID(action)
	return action, nil
}

func (t *Translator) mapCategories(notes string) string {
	// Simple mapping based on CrowdSec scenario names in notes
	notes = strings.ToLower(notes)
	var cats []string

	if strings.Contains(notes, "ssh") {
		cats = append(cats, "22")
	}
	if strings.Contains(notes, "http") || strings.Contains(notes, "wordpress") {
		cats = append(cats, "21", "19")
	}
	if strings.Contains(notes, "bruteforce") {
		cats = append(cats, "18")
	}

	if len(cats) == 0 {
		return "21" // Generic Web Abuse
	}
	return strings.Join(cats, ",")
}

func (t *Translator) deriveExecutionID(a models.ExecutableReport) string {
	sum := sha256.Sum256([]byte("abuseipdb:" + a.IP + ":" + a.OriginatingOpID))
	return "report-" + hex.EncodeToString(sum[:8])
}

func (t *Translator) buildCanonicalComment(notes string, opID string) string {
	source := abuseformat.SourceCrowdSecWAF
	lower := strings.ToLower(notes)
	uris := []string{"/"}
	abuseType := "suspicious_probe"
	categories := []string{"Bad Web Bot"}
	if strings.Contains(lower, "openresty") {
		source = abuseformat.SourceOpenRestyWAF
	}
	if strings.Contains(lower, "wordpress") || strings.Contains(lower, "xmlrpc") || strings.Contains(lower, "wp-login") {
		abuseType = "wordpress_probe"
		categories = []string{"Web App Attack", "Bad Web Bot"}
		if strings.Contains(lower, "xmlrpc") {
			uris = []string{"/xmlrpc.php"}
		} else {
			uris = []string{"/wp-login.php"}
		}
	}
	return abuseformat.Build(abuseformat.Input{
		Source:     source,
		Hits:       1,
		WindowSec:  300,
		Action:     "block",
		AbuseType:  abuseType,
		Categories: categories,
		RuleID:     opID,
		URIs:       uris,
		Confidence: 0.70,
	})
}
