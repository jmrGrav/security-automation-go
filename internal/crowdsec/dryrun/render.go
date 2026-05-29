package dryrun

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// Renderer produces human-readable and serializable dry-run summaries.
type Renderer struct{}

func New() *Renderer {
	return &Renderer{}
}

// RenderText produces a multi-line string for console output.
func (r *Renderer) RenderText(actions []models.ExecutableOperation) string {
	if len(actions) == 0 {
		return "No actions planned."
	}

	var sb strings.Builder
	sb.WriteString("CrowdSec Dry-Run Execution Plan:\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	for i, a := range actions {
		sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, a.Type, a.StableIdentityKey))

		if a.Scope != "" {
			sb.WriteString(fmt.Sprintf("   Target: %s (%s)\n", a.Value, a.Scope))
		} else {
			sb.WriteString(fmt.Sprintf("   Target: %s\n", a.Value))
		}

		if a.Scenario != "" {
			sb.WriteString(fmt.Sprintf("   Scenario: %s\n", a.Scenario))
		}
		if a.Reason != "" {
			sb.WriteString(fmt.Sprintf("   Reason: %s\n", a.Reason))
		}
		sb.WriteString(fmt.Sprintf("   Origin: %s\n", a.OriginatingOpID))
		sb.WriteString("\n")
	}

	return sb.String()
}

// RenderJSON produces a JSON representation of the summary.
func (r *Renderer) RenderJSON(actions []models.ExecutableOperation) (string, error) {
	summary := models.ExecutionSummary{
		TotalActions: len(actions),
		Actions:      actions,
	}

	for _, a := range actions {
		if a.Type == models.ActionAddDecision {
			summary.Additions++
		} else if a.Type == models.ActionDeleteDecision {
			summary.Deletions++
		}
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
