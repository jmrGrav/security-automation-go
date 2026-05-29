package scenarios

import (
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/testing/chaos"
)

func GetInitialScenarios() []chaos.Scenario {
	openState := breaker.StateOpen
	success := true
	failure := false
	zero := 0

	return []chaos.Scenario{
		{
			ID:          "429-storm",
			Description: "Cloudflare returns continuous 429 errors",
			Injections: []chaos.Injection{
				{Type: "transport", Target: "*", Probability: 1.0, ErrorCode: 429},
			},
			Expectations: chaos.Expectations{
				BreakerState:      &openState,
				MutationsExecuted: &zero,
				Success:           &failure,
			},
		},
		{
			ID:          "happy-path",
			Description: "Normal execution without any failure",
			Injections:  []chaos.Injection{},
			Expectations: chaos.Expectations{
				Success: &success,
			},
		},
	}
}
