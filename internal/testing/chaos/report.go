package chaos

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ChaosReport struct {
	TotalScenarios int      `json:"total_scenarios"`
	Passed         int      `json:"passed"`
	Failed         int      `json:"failed"`
	Results        []Result `json:"results"`
}

func (r *Runner) RunSuite(ctx context.Context, scenarios []Scenario) ChaosReport {
	report := ChaosReport{
		TotalScenarios: len(scenarios),
	}

	for _, s := range scenarios {
		res, err := r.RunScenario(ctx, s)
		if err != nil {
			res.Passed = false
			res.Failures = append(res.Failures, fmt.Sprintf("internal runner error: %v", err))
		}

		if res.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, res)
	}

	return report
}

func (cr ChaosReport) String() string {
	var sb strings.Builder
	sb.WriteString("=== cf-sync Chaos Engineering Report ===\n")
	sb.WriteString(fmt.Sprintf("Scenarios Run: %d\n", cr.TotalScenarios))
	sb.WriteString(fmt.Sprintf("Passed:        %d\n", cr.Passed))
	sb.WriteString(fmt.Sprintf("Failed:        %d\n", cr.Failed))
	sb.WriteString("----------------------------------------\n")

	for _, res := range cr.Results {
		status := "PASS"
		if !res.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s (%s)\n", status, res.ScenarioID, res.Duration.Round(time.Millisecond)))
		for _, fail := range res.Failures {
			sb.WriteString(fmt.Sprintf("  - %s\n", fail))
		}
	}

	return sb.String()
}
