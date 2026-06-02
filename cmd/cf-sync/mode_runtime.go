package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/dryrun"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/runtime/diagnostics"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/jm/security-automation-go/internal/snapshot"
	"github.com/jm/security-automation-go/internal/testing/chaos"
	"github.com/jm/security-automation-go/internal/testing/chaos/scenarios"
)

func runCLI(ctx context.Context, orch *pipeline.Orchestrator, zoneID string, dryRun bool, format string) {
	if orch.IsKilled() {
		fmt.Println("Error: Manual kill-switch is active. Mutations are disabled.")
	}
	prov := snapshot.ProvenanceMetadata{GeneratedBy: "cf-sync-cli", GeneratedAt: time.Now().UTC()}
	res, err := orch.DryRun(ctx, zoneID, snapshot.ResourceIPAccessRules, prov)
	if err != nil {
		fmt.Printf("Pipeline failed: %v\n", err)
		os.Exit(1)
	}
	if format == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}
	renderer := dryrun.New()
	fmt.Printf("Snapshot: %d objects, Checksum: %s\n", res.Snapshot.ObjectCount, res.Snapshot.Checksum)
	fmt.Printf("Plan: %d operations\n", res.Planning.OperationCount)
	fmt.Println(renderer.RenderText(res.Actions))
	if !dryRun {
		fmt.Println("Live execution not yet implemented in CLI.")
	}
}

func runStatus(collector *status.Collector, format string) {
	res, err := collector.Collect()
	if err != nil {
		fmt.Printf("Error: Failed to collect status: %v\n", err)
		os.Exit(1)
	}
	if format == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}
	fmt.Println("=== cf-sync Runtime Status ===")
	fmt.Printf("Version:    %s\n", res.Version)
	fmt.Printf("Uptime:     %s (Started at %s)\n", res.Uptime, res.StartedAt.Format(time.RFC3339))
	fmt.Printf("Health:     %s (Consecutive Fails: %d)\n", res.Health.Status, res.Health.ConsecutiveFails)
	fmt.Printf("Breaker:    %s\n", res.Breaker.State)
	fmt.Printf("Lock:       Locked=%v\n", res.Lock.IsLocked)
	fmt.Printf("Quarantine: %d active items\n", res.Quarantine.ActiveItems)
	fmt.Printf("Last Sync:  %s\n", res.Reconciliation.LastSuccessAt)
	if res.Reconciliation.LastPlanID != "" {
		fmt.Printf("Last Plan:  %s\n", res.Reconciliation.LastPlanID)
	}
}

func runDoctor(ctx context.Context, orch *pipeline.Orchestrator, stateStore *state.StateStore, j journal.JournalStore) {
	events, _ := j.List()
	curState, _ := stateStore.Load()
	val := diagnostics.New()
	report := val.ValidateConsistency(events, curState)
	fmt.Printf("Journal Entries: %d\n", report.JournalEntries)
	fmt.Printf("Healthy:         %v\n", report.Healthy)
	if !report.Healthy {
		fmt.Printf("Issues Detected:\n")
		for _, issue := range report.IncompleteRuns {
			fmt.Printf("- Incomplete Run: %s\n", issue)
		}
	}
	fmt.Println("\n=== Running Chaos Engineering Suite ===")
	runner := chaos.NewRunner(orch)
	chaosReport := runner.RunSuite(ctx, scenarios.GetInitialScenarios())
	fmt.Println(chaosReport.String())
}
