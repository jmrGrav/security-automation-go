package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

func runOwnershipCLI(ctx context.Context, store ownership.LineageStore, args []string, format string) {
	if store == nil {
		fmt.Println("Error: ownership lineage store unavailable")
		os.Exit(1)
	}
	if len(args) == 0 {
		fmt.Println("Usage: cf-sync -mode ownership [list|show|explain] ...")
		os.Exit(1)
	}
	svc := ownership.NewLineageQueryService(store)
	switch args[0] {
	case "list", "search":
		fs := flag.NewFlagSet("ownership list", flag.ExitOnError)
		scopeID := fs.String("scope_id", "", "filter by scope id")
		resourceID := fs.String("resource_id", "", "filter by resource id")
		beforeCreatedAt := fs.String("before_created_at", "", "cursor: RFC3339Nano created_at from previous page")
		beforeID := fs.String("before_id", "", "cursor: id from previous page")
		limit := fs.Int("limit", 20, "maximum number of entries")
		_ = fs.Parse(args[1:])
		var before time.Time
		if *beforeCreatedAt != "" {
			ts, err := time.Parse(time.RFC3339Nano, *beforeCreatedAt)
			if err != nil {
				fmt.Printf("Error: invalid --before_created_at: %v\n", err)
				os.Exit(1)
			}
			before = ts.UTC()
		}
		items, err := svc.Search(ctx, ownership.LineageSearchOptions{
			ScopeID:         *scopeID,
			ResourceID:      *resourceID,
			BeforeCreatedAt: before,
			BeforeID:        *beforeID,
			Limit:           clampOwnershipLineageCLILimit(*limit),
		})
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if format == "json" {
			renderOwnershipJSON(items)
			return
		}
		for _, ev := range items {
			fmt.Printf("%s %s %s %s %s %s\n", ev.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), ev.ID, ev.ScopeID, ev.ResourceID, ev.EventType, ev.Decision)
		}
	case "show":
		if len(args) < 2 {
			fmt.Println("Usage: cf-sync -mode ownership show <event_id>")
			os.Exit(1)
		}
		ev, found, err := svc.Get(ctx, args[1])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Error: ownership lineage event not found: %s\n", args[1])
			os.Exit(1)
		}
		renderOwnershipJSON(ev)
	case "explain":
		if len(args) < 2 {
			fmt.Println("Usage: cf-sync -mode ownership explain <event_id>")
			os.Exit(1)
		}
		ev, found, err := svc.Get(ctx, args[1])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Error: ownership lineage event not found: %s\n", args[1])
			os.Exit(1)
		}
		renderOwnershipJSON(ownership.ExplainLineageEvent(ev))
	default:
		fmt.Printf("Error: unknown ownership command: %s\n", args[0])
		os.Exit(1)
	}
}

func clampOwnershipLineageCLILimit(limit int) int {
	if limit <= 0 {
		return 20
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func renderOwnershipJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
