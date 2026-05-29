package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

func runEvidenceCLI(ctx context.Context, store reporting.EvidenceStore, args []string, format string) {
	if store == nil {
		fmt.Println("Error: evidence store unavailable")
		os.Exit(1)
	}
	if len(args) == 0 {
		fmt.Println("Usage: cf-sync -mode evidence [list|show|search|explain] ...")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("evidence list", flag.ExitOnError)
		limit := fs.Int("limit", 20, "maximum number of entries")
		offset := fs.Int("offset", 0, "pagination offset")
		_ = fs.Parse(args[1:])
		renderEvidenceList(ctx, store, reporting.EvidenceSearchOptions{Limit: *limit, Offset: *offset}, format)
	case "search":
		fs := flag.NewFlagSet("evidence search", flag.ExitOnError)
		ip := fs.String("ip", "", "filter by IP")
		source := fs.String("source", "", "filter by source")
		decision := fs.String("decision", "", "filter by decision")
		reason := fs.String("reason", "", "filter by suppression reason")
		from := fs.String("from", "", "RFC3339 lower bound")
		to := fs.String("to", "", "RFC3339 upper bound")
		limit := fs.Int("limit", 20, "maximum number of entries")
		offset := fs.Int("offset", 0, "pagination offset")
		_ = fs.Parse(args[1:])
		opts := reporting.EvidenceSearchOptions{
			IP:                *ip,
			Source:            *source,
			Decision:          *decision,
			SuppressionReason: *reason,
			Limit:             *limit,
			Offset:            *offset,
		}
		if *from != "" {
			ts, err := time.Parse(time.RFC3339, *from)
			if err != nil {
				fmt.Printf("Error: invalid --from: %v\n", err)
				os.Exit(1)
			}
			opts.From = ts
		}
		if *to != "" {
			ts, err := time.Parse(time.RFC3339, *to)
			if err != nil {
				fmt.Printf("Error: invalid --to: %v\n", err)
				os.Exit(1)
			}
			opts.To = ts
		}
		renderEvidenceList(ctx, store, opts, format)
	case "show":
		if len(args) < 2 {
			fmt.Println("Usage: cf-sync -mode evidence show <evidence_id>")
			os.Exit(1)
		}
		evidence, found, err := store.Get(ctx, args[1])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Error: evidence not found: %s\n", args[1])
			os.Exit(1)
		}
		renderJSON(evidence)
	case "explain":
		if len(args) < 2 {
			fmt.Println("Usage: cf-sync -mode evidence explain <evidence_id>")
			os.Exit(1)
		}
		evidence, found, err := store.Get(ctx, args[1])
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if !found {
			fmt.Printf("Error: evidence not found: %s\n", args[1])
			os.Exit(1)
		}
		renderJSON(reporting.ExplainEvidence(evidence))
	default:
		fmt.Printf("Error: unknown evidence command: %s\n", args[0])
		os.Exit(1)
	}
}

func renderEvidenceList(ctx context.Context, store reporting.EvidenceStore, opts reporting.EvidenceSearchOptions, format string) {
	evidence, err := store.Search(ctx, opts)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if format == "json" {
		renderJSON(evidence)
		return
	}
	for _, ev := range evidence {
		fmt.Printf("%s %s %s %s %s\n", ev.Timestamp.Format(time.RFC3339), ev.EvidenceID, ev.Source, ev.Decision, ev.IP)
	}
}

func renderJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
