package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"github.com/jm/security-automation-go/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	s := mcpserver.NewServer(mcpserver.Options{
		Name:      "security-automation-mcp",
		Version:   "0.1.0",
		AuditSink: stderrAuditSink{},
	})

	fmt.Fprintln(os.Stderr, "Starting security-automation-mcp on stdio...")
	return s.Run(ctx, &mcp.StdioTransport{})
}

type stderrAuditSink struct{}

func (stderrAuditSink) Record(action string, fields map[string]string) {
	fmt.Fprintf(os.Stderr, "audit action=%s", action)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := fields[k]
		fmt.Fprintf(os.Stderr, " %s=%s", k, v)
	}
	fmt.Fprintln(os.Stderr)
}
