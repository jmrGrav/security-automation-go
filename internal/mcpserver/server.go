package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Options defines the dependencies for the MCP server.
type Options struct {
	Name        string
	Version     string
	AuditSink   audit.AuditSink
	AuditReader audit.AuditReader
}

type toolHandler struct {
	sink  audit.AuditSink
	audit audit.AuditReader
}

// NewServer creates a new read-only MCP server.
func NewServer(opts Options) *mcp.Server {
	s := mcp.NewServer(
		&mcp.Implementation{
			Name:    opts.Name,
			Version: opts.Version,
		},
		nil,
	)

	h := &toolHandler{sink: opts.AuditSink, audit: opts.AuditReader}

	// Register tools using the SDK's functional style
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_runtime_status",
		Description: "Get the current read-only runtime status of the security automation system.",
	}, h.handleGetRuntimeStatus)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_audit_logs",
		Description: "Read the latest audit log entries (redacted).",
	}, h.handleGetAuditLogs)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_timeline",
		Description: "Read the security event timeline (redacted).",
	}, h.handleGetTimeline)

	return s
}

func (h *toolHandler) handleGetRuntimeStatus(ctx context.Context, req *mcp.CallToolRequest, args any) (*mcp.CallToolResult, any, error) {
	status := map[string]string{
		"status":  "healthy",
		"version": "0.1.0",
		"mode":    "read-only",
	}
	raw, _ := json.Marshal(status)
	h.record("get_runtime_status", map[string]string{"result": "ok"})
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(raw)},
		},
	}, nil, nil
}

func (h *toolHandler) handleGetAuditLogs(ctx context.Context, req *mcp.CallToolRequest, args any) (*mcp.CallToolResult, any, error) {
	if h.audit == nil {
		h.record("get_audit_logs", map[string]string{"result": "unconfigured"})
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Audit reader not configured"},
			},
		}, nil, nil
	}
	entries := h.audit.Entries()
	if len(entries) > 50 {
		entries = entries[len(entries)-50:]
	}
	raw, _ := json.Marshal(entries)
	redacted := RedactJSON(raw)
	h.record("get_audit_logs", map[string]string{"result": "ok", "entries_returned": fmt.Sprintf("%d", len(entries))})
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(redacted)},
		},
	}, nil, nil
}

func (h *toolHandler) handleGetTimeline(ctx context.Context, req *mcp.CallToolRequest, args any) (*mcp.CallToolResult, any, error) {
	if h.audit == nil {
		h.record("get_timeline", map[string]string{"result": "unconfigured"})
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Audit reader not configured"},
			},
		}, nil, nil
	}
	entries := h.audit.Entries()
	if len(entries) > 50 {
		entries = entries[len(entries)-50:]
	}
	raw, _ := json.Marshal(entries)
	redacted := RedactJSON(raw)
	h.record("get_timeline", map[string]string{"result": "ok", "entries_returned": fmt.Sprintf("%d", len(entries))})
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(redacted)},
		},
	}, nil, nil
}

func (h *toolHandler) record(action string, fields map[string]string) {
	if h == nil || h.sink == nil {
		return
	}
	if fields == nil {
		fields = map[string]string{}
	}
	fields["source"] = "security-automation-mcp"
	fields["action"] = action
	h.sink.Record(action, fields)
}
