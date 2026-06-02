package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/security/audit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type stubAudit struct {
	entries []audit.AuditEntry
}

func (s stubAudit) Entries() []audit.AuditEntry {
	return append([]audit.AuditEntry(nil), s.entries...)
}

type captureSink struct {
	records []recordedEvent
}

type recordedEvent struct {
	action string
	fields map[string]string
}

func (s *captureSink) Record(action string, fields map[string]string) {
	if s == nil {
		return
	}
	copyFields := make(map[string]string, len(fields))
	for k, v := range fields {
		copyFields[k] = v
	}
	s.records = append(s.records, recordedEvent{action: action, fields: copyFields})
}

func TestRedactJSONRedactsSensitiveFields(t *testing.T) {
	in := []byte(`{"authorization":"Bearer secret-token","nested":{"api_key":"abc123","safe":"ok"}}`)
	got := string(RedactJSON(in))
	for _, forbidden := range []string{"secret-token", "abc123", "Bearer "} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redacted json leaked %q: %s", forbidden, got)
		}
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("expected redactions in %s", got)
	}
}

func TestServerAuditsAndBoundsToolCalls(t *testing.T) {
	entries := make([]audit.AuditEntry, 60)
	for i := range entries {
		entries[i] = audit.AuditEntry{
			Timestamp:   "2026-06-01T09:00:00Z",
			Action:      "login_success",
			Target:      "Bearer secret-token",
			Result:      "ok",
			Correlation: "corr-1",
			EventID:     "evt-1",
		}
	}
	reader := stubAudit{entries: entries}
	sink := &captureSink{}
	handler := &toolHandler{sink: sink, audit: reader}

	gotLogs, _, err := handler.handleGetAuditLogs(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("get_audit_logs: %v", err)
	}
	logsJSON := gotLogs.Content[0].(*mcp.TextContent).Text
	if strings.Contains(logsJSON, "secret-token") {
		t.Fatalf("audit logs leaked secret: %s", logsJSON)
	}
	if strings.Count(logsJSON, "login_success") != 50 {
		t.Fatalf("expected bounded audit log projection, got %s", logsJSON)
	}

	gotTimeline, _, err := handler.handleGetTimeline(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("get_timeline: %v", err)
	}
	timelineJSON := gotTimeline.Content[0].(*mcp.TextContent).Text
	if strings.Contains(timelineJSON, "secret-token") {
		t.Fatalf("timeline leaked secret: %s", timelineJSON)
	}
	if strings.Count(timelineJSON, "login_success") != 50 {
		t.Fatalf("expected bounded timeline projection, got %s", timelineJSON)
	}

	_, _, err = handler.handleGetRuntimeStatus(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("get_runtime_status: %v", err)
	}

	if len(sink.records) != 3 {
		t.Fatalf("expected 3 audited tool calls, got %d", len(sink.records))
	}
	for _, rec := range sink.records {
		if rec.fields["source"] != "security-automation-mcp" {
			t.Fatalf("expected source annotation, got %+v", rec)
		}
		if rec.fields["action"] == "" {
			t.Fatalf("missing action annotation, got %+v", rec)
		}
		if rec.fields["result"] == "" {
			t.Fatalf("missing result annotation, got %+v", rec)
		}
	}
}
