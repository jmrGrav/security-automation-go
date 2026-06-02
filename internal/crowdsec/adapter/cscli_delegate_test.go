package adapter_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/adapter"
	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

type recordingDecisionWriter struct {
	calls []string
	err   error
}

func (w *recordingDecisionWriter) AddIPDecision(_ context.Context, ip, duration, reason string) error {
	w.calls = append(w.calls, "add-ip:"+ip+":"+duration+":"+reason)
	return w.err
}

func (w *recordingDecisionWriter) AddRangeDecision(_ context.Context, cidr, duration, reason string) error {
	w.calls = append(w.calls, "add-range:"+cidr+":"+duration+":"+reason)
	return w.err
}

func (w *recordingDecisionWriter) DeleteIPDecision(_ context.Context, ip string) error {
	w.calls = append(w.calls, "delete-ip:"+ip)
	return w.err
}

func (w *recordingDecisionWriter) DeleteRangeDecision(_ context.Context, cidr string) error {
	w.calls = append(w.calls, "delete-range:"+cidr)
	return w.err
}

func TestCSCLIExecutorDelegatesToCrowdSecWriter(t *testing.T) {
	writer := &recordingDecisionWriter{}
	exec := adapter.NewCSCLIExecutorWithWriter(writer, 5*time.Second)

	result, err := exec.Execute(context.Background(), models.Batch{
		ID: "delegated",
		Actions: []models.ExecutableOperation{
			{Type: models.ActionAddDecision, Scope: "ip", Value: "1.2.3.4", Duration: "4h", Reason: "test", OriginatingOpID: "op-add-ip"},
			{Type: models.ActionAddDecision, Scope: "range", Value: "10.0.0.0/24", Duration: "24h", Reason: "range", OriginatingOpID: "op-add-range"},
			{Type: models.ActionDeleteDecision, Scope: "ip", Value: "5.6.7.8", OriginatingOpID: "op-del-ip"},
			{Type: models.ActionDeleteDecision, Scope: "range", Value: "192.0.2.0/24", OriginatingOpID: "op-del-range"},
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.Success {
		t.Fatalf("delegated batch should succeed: %#v", result.Results)
	}

	want := []string{
		"add-ip:1.2.3.4:4h:test",
		"add-range:10.0.0.0/24:24h:range",
		"delete-ip:5.6.7.8",
		"delete-range:192.0.2.0/24",
	}
	if strings.Join(writer.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("delegation mismatch:\n got %v\nwant %v", writer.calls, want)
	}
	for _, res := range result.Results {
		if strings.Contains(res.Audit.RawCommand, "cscli ") {
			t.Fatalf("delegating executor must not expose or run raw cscli command: %#v", res.Audit)
		}
	}
}

func TestCSCLIExecutorValidationFailsBeforeDelegation(t *testing.T) {
	writer := &recordingDecisionWriter{}
	exec := adapter.NewCSCLIExecutorWithWriter(writer, 5*time.Second)

	result, err := exec.Execute(context.Background(), models.Batch{
		ID: "bad",
		Actions: []models.ExecutableOperation{{
			Type: models.ActionAddDecision, Scope: "ip", Value: "not-an-ip", Duration: "4h", Reason: "x", OriginatingOpID: "op",
		}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Success {
		t.Fatal("invalid operation must fail batch")
	}
	if len(writer.calls) != 0 {
		t.Fatalf("invalid operation must not reach writer, got %v", writer.calls)
	}
	if result.Results[0].Error != "value is not a valid IP address" {
		t.Fatalf("unexpected validation error: %q", result.Results[0].Error)
	}
}
