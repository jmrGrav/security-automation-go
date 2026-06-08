package auth

import (
	"context"
	"testing"
)

func TestAuthenticator_ValidToken(t *testing.T) {
	a := NewAuthenticator(map[string]Identity{
		"secret-token": {OperatorID: "op-1", Scopes: []Scope{ScopeRuntimeRead}},
	})
	id, err := a.Authenticate("secret-token")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id.OperatorID != "op-1" {
		t.Errorf("expected op-1, got %s", id.OperatorID)
	}
}

func TestAuthenticator_InvalidToken(t *testing.T) {
	a := NewAuthenticator(map[string]Identity{})
	if _, err := a.Authenticate("bad-token"); err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestIdentity_HasScope(t *testing.T) {
	id := Identity{Scopes: []Scope{ScopeRuntimeRead, ScopeAuditRead}}
	if !id.HasScope(ScopeRuntimeRead) {
		t.Error("expected ScopeRuntimeRead")
	}
	if !id.HasScope(ScopeAuditRead) {
		t.Error("expected ScopeAuditRead")
	}
	if id.HasScope(ScopeRuntimeExecute) {
		t.Error("should not have ScopeRuntimeExecute")
	}
	if id.HasScope(ScopeQuarantineManage) {
		t.Error("should not have ScopeQuarantineManage")
	}
}

func TestIdentity_EmptyScopesHasNothing(t *testing.T) {
	id := Identity{}
	for _, s := range []Scope{ScopeRuntimeRead, ScopeRuntimeExecute, ScopeRuntimeRollback, ScopeQuarantineManage, ScopeAuditRead} {
		if id.HasScope(s) {
			t.Errorf("empty identity should not have scope %s", s)
		}
	}
}

func TestWithIdentity_RoundTrip(t *testing.T) {
	want := Identity{OperatorID: "op-2", Scopes: []Scope{ScopeRuntimeExecute}}
	ctx := WithIdentity(context.Background(), want)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("expected identity in context")
	}
	if got.OperatorID != want.OperatorID {
		t.Errorf("expected %s, got %s", want.OperatorID, got.OperatorID)
	}
}

func TestFromContext_Missing(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Fatal("expected no identity in empty context")
	}
}
