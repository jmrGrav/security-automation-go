package auth

import (
	"context"
	"errors"
)

type Scope string

const (
	ScopeRuntimeRead      Scope = "runtime.read"
	ScopeRuntimeExecute   Scope = "runtime.execute"
	ScopeRuntimeRollback  Scope = "runtime.rollback"
	ScopeQuarantineManage Scope = "quarantine.manage"
	ScopeAuditRead        Scope = "audit.read"
)

type Identity struct {
	OperatorID string
	Scopes     []Scope
}

type contextKey string

const identityKey contextKey = "api.identity"

func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok
}

type Authenticator struct {
	tokens map[string]Identity
}

func NewAuthenticator(tokens map[string]Identity) *Authenticator {
	return &Authenticator{tokens: tokens}
}

func (a *Authenticator) Authenticate(token string) (Identity, error) {
	id, ok := a.tokens[token]
	if !ok {
		return Identity{}, errors.New("invalid token")
	}
	return id, nil
}

func (id Identity) HasScope(s Scope) bool {
	for _, scope := range id.Scopes {
		if scope == s {
			return true
		}
	}
	return false
}
