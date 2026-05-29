package scope

import (
	"crypto/sha256"
	"fmt"
)

// RuntimeScope defines a canonical execution partition.
type RuntimeScope struct {
	Tenant      string `json:"tenant"`
	AccountID   string `json:"account_id"`
	ZoneID      string `json:"zone_id"`
	Environment string `json:"environment"`
}

// ID derives a unique, stable identifier for the scope.
func (s RuntimeScope) ID() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%s|%s", s.Tenant, s.AccountID, s.ZoneID, s.Environment)))
	return fmt.Sprintf("%x", h.Sum(nil))[:16] // 16-char prefix is enough for local isolation
}

func (s RuntimeScope) String() string {
	return fmt.Sprintf("%s/%s/%s/%s", s.Tenant, s.Environment, s.AccountID, s.ZoneID)
}

// Registry provides scoped access to runtime components.
type Registry struct {
	BaseDir string
}

func NewRegistry(baseDir string) *Registry {
	return &Registry{BaseDir: baseDir}
}

func (r *Registry) ScopeDir(s RuntimeScope) string {
	return fmt.Sprintf("%s/%s", r.BaseDir, s.ID())
}
