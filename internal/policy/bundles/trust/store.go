package trust

import (
	"crypto/ed25519"
	"github.com/jm/security-automation-go/internal/apperr"
)

// Store provides access to trusted public keys.
type Store struct {
	keys map[string]ed25519.PublicKey
}

func NewStore() *Store {
	return &Store{
		keys: make(map[string]ed25519.PublicKey),
	}
}

func (s *Store) RegisterKey(id string, key ed25519.PublicKey) {
	s.keys[id] = key
}

func (s *Store) GetPublicKey(id string) (ed25519.PublicKey, error) {
	const op = "policy.bundles.trust.GetPublicKey"
	key, ok := s.keys[id]
	if !ok {
		return nil, apperr.Newf(op, "trusted key not found: %s", id)
	}
	return key, nil
}

func (s *Store) AllKeys() map[string]ed25519.PublicKey {
	return s.keys
}
