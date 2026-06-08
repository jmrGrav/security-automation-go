package sqlite

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jm/security-automation-go/internal/apperr"
)

const credentialSecretKeyFile = "secret.key"

func (s *DB) ensureCredentialKey(ctx context.Context) error {
	const op = "storage.sqlite.DB.ensureCredentialKey"
	if len(s.credentialKey) > 0 {
		return nil
	}
	keyPath := filepath.Join(filepath.Dir(s.path), credentialSecretKeyFile)
	key, err := loadCredentialKey(keyPath)
	if err == nil {
		s.credentialKey = key
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return apperr.Wrap(op, err)
	}
	hasRows, err := s.hasCredentialRows(ctx)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if hasRows {
		return apperr.New(op, "credential secret key is missing while encrypted credentials already exist")
	}
	key, err = generateCredentialKey()
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if err := writeCredentialKey(keyPath, key); err != nil {
		return apperr.Wrap(op, err)
	}
	s.credentialKey = key
	return nil
}

func (s *DB) hasCredentialRows(ctx context.Context) (bool, error) {
	var count int
	err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM credential_secrets`).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func loadCredentialKey(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("credential key path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("credential key path is a directory: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential key must be 0600 or stricter")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode credential key: %w", err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("credential key must decode to 32 bytes, got %d", len(decoded))
	}
	out := make([]byte, len(decoded))
	copy(out, decoded)
	return out, nil
}

func generateCredentialKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func writeCredentialKey(path string, key []byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("credential key path is required")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if _, err := tmp.WriteString(encoded + "\n"); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
