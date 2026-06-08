package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// CredentialRecord is a decrypted credential value plus metadata.
type CredentialRecord struct {
	Name            string
	Value           string
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastValidatedAt sql.NullTime
}

// CredentialStore persists operator-configured credentials in encrypted SQLite rows.
type CredentialStore struct {
	db *DB
}

func NewCredentialStore(db *DB) *CredentialStore {
	return &CredentialStore{db: db}
}

func (s *CredentialStore) Set(ctx context.Context, name, value string, enabled bool) error {
	return s.Put(ctx, name, value, enabled)
}

func (s *CredentialStore) Lookup(ctx context.Context, name string) (string, bool, error) {
	rec, ok, err := s.Get(ctx, name)
	if err != nil || !ok {
		return "", ok, err
	}
	return rec.Value, true, nil
}

func (s *CredentialStore) Put(ctx context.Context, name, value string, enabled bool) error {
	const op = "storage.sqlite.CredentialStore.Put"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return apperr.New(op, "credential name is required")
	}
	if strings.TrimSpace(value) == "" {
		return apperr.New(op, "credential value is required")
	}
	ciphertext, nonce, err := s.encrypt(name, []byte(strings.TrimSpace(value)))
	if err != nil {
		return apperr.Wrap(op, err)
	}
	now := time.Now().UTC()
	_, err = s.db.Conn().ExecContext(ctx,
		`INSERT INTO credential_secrets (name, ciphertext, nonce, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
		 ciphertext = excluded.ciphertext,
		 nonce = excluded.nonce,
		 enabled = excluded.enabled,
		 updated_at = excluded.updated_at`,
		name, ciphertext, nonce, boolToInt(enabled), now, now,
	)
	return apperr.Wrap(op, err)
}

func (s *CredentialStore) Get(ctx context.Context, name string) (CredentialRecord, bool, error) {
	const op = "storage.sqlite.CredentialStore.Get"
	name = strings.TrimSpace(name)
	if name == "" {
		return CredentialRecord{}, false, apperr.New(op, "credential name is required")
	}
	var (
		ciphertext []byte
		nonce      []byte
		enabled    int
		createdAt  time.Time
		updatedAt  time.Time
		validated  sql.NullTime
	)
	err := s.db.Conn().QueryRowContext(ctx,
		`SELECT ciphertext, nonce, enabled, created_at, updated_at, last_validated_at
		 FROM credential_secrets WHERE name = ?`,
		name,
	).Scan(&ciphertext, &nonce, &enabled, &createdAt, &updatedAt, &validated)
	if err == sql.ErrNoRows {
		return CredentialRecord{}, false, nil
	}
	if err != nil {
		return CredentialRecord{}, false, apperr.Wrap(op, err)
	}
	plain, err := s.decrypt(name, ciphertext, nonce)
	if err != nil {
		return CredentialRecord{}, false, apperr.Wrap(op, err)
	}
	return CredentialRecord{
		Name:            name,
		Value:           string(plain),
		Enabled:         enabled != 0,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		LastValidatedAt: validated,
	}, true, nil
}

func (s *CredentialStore) Delete(ctx context.Context, name string) error {
	const op = "storage.sqlite.CredentialStore.Delete"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return apperr.New(op, "credential name is required")
	}
	_, err := s.db.Conn().ExecContext(ctx, `DELETE FROM credential_secrets WHERE name = ?`, name)
	return apperr.Wrap(op, err)
}

func (s *CredentialStore) MarkValidated(ctx context.Context, name string, validatedAt time.Time) error {
	const op = "storage.sqlite.CredentialStore.MarkValidated"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return apperr.New(op, "credential name is required")
	}
	_, err := s.db.Conn().ExecContext(ctx,
		`UPDATE credential_secrets SET last_validated_at = ?, updated_at = ? WHERE name = ?`,
		validatedAt.UTC(), time.Now().UTC(), name,
	)
	return apperr.Wrap(op, err)
}

func (s *CredentialStore) ImportLegacyDir(ctx context.Context, legacyDir string) (int, error) {
	const op = "storage.sqlite.CredentialStore.ImportLegacyDir"
	if strings.TrimSpace(legacyDir) == "" {
		return 0, apperr.New(op, "legacy directory is required")
	}
	if imported, err := s.legacyImportDone(ctx); err != nil {
		return 0, apperr.Wrap(op, err)
	} else if imported {
		return 0, nil
	}

	imported := 0
	for _, spec := range legacyCredentialSpecs() {
		path := filepath.Join(legacyDir, spec.fileName)
		value, ok, err := readLegacyCredentialValue(path, spec.parser)
		if err != nil {
			return 0, apperr.Wrapf(op, err, "import %s", spec.name)
		}
		if !ok {
			continue
		}
		if err := s.Put(ctx, spec.name, value, true); err != nil {
			return 0, apperr.Wrapf(op, err, "import %s", spec.name)
		}
		imported++
	}
	if imported == 0 {
		return 0, nil
	}
	if err := s.setLegacyImportDone(ctx, time.Now().UTC()); err != nil {
		return 0, apperr.Wrap(op, err)
	}
	return imported, nil
}

func (s *CredentialStore) encrypt(name string, plain []byte) ([]byte, []byte, error) {
	if len(s.db.credentialKey) != 32 {
		return nil, nil, errors.New("credential master key not loaded")
	}
	block, err := aes.NewCipher(s.db.credentialKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := randRead(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(name))
	return ciphertext, nonce, nil
}

func (s *CredentialStore) decrypt(name string, ciphertext, nonce []byte) ([]byte, error) {
	if len(s.db.credentialKey) != 32 {
		return nil, errors.New("credential master key not loaded")
	}
	block, err := aes.NewCipher(s.db.credentialKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(name))
	if err != nil {
		return nil, err
	}
	return plain, nil
}

type legacyCredentialSpec struct {
	name     string
	fileName string
	parser   func([]byte) (string, bool, error)
}

func legacyCredentialSpecs() []legacyCredentialSpec {
	return []legacyCredentialSpec{
		{name: "cloudflare.api_token", fileName: "cloudflare_api_token", parser: parseEnvValue("CF_API_TOKEN")},
		{name: "abuseipdb.api_key", fileName: "abuseipdb_api_key", parser: parseEnvValue("ABUSEIPDB_KEY")},
		{name: "betterstack.source_token", fileName: "betterstack_source_token", parser: parseEnvValue("BETTERSTACK_SOURCE_TOKEN")},
		{name: "ai.openai.api_key", fileName: "openai_api_key", parser: parseRawValue},
		{name: "ai.anthropic.api_key", fileName: "anthropic_api_key", parser: parseRawValue},
		{name: "ai.gemini.api_key", fileName: "gemini_api_key", parser: parseRawValue},
	}
}

func readLegacyCredentialValue(path string, parser func([]byte) (string, bool, error)) (string, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	value, ok, err := parser(raw)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	return value, true, nil
}

func parseEnvValue(key string) func([]byte) (string, bool, error) {
	return func(raw []byte) (string, bool, error) {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if strings.TrimSpace(k) != key {
				continue
			}
			return strings.TrimSpace(v), true, nil
		}
		return "", false, fmt.Errorf("missing %s assignment", key)
	}
}

func parseRawValue(raw []byte) (string, bool, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", false, fmt.Errorf("credential file is empty")
	}
	return value, true, nil
}

func (s *CredentialStore) legacyImportDone(ctx context.Context) (bool, error) {
	const op = "storage.sqlite.CredentialStore.legacyImportDone"
	var value string
	err := s.db.Conn().QueryRowContext(ctx,
		`SELECT value FROM credential_meta WHERE key = ?`,
		"legacy_imported_at",
	).Scan(&value)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, apperr.Wrap(op, err)
	}
	return strings.TrimSpace(value) != "", nil
}

func (s *CredentialStore) setLegacyImportDone(ctx context.Context, at time.Time) error {
	const op = "storage.sqlite.CredentialStore.setLegacyImportDone"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO credential_meta (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		"legacy_imported_at", at.UTC().Format(time.RFC3339), at.UTC(),
	)
	return apperr.Wrap(op, err)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func randRead(b []byte) (int, error) {
	return crand.Read(b)
}
