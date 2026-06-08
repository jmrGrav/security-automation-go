package sqlite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialStore_RoundTripEncrypted(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	store := NewCredentialStore(db)

	if err := store.Put(context.Background(), "cloudflare.api_token", "super-secret-token", true); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := store.Get(context.Background(), "cloudflare.api_token")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("expected credential to exist")
	}
	if got.Value != "super-secret-token" {
		t.Fatalf("expected decrypted secret, got %q", got.Value)
	}
	if !got.Enabled {
		t.Fatal("expected enabled flag to round-trip")
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "runtime.db"))
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if dbInfo, err := os.Stat(filepath.Join(dir, "runtime.db")); err != nil {
		t.Fatalf("stat db: %v", err)
	} else if got := dbInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected runtime.db mode 0600, got %04o", got)
	}
	if bytes.Contains(data, []byte("super-secret-token")) {
		t.Fatal("plaintext secret leaked into SQLite file")
	}
	keyPath := filepath.Join(dir, "secret.key")
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat master key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected master key mode 0600, got %04o", keyInfo.Mode().Perm())
	}
	if keyData, err := os.ReadFile(keyPath); err == nil && bytes.Contains(keyData, []byte("super-secret-token")) {
		t.Fatal("plaintext secret leaked into master key file")
	}
}

func TestCredentialStore_MissingMasterKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	db, err := New(dir)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	store := NewCredentialStore(db)
	if err := store.Put(context.Background(), "cloudflare.api_token", "secret-for-reopen", true); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "secret.key")); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	_, err = New(dir)
	if err == nil {
		t.Fatal("expected missing master key to fail closed")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "secret key") {
		t.Fatalf("expected clear secret-key error, got %v", err)
	}
}

func TestCredentialStore_ImportLegacyIdempotent(t *testing.T) {
	dir := t.TempDir()
	legacyDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(legacyDir, "cloudflare_api_token"), []byte("CF_API_TOKEN=cf-legacy-token"), 0o600); err != nil {
		t.Fatalf("write cloudflare legacy file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "abuseipdb_api_key"), []byte("ABUSEIPDB_KEY=abuse-legacy-token"), 0o600); err != nil {
		t.Fatalf("write abuseipdb legacy file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "openai_api_key"), []byte("openai-legacy-token"), 0o600); err != nil {
		t.Fatalf("write openai legacy file: %v", err)
	}

	db, err := New(dir)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	store := NewCredentialStore(db)

	imported, err := store.ImportLegacyDir(context.Background(), legacyDir)
	if err != nil {
		t.Fatalf("ImportLegacyDir: %v", err)
	}
	if imported != 3 {
		t.Fatalf("expected 3 imported credentials, got %d", imported)
	}

	cf, ok, err := store.Get(context.Background(), "cloudflare.api_token")
	if err != nil {
		t.Fatalf("Get cloudflare: %v", err)
	}
	if !ok || cf.Value != "cf-legacy-token" {
		t.Fatalf("cloudflare import mismatch: ok=%v value=%q", ok, cf.Value)
	}
	openai, ok, err := store.Get(context.Background(), "ai.openai.api_key")
	if err != nil {
		t.Fatalf("Get openai: %v", err)
	}
	if !ok || openai.Value != "openai-legacy-token" {
		t.Fatalf("openai import mismatch: ok=%v value=%q", ok, openai.Value)
	}

	importedAgain, err := store.ImportLegacyDir(context.Background(), legacyDir)
	if err != nil {
		t.Fatalf("ImportLegacyDir second pass: %v", err)
	}
	if importedAgain != 0 {
		t.Fatalf("expected idempotent import to skip second pass, got %d", importedAgain)
	}
}
