package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// SetupStore persists setup wizard progress and named UI settings.
type SetupStore struct {
	db *DB
}

func NewSetupStore(db *DB) *SetupStore {
	return &SetupStore{db: db}
}

// GetCurrentStep returns the current wizard step (1–9). Returns 1 if no row exists.
func (s *SetupStore) GetCurrentStep(ctx context.Context) (int, error) {
	const op = "storage.sqlite.SetupStore.GetCurrentStep"
	var step int
	err := s.db.Conn().QueryRowContext(ctx, `SELECT current_step FROM setup_state WHERE id = 1`).Scan(&step)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, apperr.Wrap(op, err)
	}
	return step, nil
}

// SetCurrentStep persists the current wizard step.
func (s *SetupStore) SetCurrentStep(ctx context.Context, step int) error {
	const op = "storage.sqlite.SetupStore.SetCurrentStep"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO setup_state (id, current_step, updated_at)
		 VALUES (1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET current_step = excluded.current_step, updated_at = excluded.updated_at`,
		step, time.Now().UTC(),
	)
	return apperr.Wrap(op, err)
}

// IsComplete reports whether the setup wizard has been completed.
func (s *SetupStore) IsComplete(ctx context.Context) (bool, error) {
	const op = "storage.sqlite.SetupStore.IsComplete"
	var completedAt sql.NullTime
	err := s.db.Conn().QueryRowContext(ctx, `SELECT completed_at FROM setup_state WHERE id = 1`).Scan(&completedAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, apperr.Wrap(op, err)
	}
	return completedAt.Valid, nil
}

// MarkComplete marks setup as complete with the current timestamp.
func (s *SetupStore) MarkComplete(ctx context.Context) error {
	const op = "storage.sqlite.SetupStore.MarkComplete"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO setup_state (id, current_step, completed_at, updated_at)
		 VALUES (1, 9, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET current_step = excluded.current_step, completed_at = excluded.completed_at, updated_at = excluded.updated_at`,
		now, now,
	)
	return apperr.Wrap(op, err)
}

// GetSetting retrieves a named setting value. Returns ("", false, nil) when not set.
func (s *SetupStore) GetSetting(ctx context.Context, key string) (string, bool, error) {
	const op = "storage.sqlite.SetupStore.GetSetting"
	var val string
	err := s.db.Conn().QueryRowContext(ctx, `SELECT value FROM ui_settings WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, apperr.Wrap(op, err)
	}
	return val, true, nil
}

// SetSetting upserts a named setting.
func (s *SetupStore) SetSetting(ctx context.Context, key, value string) error {
	const op = "storage.sqlite.SetupStore.SetSetting"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO ui_settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().UTC(),
	)
	return apperr.Wrap(op, err)
}

// GetAuthEpoch returns the current auth epoch from ui_settings (default 0 if not set).
func (s *SetupStore) GetAuthEpoch(ctx context.Context) (int64, error) {
	const op = "storage.sqlite.SetupStore.GetAuthEpoch"
	v, ok, err := s.GetSetting(ctx, "auth_epoch")
	if err != nil {
		return 0, apperr.Wrap(op, err)
	}
	if !ok {
		return 0, nil
	}
	epoch, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, apperr.Wrapf(op, err, "parse auth_epoch %q", v)
	}
	return epoch, nil
}

// IncrementAuthEpoch increments and persists the auth epoch, returning the new value.
func (s *SetupStore) IncrementAuthEpoch(ctx context.Context) (int64, error) {
	const op = "storage.sqlite.SetupStore.IncrementAuthEpoch"
	epoch, err := s.GetAuthEpoch(ctx)
	if err != nil {
		return 0, apperr.Wrap(op, err)
	}
	epoch++
	if err := s.SetSetting(ctx, "auth_epoch", fmt.Sprintf("%d", epoch)); err != nil {
		return 0, apperr.Wrap(op, err)
	}
	return epoch, nil
}

// GetPasswordChangeRequired returns true when the operator must change the admin password.
func (s *SetupStore) GetPasswordChangeRequired(ctx context.Context) (bool, error) {
	const op = "storage.sqlite.SetupStore.GetPasswordChangeRequired"
	v, ok, err := s.GetSetting(ctx, "password_change_required")
	if err != nil {
		return false, apperr.Wrap(op, err)
	}
	return ok && v == "true", nil
}

// SetPasswordChangeRequired sets or clears the forced password change flag.
func (s *SetupStore) SetPasswordChangeRequired(ctx context.Context, required bool) error {
	v := "false"
	if required {
		v = "true"
	}
	return s.SetSetting(ctx, "password_change_required", v)
}

// SetRecoveryKeyHash upserts the single admin recovery key hash (row id=1).
// Called on create and rotate; rotated_at is updated on rotate.
func (s *SetupStore) SetRecoveryKeyHash(ctx context.Context, hash string) error {
	const op = "storage.sqlite.SetupStore.SetRecoveryKeyHash"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO admin_recovery_keys (id, key_hash, created_at)
		VALUES (1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			key_hash = excluded.key_hash,
			rotated_at = CURRENT_TIMESTAMP,
			last_used_at = NULL`,
		hash,
	)
	return apperr.Wrap(op, err)
}

// GetRecoveryKeyHash returns the stored admin recovery key hash.
// Returns ("", false, nil) when no recovery key has been created.
func (s *SetupStore) GetRecoveryKeyHash(ctx context.Context) (string, bool, error) {
	const op = "storage.sqlite.SetupStore.GetRecoveryKeyHash"
	var hash string
	err := s.db.Conn().QueryRowContext(ctx, `SELECT key_hash FROM admin_recovery_keys WHERE id = 1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, apperr.Wrap(op, err)
	}
	return hash, true, nil
}

// RuntimeFlags holds the feature-enable flags stored in ui_settings.
type RuntimeFlags struct {
	CSPollerEnabled            bool
	CloudflareMutationsEnabled bool
	AbuseIPDBEnabled           bool
	BetterStackEnabled         bool
	AutoBanEnabled             bool
}

// GetRuntimeFlags reads all feature flags from ui_settings.
// Missing rows default to false (safe: off by default, operator must enable).
func (s *SetupStore) GetRuntimeFlags(ctx context.Context) (RuntimeFlags, error) {
	const op = "storage.sqlite.SetupStore.GetRuntimeFlags"
	keys := []string{
		"cs_poller_enabled",
		"cloudflare_mutations_enabled",
		"abuseipdb_enabled",
		"betterstack_enabled",
		"auto_ban_enabled",
	}
	var flags RuntimeFlags
	for _, key := range keys {
		v, ok, err := s.GetSetting(ctx, key)
		if err != nil {
			return flags, apperr.Wrap(op, err)
		}
		if !ok {
			continue
		}
		enabled := v == "true"
		switch key {
		case "cs_poller_enabled":
			flags.CSPollerEnabled = enabled
		case "cloudflare_mutations_enabled":
			flags.CloudflareMutationsEnabled = enabled
		case "abuseipdb_enabled":
			flags.AbuseIPDBEnabled = enabled
		case "betterstack_enabled":
			flags.BetterStackEnabled = enabled
		case "auto_ban_enabled":
			flags.AutoBanEnabled = enabled
		}
	}
	return flags, nil
}

// SetRuntimeFlag persists a single feature flag.
// Valid keys: cs_poller_enabled, cloudflare_mutations_enabled, abuseipdb_enabled, betterstack_enabled.
func (s *SetupStore) SetRuntimeFlag(ctx context.Context, key string, enabled bool) error {
	const op = "storage.sqlite.SetupStore.SetRuntimeFlag"
	allowed := map[string]bool{
		"cs_poller_enabled":            true,
		"cloudflare_mutations_enabled": true,
		"abuseipdb_enabled":            true,
		"betterstack_enabled":          true,
	}
	if !allowed[key] {
		return apperr.Newf(op, "unknown flag key %q", key)
	}
	v := "false"
	if enabled {
		v = "true"
	}
	return s.SetSetting(ctx, key, v)
}

// UpdateRecoveryKeyLastUsed records a successful recovery key use.
func (s *SetupStore) UpdateRecoveryKeyLastUsed(ctx context.Context) error {
	const op = "storage.sqlite.SetupStore.UpdateRecoveryKeyLastUsed"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx, `UPDATE admin_recovery_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = 1`)
	return apperr.Wrap(op, err)
}
