package manager

import (
	"context"
	"database/sql"
	"sort"

	"github.com/jm/security-automation-go/internal/apperr"
)

// Migrator handles versioned SQL migrations.
type Migrator struct {
	db *sql.DB
}

func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

// Migration represents a single versioned change.
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// Migrate applies all pending migrations from the provided map.
func (m *Migrator) Migrate(ctx context.Context, migrations []Migration) error {
	const op = "storage.manager.Migrate"

	// 1. Ensure migrations table exists
	_, err := m.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	// 2. Get current version
	var currentVersion int
	err = m.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	// 3. Sort migrations
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	// 4. Apply pending
	for _, mig := range migrations {
		if mig.Version <= currentVersion {
			continue
		}

		tx, err := m.db.BeginTx(ctx, nil)
		if err != nil {
			return apperr.Wrap(op, err)
		}

		if _, err := tx.ExecContext(ctx, mig.SQL); err != nil {
			tx.Rollback()
			return apperr.Wrapf(op, err, "failed to apply migration %d: %s", mig.Version, mig.Description)
		}

		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version, description) VALUES (?, ?)", mig.Version, mig.Description); err != nil {
			tx.Rollback()
			return apperr.Wrap(op, err)
		}

		if err := tx.Commit(); err != nil {
			return apperr.Wrap(op, err)
		}
	}

	return nil
}

// Maintenance handles WAL checkpoints and Vacuum.
func (m *Migrator) Maintenance(ctx context.Context) error {
	const op = "storage.manager.Maintenance"

	// 1. Integrity Check
	if err := m.IntegrityCheck(ctx); err != nil {
		return apperr.Wrap(op, err)
	}

	// 2. Perform WAL Checkpoint (TRUNCATE mode to shrink WAL file)
	if _, err := m.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		return apperr.Wrap(op, err)
	}

	// 3. Periodic Vacuum (only if requested or needed, here we just do it)
	if _, err := m.db.ExecContext(ctx, "VACUUM;"); err != nil {
		return apperr.Wrap(op, err)
	}

	// 4. Optimize
	if _, err := m.db.ExecContext(ctx, "PRAGMA optimize;"); err != nil {
		return apperr.Wrap(op, err)
	}

	return nil
}

// IntegrityCheck runs SQLite integrity checks.
func (m *Migrator) IntegrityCheck(ctx context.Context) error {
	const op = "storage.manager.IntegrityCheck"

	var result string
	err := m.db.QueryRowContext(ctx, "PRAGMA integrity_check;").Scan(&result)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	if result != "ok" {
		return apperr.Newf(op, "database integrity check failed: %s", result)
	}

	err = m.db.QueryRowContext(ctx, "PRAGMA foreign_key_check;").Scan(&result)
	if err != nil && err != sql.ErrNoRows {
		return apperr.Wrap(op, err)
	}
	// foreign_key_check returns rows if there are errors, otherwise empty

	return nil
}
