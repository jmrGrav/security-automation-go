package sqlite

import (
	"context"
	"testing"
)

// TestSQLiteMigrations_UpgradeFromLegacyRuntimeDB_CreatesAllCurrentTables guards
// against the "dpkg upgrade doesn't replay migrations" hypothesis: it simulates a
// runtime.db that was created by an older binary (missing the newest tables and
// with schema_migrations rewound to an earlier version), then re-opens it the
// same way every cf-sync entry point does (daemon, -mode ui, bootstrap, admin
// CLI all call sqlite.New(stateDir)) and asserts the schema is brought fully
// current — without ever dropping existing data — and that re-running the open
// path again is a no-op (idempotent).
func TestSQLiteMigrations_UpgradeFromLegacyRuntimeDB_CreatesAllCurrentTables(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: simulate a fresh-but-current DB, then "downgrade" it in place to
	// look like a DB last touched by a pre-v1.7.4 binary: drop the newest
	// tables it introduced (cf_ban_lifecycle, trusted_networks) and rewind the
	// migration watermark so the migrator believes those versions were never
	// applied. This is a faithful simulation of an upgraded host's on-disk
	// state immediately before its first post-upgrade start.
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("create initial db: %v", err)
	}

	// Seed a row in a long-standing table to prove the upgrade path never
	// loses pre-existing data.
	if _, err := db.Conn().ExecContext(context.Background(),
		`INSERT INTO runtime_cursors (name, cursor_value, updated_at) VALUES ('seed', 'keep-me', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("seed runtime_cursors: %v", err)
	}

	downgradeStatements := []string{
		`DROP TABLE IF EXISTS cf_ban_lifecycle`,
		`DROP TABLE IF EXISTS trusted_networks`,
		`DROP TABLE IF EXISTS crowdsec_allowlist_status`,
		`DELETE FROM schema_migrations WHERE version >= 18`,
	}
	for _, stmt := range downgradeStatements {
		if _, err := db.Conn().ExecContext(context.Background(), stmt); err != nil {
			t.Fatalf("simulate legacy schema (%s): %v", stmt, err)
		}
	}

	var watermark int
	if err := db.Conn().QueryRowContext(context.Background(),
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&watermark); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	if watermark != 17 {
		t.Fatalf("expected simulated legacy watermark of 17, got %d", watermark)
	}

	// Confirm the new-in-v1.7.4 table is really gone, simulating the
	// operator's observed symptom (table missing on the upgraded host).
	var missingCount int
	if err := db.Conn().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cf_ban_lifecycle'").Scan(&missingCount); err != nil {
		t.Fatalf("check table absence: %v", err)
	}
	if missingCount != 0 {
		t.Fatalf("expected cf_ban_lifecycle to be absent after simulated downgrade, found %d", missingCount)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close db before reopen: %v", err)
	}

	// Step 2: re-open the same on-disk DB the way every cf-sync entry point
	// does post-upgrade (daemon startup, -mode ui startup, bootstrap, admin
	// CLI: all call sqlite.New(stateDir) unconditionally, not gated behind any
	// "first run" / wizard-completeness check).
	upgraded, err := New(tmpDir)
	if err != nil {
		t.Fatalf("re-open db to apply pending migrations: %v", err)
	}
	defer upgraded.Close()

	if err := upgraded.VerifySchema(context.Background()); err != nil {
		t.Fatalf("schema not current after re-open: %v", err)
	}

	for _, table := range []string{"cf_ban_lifecycle", "trusted_networks", "crowdsec_allowlist_status", "operator_notes"} {
		var exists int
		if err := upgraded.Conn().QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if exists == 0 {
			t.Fatalf("expected table %s to exist after migration re-run, but it is missing", table)
		}
	}

	var appliedVersions []int
	rows, err := upgraded.Conn().QueryContext(context.Background(), "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("list applied migrations: %v", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan version: %v", err)
		}
		appliedVersions = append(appliedVersions, v)
	}
	rows.Close()
	if len(appliedVersions) == 0 || appliedVersions[len(appliedVersions)-1] < 22 {
		t.Fatalf("expected migrations to be replayed up to at least version 22, got versions: %v", appliedVersions)
	}

	// Pre-existing data must survive the upgrade untouched.
	var cursorValue string
	if err := upgraded.Conn().QueryRowContext(context.Background(),
		"SELECT cursor_value FROM runtime_cursors WHERE name = 'seed'").Scan(&cursorValue); err != nil {
		t.Fatalf("read seeded cursor after upgrade: %v", err)
	}
	if cursorValue != "keep-me" {
		t.Fatalf("expected pre-existing data to survive migration, got %q", cursorValue)
	}

	if err := upgraded.Close(); err != nil {
		t.Fatalf("close upgraded db: %v", err)
	}

	// Step 3: re-running the same startup path again (e.g. a subsequent
	// restart) must be a pure no-op — idempotent, no errors, no data loss,
	// no duplicate migration application.
	again, err := New(tmpDir)
	if err != nil {
		t.Fatalf("second re-open (idempotency check) failed: %v", err)
	}
	defer again.Close()

	if err := again.VerifySchema(context.Background()); err != nil {
		t.Fatalf("schema not current on second re-open: %v", err)
	}

	var migrationCount18, migrationCount19 int
	if err := again.Conn().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM schema_migrations WHERE version = 18").Scan(&migrationCount18); err != nil {
		t.Fatalf("count migration 18: %v", err)
	}
	if err := again.Conn().QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM schema_migrations WHERE version = 19").Scan(&migrationCount19); err != nil {
		t.Fatalf("count migration 19: %v", err)
	}
	if migrationCount18 != 1 || migrationCount19 != 1 {
		t.Fatalf("expected each migration recorded exactly once after repeated startups, got v18=%d v19=%d", migrationCount18, migrationCount19)
	}

	if err := again.Conn().QueryRowContext(context.Background(),
		"SELECT cursor_value FROM runtime_cursors WHERE name = 'seed'").Scan(&cursorValue); err != nil {
		t.Fatalf("read seeded cursor after second re-open: %v", err)
	}
	if cursorValue != "keep-me" {
		t.Fatalf("expected pre-existing data to survive a second idempotent startup, got %q", cursorValue)
	}
}
