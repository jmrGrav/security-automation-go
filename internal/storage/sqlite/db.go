package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/storage/manager"
	_ "modernc.org/sqlite"
)

var walCheckpointModes = map[string]struct{}{
	"PASSIVE":  {},
	"FULL":     {},
	"RESTART":  {},
	"TRUNCATE": {},
}

var knownTables = map[string]struct{}{
	"schema_migrations":            {},
	"runtime_state":                {},
	"leases":                       {},
	"ownership_claims":             {},
	"ownership_lineage":            {},
	"governance_evidence":          {},
	"events":                       {},
	"event_sequences":              {},
	"event_checkpoints":            {},
	"abuseipdb_report_dedup":       {},
	"runtime_cursors":              {},
	"abuseipdb_reporting_evidence": {},
	"abuseipdb_report_outbox":      {},
	"approval_execution_evidence":  {},
	"rollback_checkpoints":         {},
	"credential_secrets":           {},
	"credential_meta":              {},
	"setup_state":                  {},
	"ui_settings":                  {},
}

// DB manages a scoped SQLite connection with migrations.
type DB struct {
	conn           *sql.DB
	path           string
	credentialKey  []byte
	readOnly       atomic.Bool
	integrityCheck func(context.Context) error
}

func New(dir string) (*DB, error) {
	const op = "storage.sqlite.New"

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, apperr.Wrap(op, err)
	}

	path := filepath.Join(dir, "runtime.db")
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Performance and safety pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA wal_autocheckpoint=1000;",
	}

	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, apperr.Wrapf(op, err, "failed to execute pragma: %s", p)
		}
	}

	s := &DB{
		conn: db,
		path: path,
	}

	if err := s.runMigrations(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	if err := s.ensureCredentialKey(context.Background()); err != nil {
		_ = db.Close()
		return nil, apperr.Wrap(op, err)
	}
	if err := s.VerifySchema(context.Background()); err != nil {
		return nil, apperr.Wrap(op, err)
	}

	return s, nil
}

func (s *DB) runMigrations() error {
	m := manager.NewMigrator(s.conn)

	migrations := []manager.Migration{
		{
			Version:     1,
			Description: "Initial schema",
			SQL: `
				CREATE TABLE IF NOT EXISTS runtime_state (
					id INTEGER PRIMARY KEY CHECK (id = 1),
					data TEXT NOT NULL,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				);

				CREATE TABLE IF NOT EXISTS leases (
					lease_id TEXT PRIMARY KEY,
					owner TEXT NOT NULL,
					action TEXT NOT NULL,
					epoch_id TEXT NOT NULL,
					fencing_token INTEGER NOT NULL,
					expires_at TIMESTAMP NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				);

				CREATE TABLE IF NOT EXISTS ownership_claims (
					resource_id TEXT PRIMARY KEY,
					domain_id TEXT NOT NULL,
					rights TEXT NOT NULL,
					epoch INTEGER NOT NULL,
					timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				);

				CREATE TABLE IF NOT EXISTS governance_evidence (
					evidence_id TEXT PRIMARY KEY,
					data TEXT NOT NULL,
					timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				);
			`,
		},
		{
			Version:     2,
			Description: "Event sourcing",
			SQL: `
				CREATE TABLE IF NOT EXISTS events (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					sequence INTEGER NOT NULL,
					timestamp TIMESTAMP NOT NULL,
					category TEXT NOT NULL,
					type TEXT NOT NULL,
					correlation_id TEXT NOT NULL,
					causal_id TEXT,
					actor TEXT NOT NULL,
					scope_id TEXT NOT NULL,
					payload TEXT NOT NULL,
					metadata TEXT,
					UNIQUE(scope_id, sequence)
				);
				CREATE INDEX IF NOT EXISTS idx_events_correlation ON events(correlation_id);
				CREATE INDEX IF NOT EXISTS idx_events_scope_seq ON events(scope_id, sequence);
			`,
		},
		{
			Version:     3,
			Description: "Event checkpoints",
			SQL: `
				CREATE TABLE IF NOT EXISTS event_checkpoints (
					name TEXT NOT NULL,
					scope_id TEXT NOT NULL,
					sequence INTEGER NOT NULL,
					event_id INTEGER NOT NULL DEFAULT 0,
					checksum TEXT NOT NULL,
					state TEXT NOT NULL,
					metadata TEXT,
					schema_version INTEGER NOT NULL DEFAULT 1,
					created_at TIMESTAMP NOT NULL,
					PRIMARY KEY (name, scope_id, sequence)
				);
				CREATE INDEX IF NOT EXISTS idx_event_checkpoints_scope_name_seq ON event_checkpoints(scope_id, name, sequence DESC);
			`,
		},
		{
			Version:     4,
			Description: "AbuseIPDB report dedup",
			SQL: `
				CREATE TABLE IF NOT EXISTS abuseipdb_report_dedup (
					ip TEXT PRIMARY KEY,
					last_reported_at TIMESTAMP NOT NULL,
					last_evidence_id TEXT NOT NULL,
					report_count INTEGER NOT NULL DEFAULT 1,
					updated_at TIMESTAMP NOT NULL
				);
			`,
		},
		{
			Version:     5,
			Description: "Runtime cursors",
			SQL: `
				CREATE TABLE IF NOT EXISTS runtime_cursors (
					name TEXT PRIMARY KEY,
					cursor_value TEXT NOT NULL,
					updated_at TIMESTAMP NOT NULL
				);
			`,
		},
		{
			Version:     6,
			Description: "Reporting evidence",
			SQL: `
				CREATE TABLE IF NOT EXISTS abuseipdb_reporting_evidence (
					evidence_id TEXT PRIMARY KEY,
					timestamp TIMESTAMP NOT NULL,
					source TEXT NOT NULL,
					ip TEXT NOT NULL,
					suppression_reason TEXT,
					data TEXT NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_reporting_evidence_ts ON abuseipdb_reporting_evidence(timestamp DESC);
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_reporting_evidence_ip ON abuseipdb_reporting_evidence(ip, timestamp DESC);
			`,
		},
		{
			Version:     7,
			Description: "Scope-aware leases and atomic event sequences",
			SQL: `
				ALTER TABLE leases ADD COLUMN scope_id TEXT NOT NULL DEFAULT '';
				CREATE INDEX IF NOT EXISTS idx_leases_scope_action ON leases(scope_id, action, expires_at);
				CREATE TABLE IF NOT EXISTS event_sequences (
					scope_id TEXT PRIMARY KEY,
					next_sequence INTEGER NOT NULL
				);
				INSERT INTO event_sequences(scope_id, next_sequence)
				SELECT scope_id, COALESCE(MAX(sequence), 0) + 1
				FROM events
				GROUP BY scope_id
				ON CONFLICT(scope_id) DO UPDATE SET next_sequence = excluded.next_sequence;
			`,
		},
		{
			Version:     8,
			Description: "Approval execution evidence",
			SQL: `
				CREATE TABLE IF NOT EXISTS approval_execution_evidence (
					evidence_id TEXT PRIMARY KEY,
					timestamp TIMESTAMP NOT NULL,
					approval_id TEXT,
					batch_id TEXT,
					operation_id TEXT,
					status TEXT NOT NULL,
					data TEXT NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_approval_execution_evidence_ts ON approval_execution_evidence(timestamp DESC);
				CREATE INDEX IF NOT EXISTS idx_approval_execution_evidence_approval ON approval_execution_evidence(approval_id, timestamp DESC);
			`,
		},
		{
			Version:     9,
			Description: "Event idempotency keys",
			SQL: `
				ALTER TABLE events ADD COLUMN event_uid TEXT NOT NULL DEFAULT '';
				CREATE UNIQUE INDEX IF NOT EXISTS idx_events_scope_uid ON events(scope_id, event_uid) WHERE event_uid <> '';
			`,
		},
		{
			Version:     10,
			Description: "Reporting evidence indexes and AbuseIPDB report outbox",
			SQL: `
				ALTER TABLE abuseipdb_reporting_evidence ADD COLUMN decision TEXT NOT NULL DEFAULT '';
				ALTER TABLE abuseipdb_reporting_evidence ADD COLUMN abuse_type TEXT NOT NULL DEFAULT '';
				UPDATE abuseipdb_reporting_evidence
				SET decision = COALESCE(json_extract(data, '$.decision'), ''),
				    abuse_type = COALESCE(json_extract(data, '$.abuse_type'), '')
				WHERE decision = '' OR abuse_type = '';
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_reporting_evidence_source_ts ON abuseipdb_reporting_evidence(source, timestamp DESC, evidence_id DESC);
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_reporting_evidence_decision_ts ON abuseipdb_reporting_evidence(decision, timestamp DESC, evidence_id DESC);
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_reporting_evidence_reason_ts ON abuseipdb_reporting_evidence(suppression_reason, timestamp DESC, evidence_id DESC);
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_reporting_evidence_abuse_ts ON abuseipdb_reporting_evidence(abuse_type, timestamp DESC, evidence_id DESC);
				CREATE TABLE IF NOT EXISTS abuseipdb_report_outbox (
					evidence_id TEXT PRIMARY KEY,
					ip TEXT NOT NULL,
					source TEXT NOT NULL,
					idempotency_key TEXT NOT NULL,
					status TEXT NOT NULL,
					expires_at TIMESTAMP NOT NULL,
					created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);
				CREATE UNIQUE INDEX IF NOT EXISTS idx_abuseipdb_report_outbox_pending_ip
				ON abuseipdb_report_outbox(ip)
				WHERE status = 'pending';
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_report_outbox_ip_status ON abuseipdb_report_outbox(ip, status, updated_at DESC);
			`,
		},
		{
			Version:     11,
			Description: "Retryable AbuseIPDB report outbox payload",
			SQL: `
				ALTER TABLE abuseipdb_report_outbox ADD COLUMN report_json TEXT NOT NULL DEFAULT '{}';
				ALTER TABLE abuseipdb_report_outbox ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
				ALTER TABLE abuseipdb_report_outbox ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
				ALTER TABLE abuseipdb_report_outbox ADD COLUMN next_attempt_at TIMESTAMP;
				CREATE INDEX IF NOT EXISTS idx_abuseipdb_report_outbox_retry
				ON abuseipdb_report_outbox(status, next_attempt_at, updated_at);
			`,
		},
		{
			Version:     12,
			Description: "Bootstrap-only legacy lease scope normalization",
			SQL: `
				UPDATE leases
				SET scope_id = 'default'
				WHERE scope_id = '';
			`,
		},
		{
			Version:     13,
			Description: "Ownership lineage append-only store",
			SQL: `
				CREATE TABLE IF NOT EXISTS ownership_lineage (
					id TEXT PRIMARY KEY,
					parent_id TEXT,
					scope_id TEXT NOT NULL,
					resource_id TEXT NOT NULL,
					domain_id TEXT NOT NULL,
					event_type TEXT NOT NULL,
					decision TEXT,
					required_right TEXT,
					owner_domain TEXT,
					epoch INTEGER NOT NULL DEFAULT 0,
					fencing_token INTEGER NOT NULL DEFAULT 0,
					reason TEXT,
					decision_hash TEXT NOT NULL,
					payload_json TEXT NOT NULL,
					created_at TIMESTAMP NOT NULL
				);
				CREATE INDEX IF NOT EXISTS idx_ownership_lineage_scope_resource_time
				ON ownership_lineage(scope_id, resource_id, created_at DESC, id DESC);
			`,
		},
		{
			Version:     14,
			Description: "Rollback durable checkpoints",
			SQL: `
				CREATE TABLE IF NOT EXISTS rollback_checkpoints (
					batch_id TEXT PRIMARY KEY,
					scope_id TEXT NOT NULL DEFAULT '',
					status TEXT NOT NULL,
					last_completed_op_idx INTEGER NOT NULL DEFAULT 0,
					started_at TIMESTAMP,
					finished_at TIMESTAMP,
					data TEXT NOT NULL,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);
				CREATE INDEX IF NOT EXISTS idx_rollback_checkpoints_scope_updated
				ON rollback_checkpoints(scope_id, updated_at DESC);
			`,
		},
		{
			Version:     15,
			Description: "Setup wizard state and UI settings",
			SQL: `
				CREATE TABLE IF NOT EXISTS setup_state (
					id INTEGER PRIMARY KEY CHECK (id = 1),
					current_step INTEGER NOT NULL DEFAULT 1,
					completed_at TIMESTAMP,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);
				INSERT OR IGNORE INTO setup_state (id, current_step) VALUES (1, 1);

				CREATE TABLE IF NOT EXISTS ui_settings (
					key TEXT PRIMARY KEY,
					value TEXT NOT NULL,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);
			`,
		},
		{
			Version:     16,
			Description: "Encrypted credential store",
			SQL: `
				CREATE TABLE IF NOT EXISTS credential_secrets (
					name TEXT PRIMARY KEY,
					ciphertext BLOB NOT NULL,
					nonce BLOB NOT NULL,
					enabled INTEGER NOT NULL DEFAULT 1,
					created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					last_validated_at TIMESTAMP
				);
				CREATE TABLE IF NOT EXISTS credential_meta (
					key TEXT PRIMARY KEY,
					value TEXT NOT NULL,
					updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				);
			`,
		},
	}

	return m.Migrate(context.Background(), migrations)
}

// NormalizeLeases is kept as an explicit bootstrap/admin utility only.
// Runtime hot paths must not call this.
func (s *DB) NormalizeLeases(ctx context.Context) error {
	const op = "storage.sqlite.DB.NormalizeLeases"
	_, err := s.conn.ExecContext(ctx, `
		UPDATE leases
		SET scope_id = 'default'
		WHERE scope_id = ''
	`)
	return apperr.Wrap(op, err)
}

func (s *DB) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *DB) Reopen(ctx context.Context) error {
	const op = "storage.sqlite.DB.Reopen"
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.credentialKey = nil

	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Performance and safety pragmas
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA foreign_keys=ON;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA wal_autocheckpoint=1000;",
	}

	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			return apperr.Wrapf(op, err, "failed to execute pragma: %s", p)
		}
	}

	s.conn = db

	if err := s.runMigrations(); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := s.ensureCredentialKey(ctx); err != nil {
		return apperr.Wrap(op, err)
	}
	return s.VerifySchema(ctx)
}

func (s *DB) Conn() *sql.DB {
	return s.conn
}

func (s *DB) Path() string {
	return s.path
}

func (s *DB) SetReadOnlyDegradedMode(enabled bool) {
	s.readOnly.Store(enabled)
	if enabled {
		metrics.SQLiteDegradedModeTotal.Inc()
	}
}

func (s *DB) ReadOnlyDegradedMode() bool {
	return s.readOnly.Load()
}

func (s *DB) ensureWritable(op string) error {
	if s.readOnly.Load() {
		return apperr.New(op, "sqlite database is in read-only degraded mode")
	}
	return nil
}

func (s *DB) Maintenance(ctx context.Context) error {
	m := manager.NewMigrator(s.conn)
	return m.Maintenance(ctx)
}

func (s *DB) IntegrityCheck(ctx context.Context) error {
	if s.integrityCheck != nil {
		return s.integrityCheck(ctx)
	}
	m := manager.NewMigrator(s.conn)
	return m.IntegrityCheck(ctx)
}

func (s *DB) WALCheckpoint(ctx context.Context, mode string) error {
	const op = "storage.sqlite.DB.WALCheckpoint"
	if mode == "" {
		mode = "TRUNCATE"
	}
	if _, ok := walCheckpointModes[mode]; !ok {
		return apperr.Newf(op, "invalid checkpoint mode: %q", mode)
	}
	_, err := s.conn.ExecContext(ctx, "PRAGMA wal_checkpoint("+mode+");")
	return apperr.Wrap(op, err)
}

func (s *DB) ExportHotSnapshot(ctx context.Context, targetPath string) error {
	const op = "storage.sqlite.DB.ExportHotSnapshot"
	if targetPath == "" {
		return apperr.New(op, "targetPath must not be empty")
	}
	if !filepath.IsAbs(targetPath) {
		return apperr.Newf(op, "targetPath must be absolute, got %q", targetPath)
	}
	clean := filepath.Clean(targetPath)
	if clean != targetPath {
		return apperr.Newf(op, "targetPath contains traversal, got %q", targetPath)
	}
	if strings.ContainsAny(clean, "'\"") {
		return apperr.Newf(op, "targetPath contains invalid characters: %q", targetPath)
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0755); err != nil {
		return apperr.Wrap(op, err)
	}
	if _, err := s.conn.ExecContext(ctx, "VACUUM INTO '"+clean+"'"); err != nil {
		return apperr.Wrap(op, err)
	}
	return nil
}

func (s *DB) QuarantineCorruption(ctx context.Context, quarantineDir string) (string, error) {
	const op = "storage.sqlite.DB.QuarantineCorruption"
	if err := s.IntegrityCheck(ctx); err == nil {
		return "", nil
	}
	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return "", apperr.Wrap(op, err)
	}
	target := filepath.Join(quarantineDir, filepath.Base(s.path))
	if err := copyFileAtomic(s.path, target); err != nil {
		return "", apperr.Wrap(op, err)
	}
	_ = copyFileAtomic(s.path+"-wal", target+"-wal")
	_ = copyFileAtomic(s.path+"-shm", target+"-shm")
	s.SetReadOnlyDegradedMode(true)
	metrics.SQLiteQuarantineCreatedTotal.Inc()
	return target, nil
}

func (s *DB) RotateBackups(backupDir string, keep int) error {
	const op = "storage.sqlite.DB.RotateBackups"
	if keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return apperr.Wrap(op, err)
	}
	sort.Slice(entries, func(i, j int) bool {
		ii, _ := entries[i].Info()
		jj, _ := entries[j].Info()
		return ii.ModTime().After(jj.ModTime())
	})
	var errs []error
	for _, entry := range entries[keep:] {
		if err := os.Remove(filepath.Join(backupDir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return apperr.Newf(op, "failed to remove %d backup(s): %v", len(errs), errs[0])
	}
	return nil
}

func (s *DB) VerifySchema(ctx context.Context) error {
	const op = "storage.sqlite.DB.VerifySchema"
	requiredTables := []string{
		"schema_migrations",
		"runtime_state",
		"leases",
		"ownership_claims",
		"ownership_lineage",
		"governance_evidence",
		"events",
		"event_sequences",
		"event_checkpoints",
		"abuseipdb_report_dedup",
		"runtime_cursors",
		"abuseipdb_reporting_evidence",
		"abuseipdb_report_outbox",
		"approval_execution_evidence",
		"rollback_checkpoints",
		"credential_secrets",
		"credential_meta",
		"setup_state",
		"ui_settings",
	}
	for _, table := range requiredTables {
		var exists int
		if err := s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&exists); err != nil {
			return apperr.Wrap(op, err)
		}
		if exists == 0 {
			return apperr.Newf(op, "required table missing: %s", table)
		}
	}
	if err := s.requireColumn(ctx, "leases", "scope_id"); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := s.requireColumn(ctx, "events", "event_uid"); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := s.requireColumn(ctx, "abuseipdb_reporting_evidence", "decision"); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := s.requireColumn(ctx, "abuseipdb_reporting_evidence", "abuse_type"); err != nil {
		return apperr.Wrap(op, err)
	}
	if err := s.requireColumn(ctx, "abuseipdb_report_outbox", "report_json"); err != nil {
		return apperr.Wrap(op, err)
	}
	return nil
}

func (s *DB) requireColumn(ctx context.Context, table string, column string) error {
	if _, ok := knownTables[table]; !ok {
		return apperr.Newf("storage.sqlite.DB.requireColumn", "unknown table: %q", table)
	}
	rows, err := s.conn.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	return apperr.Newf("storage.sqlite.DB.requireColumn", "required column missing: %s.%s", table, column)
}

func copyFile(src string, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = destination.ReadFrom(source)
	return err
}

func copyFileAtomic(src string, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := copyFile(src, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
