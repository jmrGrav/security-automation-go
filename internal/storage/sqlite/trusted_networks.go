package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

// TrustedNetworksStore is the SQLite-backed implementation of
// trustednetworks.Store — the durable source of truth the hub-and-spoke
// registry reconciles CrowdSec and Cloudflare against.
type TrustedNetworksStore struct {
	db *DB
}

// NewTrustedNetworksStore returns a TrustedNetworksStore backed by db.
func NewTrustedNetworksStore(db *DB) *TrustedNetworksStore {
	return &TrustedNetworksStore{db: db}
}

var _ trustednetworks.Store = (*TrustedNetworksStore)(nil)

func (s *TrustedNetworksStore) List(ctx context.Context) ([]trustednetworks.Entry, error) {
	const op = "storage.sqlite.TrustedNetworksStore.List"
	rows, err := s.db.Conn().QueryContext(ctx, `
		SELECT value, label, source, comment, created_at, updated_at
		FROM trusted_networks
		ORDER BY created_at ASC, id ASC
	`)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()
	var out []trustednetworks.Entry
	for rows.Next() {
		e, err := scanTrustedNetworkEntryRow(rows)
		if err != nil {
			return nil, apperr.Wrap(op, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
}

func (s *TrustedNetworksStore) Get(ctx context.Context, value string) (trustednetworks.Entry, bool, error) {
	const op = "storage.sqlite.TrustedNetworksStore.Get"
	row := s.db.Conn().QueryRowContext(ctx, `
		SELECT value, label, source, comment, created_at, updated_at
		FROM trusted_networks
		WHERE value = ?
	`, value)
	e, err := scanTrustedNetworkEntryRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return trustednetworks.Entry{}, false, nil
	}
	if err != nil {
		return trustednetworks.Entry{}, false, apperr.Wrap(op, err)
	}
	return e, true, nil
}

func (s *TrustedNetworksStore) Upsert(ctx context.Context, e trustednetworks.Entry) error {
	const op = "storage.sqlite.TrustedNetworksStore.Upsert"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO trusted_networks (value, label, source, comment)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(value) DO UPDATE SET
			label = excluded.label,
			source = excluded.source,
			comment = excluded.comment,
			updated_at = CURRENT_TIMESTAMP
	`, e.Value, e.Label, e.Source, e.Comment)
	return apperr.Wrap(op, err)
}

func (s *TrustedNetworksStore) Remove(ctx context.Context, value string) error {
	const op = "storage.sqlite.TrustedNetworksStore.Remove"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx, `DELETE FROM trusted_networks WHERE value = ?`, value)
	return apperr.Wrap(op, err)
}

type scannable interface {
	Scan(dest ...any) error
}

func scanTrustedNetworkEntryRow(row scannable) (trustednetworks.Entry, error) {
	var e trustednetworks.Entry
	var createdAt, updatedAt time.Time
	if err := row.Scan(&e.Value, &e.Label, &e.Source, &e.Comment, &createdAt, &updatedAt); err != nil {
		return trustednetworks.Entry{}, err
	}
	e.CreatedAt = createdAt.UTC()
	e.UpdatedAt = updatedAt.UTC()
	return e, nil
}
