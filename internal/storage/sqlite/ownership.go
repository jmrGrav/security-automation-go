package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

type OwnershipRepository struct {
	db *DB
}

func NewOwnershipRepository(db *DB) *OwnershipRepository {
	return &OwnershipRepository{db: db}
}

func (r *OwnershipRepository) GetClaim(ctx context.Context, resourceID string) (ownership.OwnershipClaim, error) {
	const op = "storage.sqlite.OwnershipRepository.GetClaim"
	var c ownership.OwnershipClaim
	var rights string
	err := r.db.Conn().QueryRowContext(ctx, `
		SELECT resource_id, domain_id, rights, epoch, timestamp 
		FROM ownership_claims 
		WHERE resource_id = ?
	`, resourceID).Scan(&c.ResourceID, &c.DomainID, &rights, &c.Epoch, &c.Timestamp)

	if err == sql.ErrNoRows {
		return ownership.OwnershipClaim{}, nil
	}
	if err != nil {
		return ownership.OwnershipClaim{}, apperr.Wrap(op, err)
	}

	for _, rt := range strings.Split(rights, ",") {
		c.Rights = append(c.Rights, ownership.Right(rt))
	}

	return c, nil
}

func (r *OwnershipRepository) SetClaim(ctx context.Context, c ownership.OwnershipClaim) error {
	const op = "storage.sqlite.OwnershipRepository.SetClaim"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	rights := make([]string, 0, len(c.Rights))
	for _, rt := range c.Rights {
		rights = append(rights, string(rt))
	}

	_, err := r.db.Conn().ExecContext(ctx, `
		INSERT INTO ownership_claims (resource_id, domain_id, rights, epoch)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(resource_id) DO UPDATE SET 
			domain_id = excluded.domain_id, 
			rights = excluded.rights, 
			epoch = excluded.epoch,
			timestamp = CURRENT_TIMESTAMP
	`, c.ResourceID, c.DomainID, strings.Join(rights, ","), c.Epoch)
	return apperr.Wrap(op, err)
}

func (r *OwnershipRepository) ListClaims(ctx context.Context) ([]ownership.OwnershipClaim, error) {
	const op = "storage.sqlite.OwnershipRepository.ListClaims"
	rows, err := r.db.Conn().QueryContext(ctx, "SELECT resource_id, domain_id, rights, epoch, timestamp FROM ownership_claims")
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()

	var claims []ownership.OwnershipClaim
	for rows.Next() {
		var c ownership.OwnershipClaim
		var rights string
		if err := rows.Scan(&c.ResourceID, &c.DomainID, &rights, &c.Epoch, &c.Timestamp); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		for _, rt := range strings.Split(rights, ",") {
			c.Rights = append(c.Rights, ownership.Right(rt))
		}
		claims = append(claims, c)
	}
	return claims, nil
}

func (r *OwnershipRepository) GetLineage(ctx context.Context, eventID string) (ownership.LineageEvent, bool, error) {
	const op = "storage.sqlite.OwnershipRepository.GetLineage"
	var payload string
	err := r.db.Conn().QueryRowContext(ctx, `
		SELECT payload_json
		FROM ownership_lineage
		WHERE id = ?
	`, eventID).Scan(&payload)
	if err == sql.ErrNoRows {
		return ownership.LineageEvent{}, false, nil
	}
	if err != nil {
		return ownership.LineageEvent{}, false, apperr.Wrap(op, err)
	}
	var ev ownership.LineageEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return ownership.LineageEvent{}, false, apperr.Wrap(op, err)
	}
	return ev, true, nil
}

func (r *OwnershipRepository) AppendLineage(ctx context.Context, event ownership.LineageEvent) error {
	const op = "storage.sqlite.OwnershipRepository.AppendLineage"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	_, err = r.db.Conn().ExecContext(ctx, `
		INSERT INTO ownership_lineage (
			id, parent_id, scope_id, resource_id, domain_id, event_type, decision, required_right,
			owner_domain, epoch, fencing_token, reason, decision_hash, payload_json, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.ParentID, event.ScopeID, event.ResourceID, event.DomainID, string(event.EventType), event.Decision, string(event.RequiredRight),
		event.OwnerDomain, event.Epoch, event.FencingToken, event.Reason, event.DecisionHash, string(raw), event.CreatedAt.UTC())
	return apperr.Wrap(op, err)
}

func (r *OwnershipRepository) ListLineage(ctx context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error) {
	return r.ListLineageCursor(ctx, scopeID, resourceID, time.Time{}, "", limit)
}

func (r *OwnershipRepository) ListLineageCursor(ctx context.Context, scopeID string, resourceID string, beforeCreatedAt time.Time, beforeID string, limit int) ([]ownership.LineageEvent, error) {
	const op = "storage.sqlite.OwnershipRepository.ListLineage"
	if limit <= 0 {
		limit = 100
	}
	cursorEnabled := 0
	if !beforeCreatedAt.IsZero() {
		cursorEnabled = 1
	}
	rows, err := r.db.Conn().QueryContext(ctx, `
		SELECT payload_json
		FROM ownership_lineage
		WHERE (? = '' OR scope_id = ?)
		  AND (? = '' OR resource_id = ?)
		  AND (
			? = 0
			OR created_at < ?
			OR (created_at = ? AND id < ?)
		  )
		ORDER BY created_at DESC, id DESC
		LIMIT ?
	`,
		scopeID, scopeID,
		resourceID, resourceID,
		cursorEnabled, beforeCreatedAt.UTC(), beforeCreatedAt.UTC(), beforeID,
		limit,
	)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()

	out := make([]ownership.LineageEvent, 0, limit)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		var ev ownership.LineageEvent
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

type OwnershipLineageRecorder struct {
	repo *OwnershipRepository
	ctx  context.Context
}

func NewOwnershipLineageRecorder(repo *OwnershipRepository) *OwnershipLineageRecorder {
	return &OwnershipLineageRecorder{repo: repo, ctx: context.Background()}
}

func (r *OwnershipLineageRecorder) Append(event ownership.LineageEvent) error {
	return r.repo.AppendLineage(r.ctx, event)
}
