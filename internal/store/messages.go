package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrIdempotencyMismatch means the same idempotency key arrived with a
// different request body. Returning the first result would be a lie, so the
// caller is told instead.
var ErrIdempotencyMismatch = errors.New("idempotency key reused with a different request")

// ErrIdempotencyInFlight means an identical request is still being processed.
// The caller should retry rather than receive a second message.
var ErrIdempotencyInFlight = errors.New("an identical request is in flight")

type Domain struct {
	ID     int64
	Name   string
	Status string
}

func (s *Store) DomainByName(ctx context.Context, name string) (*Domain, error) {
	const q = `SELECT id, name, status FROM domains WHERE name = $1`
	var d Domain
	err := s.Pool.QueryRow(ctx, q, name).Scan(&d.ID, &d.Name, &d.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading domain: %w", err)
	}
	return &d, nil
}

type NewMessage struct {
	ID             string
	APIKeyID       int64
	DomainID       int64
	FromAddress    string
	Recipients     []string
	Subject        string
	BodyHTML       string
	BodyText       string
	Headers        []byte
	Tags           []byte
	ScheduledAt    *time.Time
	IdempotencyKey string
	RequestHash    []byte
}

type Message struct {
	ID        string
	Status    string
	CreatedAt time.Time
}

// EnqueueMessage writes the message and its idempotency record in one
// transaction. Either both land or neither does, so a crash between them
// cannot produce a duplicate send or a lost acceptance.
func (s *Store) EnqueueMessage(ctx context.Context, in NewMessage) (*Message, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op

	if in.IdempotencyKey != "" {
		existing, replay, err := claimIdempotency(ctx, tx, in)
		if err != nil {
			return nil, false, err
		}
		if replay {
			if err := tx.Commit(ctx); err != nil {
				return nil, false, fmt.Errorf("committing replay: %w", err)
			}
			return existing, true, nil
		}
	}

	msg, err := insertMessage(ctx, tx, in)
	if err != nil {
		return nil, false, err
	}

	if in.IdempotencyKey != "" {
		const q = `UPDATE idempotency_records SET message_id = $3 WHERE api_key_id = $1 AND key = $2`
		if _, err := tx.Exec(ctx, q, in.APIKeyID, in.IdempotencyKey, msg.ID); err != nil {
			return nil, false, fmt.Errorf("linking idempotency record: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("committing message: %w", err)
	}
	return msg, false, nil
}

// claimIdempotency reserves the key. It returns the earlier result when this
// exact request was already accepted.
func claimIdempotency(ctx context.Context, tx pgx.Tx, in NewMessage) (*Message, bool, error) {
	const insert = `
		INSERT INTO idempotency_records (api_key_id, key, request_hash, expires_at)
		VALUES ($1, $2, $3, now() + interval '24 hours')
		ON CONFLICT (api_key_id, key) DO NOTHING`

	tag, err := tx.Exec(ctx, insert, in.APIKeyID, in.IdempotencyKey, in.RequestHash)
	if err != nil {
		return nil, false, fmt.Errorf("claiming idempotency key: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil, false, nil
	}

	const load = `
		SELECT r.request_hash, m.id, m.status, m.created_at
		FROM idempotency_records r
		LEFT JOIN messages m ON m.id = r.message_id
		WHERE r.api_key_id = $1 AND r.key = $2
		FOR UPDATE OF r`

	var storedHash []byte
	var id, status *string
	var createdAt *time.Time
	if err := tx.QueryRow(ctx, load, in.APIKeyID, in.IdempotencyKey).Scan(&storedHash, &id, &status, &createdAt); err != nil {
		return nil, false, fmt.Errorf("loading idempotency record: %w", err)
	}

	if !equalBytes(storedHash, in.RequestHash) {
		return nil, false, ErrIdempotencyMismatch
	}
	if id == nil {
		return nil, false, ErrIdempotencyInFlight
	}
	return &Message{ID: *id, Status: *status, CreatedAt: *createdAt}, true, nil
}

func insertMessage(ctx context.Context, tx pgx.Tx, in NewMessage) (*Message, error) {
	const q = `
		INSERT INTO messages (id, api_key_id, domain_id, from_address, recipients, subject,
		                      body_html, body_text, headers, tags, scheduled_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, status, created_at`

	var m Message
	err := tx.QueryRow(ctx, q,
		in.ID, in.APIKeyID, in.DomainID, in.FromAddress, in.Recipients, in.Subject,
		in.BodyHTML, in.BodyText, in.Headers, in.Tags, in.ScheduledAt,
	).Scan(&m.ID, &m.Status, &m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting message: %w", err)
	}
	return &m, nil
}

func (s *Store) MessageByID(ctx context.Context, id string) (*Message, error) {
	const q = `SELECT id, status, created_at FROM messages WHERE id = $1`
	var m Message
	err := s.Pool.QueryRow(ctx, q, id).Scan(&m.ID, &m.Status, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading message: %w", err)
	}
	return &m, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
