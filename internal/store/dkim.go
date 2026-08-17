package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type SigningKey struct {
	ID        int64
	DomainID  int64
	Domain    string
	Selector  string
	Algorithm string
	Wrapped   []byte
	Record    string
}

func (s *Store) CreateSigningKey(ctx context.Context, domainID int64, selector, algorithm string, wrapped []byte, record string) (*SigningKey, error) {
	const q = `
		INSERT INTO dkim_keys (domain_id, selector, algorithm, wrapped_secret, public_record)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, domain_id, selector, algorithm, wrapped_secret, public_record`

	var k SigningKey
	err := s.Pool.QueryRow(ctx, q, domainID, selector, algorithm, wrapped, record).
		Scan(&k.ID, &k.DomainID, &k.Selector, &k.Algorithm, &k.Wrapped, &k.Record)
	if err != nil {
		return nil, fmt.Errorf("storing signing key: %w", err)
	}
	return &k, nil
}

// ActiveSigningKey returns the key a message should be signed with. Wrapped
// material is returned; unwrapping happens only inside the signer.
func (s *Store) ActiveSigningKey(ctx context.Context, domainID int64) (*SigningKey, error) {
	const q = `
		SELECT k.id, k.domain_id, d.name, k.selector, k.algorithm, k.wrapped_secret, k.public_record
		FROM dkim_keys k
		JOIN domains d ON d.id = k.domain_id
		WHERE k.domain_id = $1 AND k.active
		ORDER BY k.created_at DESC
		LIMIT 1`

	var k SigningKey
	err := s.Pool.QueryRow(ctx, q, domainID).
		Scan(&k.ID, &k.DomainID, &k.Domain, &k.Selector, &k.Algorithm, &k.Wrapped, &k.Record)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading signing key: %w", err)
	}
	return &k, nil
}

// SigningKeyForMessage resolves the key from the message's sending domain.
func (s *Store) SigningKeyForMessage(ctx context.Context, messageID string) (*SigningKey, error) {
	const q = `
		SELECT k.id, k.domain_id, d.name, k.selector, k.algorithm, k.wrapped_secret, k.public_record
		FROM messages m
		JOIN domains d ON d.id = m.domain_id
		JOIN dkim_keys k ON k.domain_id = d.id AND k.active
		WHERE m.id = $1
		ORDER BY k.created_at DESC
		LIMIT 1`

	var k SigningKey
	err := s.Pool.QueryRow(ctx, q, messageID).
		Scan(&k.ID, &k.DomainID, &k.Domain, &k.Selector, &k.Algorithm, &k.Wrapped, &k.Record)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading signing key for message: %w", err)
	}
	return &k, nil
}

func (s *Store) MarkSigned(ctx context.Context, messageID string) error {
	const q = `UPDATE messages SET signed_at = now() WHERE id = $1`
	if _, err := s.Pool.Exec(ctx, q, messageID); err != nil {
		return fmt.Errorf("recording signature: %w", err)
	}
	return nil
}
